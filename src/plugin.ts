// opencode-plugin-openshift-readonly-agent
//
// Every shell the opencode agent starts gets KUBECONFIG pointed at a
// kubeconfig this plugin owns. That file only ever holds OpenShift OAuth
// tokens scoped to `role:view:*`, so oc, kubectl and helm run by the agent can
// read but not change anything: the cluster itself refuses the rest.
//
// The file follows the user's own current context (API server, namespace).
// When a command needs a cluster and no valid read-only token exists for that
// server, the plugin asks for the user's password in a native macOS dialog and
// mints one through OpenShift's OAuth challenge flow. The password is kept in
// memory only, to renew the token silently until opencode restarts.
//
// Fail closed: KUBECONFIG is replaced for every shell, before anything else
// can go wrong. Without a token the agent's oc gets no credentials at all,
// never the user's.

import type { Plugin } from '@opencode/plugin'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { SCOPED_KUBECONFIG_NAME, checkCommand, checkPath, checkSegment, denyMessage, needsCluster } from './guard.ts'
import {
  type ClusterEntry,
  type CurrentContext,
  type Kubeconfig,
  parseCurrentContext,
  parseScopedKubeconfig,
  removeServer,
  storedToken,
  upsertServer,
} from './kubeconfig.ts'
import { type CurlTls, authorizeCurlConfig, discoveryCurlArgs, parseAuthorizeResponse, parseIssuer } from './oauth.ts'
import { type System, nodeSystem } from './system.ts'

/** The V2 plugin id. */
export const PLUGIN_ID = 'opencode-plugin-openshift-readonly-agent'

/** Renew this long before the token expires. */
const RENEW_MARGIN_MS = 60_000
/** A stored token of unknown age is re-checked after this long. */
const UNKNOWN_EXPIRY_RECHECK_MS = 10 * 60_000
/** After a cancelled dialog, commands fail without asking again for this long. */
const PROMPT_COOLDOWN_MS = 60_000

type Env = Record<string, string | undefined>

interface TokenState {
  readonly token: string
  readonly expiresAt: number
  /**
   * The real expiry is unknown (a token from an earlier opencode run, or an
   * OAuth reply without expires_in): `expiresAt` is only when to ask the API
   * server again, not when to mint a new one.
   */
  readonly recheckOnly: boolean
}

export interface AgentOptions {
  readonly system?: System
  /** Home directory; the read-only kubeconfig lives in `<home>/.kube`. */
  readonly home?: string
}

/** A shell command that prints the reason to stderr and fails. */
export function failCommand(message: string): string {
  const quoted = `'${message.replace(/'/g, `'\\''`)}'`
  return `printf '%s\\n' ${quoted} >&2; exit 1`
}

export function createReadonlyAgent(options: AgentOptions = {}) {
  const system = options.system ?? nodeSystem
  const home = options.home ?? homedir()
  const scopedPath = join(home, '.kube', SCOPED_KUBECONFIG_NAME)
  const defaultUserKubeconfig = join(home, '.kube', 'config')

  const tokens = new Map<string, TokenState>()
  const issuers = new Map<string, string>()
  const passwords = new Map<string, string>()
  let promptBlockedUntil = 0
  let queue: Promise<unknown> = Promise.resolve()

  /** One preparation at a time, so parallel shells never open two dialogs. */
  function serialize<T>(task: () => Promise<T>): Promise<T> {
    const next = queue.then(task, task)
    queue = next.catch(() => undefined)
    return next
  }

  /** The kubeconfig the user's own tools read, as the shell would have seen it. */
  function userKubeconfig(env: Env): string {
    const value = env.KUBECONFIG
    if (!value) return defaultUserKubeconfig
    const parts = value.split(':').filter((p) => p !== '' && p !== scopedPath)
    return parts.length > 0 ? parts.join(':') : defaultUserKubeconfig
  }

  async function writeConfig(config: Kubeconfig): Promise<void> {
    await system.writePrivate(scopedPath, `${JSON.stringify(config, null, 2)}\n`)
  }

  async function loadConfig(): Promise<Kubeconfig> {
    return parseScopedKubeconfig(await system.readText(scopedPath))
  }

  /** Runs oc, falling back to kubectl when oc is not installed. */
  async function cli(args: readonly string[], env: Env, kubeconfig: string) {
    let last = { code: 127, stdout: '', stderr: 'neither oc nor kubectl is on PATH' }
    for (const program of ['oc', 'kubectl']) {
      const result = await system.run(program, args, { env: { ...env, KUBECONFIG: kubeconfig }, timeoutMs: 20_000 })
      if (result.code !== 127 && !/ENOENT/.test(result.stderr)) return result
      last = result
    }
    return last
  }

  async function currentContext(env: Env): Promise<CurrentContext | string> {
    const result = await cli(['config', 'view', '--minify', '--raw', '-o', 'json'], env, userKubeconfig(env))
    if (result.code === 127) return 'neither oc nor kubectl is on PATH'
    const parsed = result.code === 0 ? parseCurrentContext(result.stdout) : undefined
    if (!parsed) return 'your kubeconfig has no current context; log in with `oc login` in your own terminal first'
    return parsed
  }

  async function tlsFor(cluster: ClusterEntry): Promise<CurlTls> {
    const data = cluster['certificate-authority-data']
    let caFile = cluster['certificate-authority']
    if (data) {
      const pem = Buffer.from(data, 'base64').toString('utf8')
      const hash = createHash('sha256').update(pem).digest('hex').slice(0, 16)
      caFile = join(home, '.cache', PLUGIN_ID, `ca-${hash}.pem`)
      await system.writePrivate(caFile, pem)
    }
    return { ...(caFile ? { caFile } : {}), ...(cluster['insecure-skip-tls-verify'] ? { insecure: true } : {}) }
  }

  async function issuerFor(cluster: ClusterEntry, env: Env): Promise<string | undefined> {
    const cached = issuers.get(cluster.server)
    if (cached) return cached
    const result = await system.run('curl', discoveryCurlArgs(cluster.server, await tlsFor(cluster)), { env, timeoutMs: 20_000 })
    const issuer = result.code === 0 ? parseIssuer(result.stdout) : undefined
    if (issuer) issuers.set(cluster.server, issuer)
    return issuer
  }

  async function loginName(context: CurrentContext, env: Env): Promise<string | undefined> {
    if (context.username) return context.username
    const result = await cli(['whoami'], env, userKubeconfig(env))
    const name = result.code === 0 ? result.stdout.trim() : ''
    return name !== '' && !name.includes(':') ? name : undefined
  }

  /** True when the API server accepts the token (`user:info` is in scope). */
  async function tokenWorks(env: Env): Promise<boolean> {
    const result = await cli(['get', '--raw', '/apis/user.openshift.io/v1/users/~'], env, scopedPath)
    return result.code === 0
  }

  async function mint(context: CurrentContext, env: Env): Promise<TokenState | string> {
    const host = new URL(context.cluster.server).host
    const username = await loginName(context, env)
    if (!username) return `cannot tell your OpenShift login name from the kubeconfig for ${host}`
    const issuer = await issuerFor(context.cluster, env)
    if (!issuer) return `cannot reach the OAuth discovery document of ${host}`
    const key = `${issuer}|${username}`

    for (let attempt = 0; attempt < 2; attempt++) {
      let password = passwords.get(key)
      const fromMemory = password !== undefined
      if (!password) {
        if (system.now() < promptBlockedUntil) {
          return 'the password dialog was cancelled a moment ago; the next oc command will ask again shortly'
        }
        const answer = await system.promptSecret(
          'OpenShift read-only agent',
          `opencode wants a read-only token for ${host}.\n\nPassword for ${username}:`,
          env,
        )
        if (answer.kind === 'cancelled') {
          promptBlockedUntil = system.now() + PROMPT_COOLDOWN_MS
          return 'the password dialog was cancelled, so there is no read-only token; ask the user'
        }
        if (answer.kind === 'unavailable') return `cannot ask for the password: ${answer.reason}`
        if (answer.value === '') return 'an empty password was entered'
        password = answer.value
      }
      const curl = await system.run('curl', ['--config', '-'], {
        env,
        input: authorizeCurlConfig({ issuer, username, password, ...(context.cluster['insecure-skip-tls-verify'] ? { insecure: true } : {}) }),
        timeoutMs: 40_000,
      })
      const result = parseAuthorizeResponse(curl.stdout)
      if (result.kind === 'token') {
        passwords.set(key, password)
        if (result.expiresInSeconds === undefined) {
          return { token: result.token, expiresAt: system.now() + UNKNOWN_EXPIRY_RECHECK_MS, recheckOnly: true }
        }
        return { token: result.token, expiresAt: system.now() + result.expiresInSeconds * 1000, recheckOnly: false }
      }
      if (result.kind === 'unauthorized') {
        // A remembered password may have been changed since: ask once more.
        passwords.delete(key)
        if (fromMemory) continue
        return `OpenShift rejected the password for ${username}`
      }
      // Network trouble or an OAuth error says nothing about the password: keep it.
      return `the OAuth server of ${host} refused a read-only token (${result.message})`
    }
    return `OpenShift rejected the password for ${username}`
  }

  /**
   * Makes the read-only kubeconfig current for the user's current context.
   * Returns why that failed, or undefined when the agent may go ahead.
   */
  async function prepare(env: Env): Promise<string | undefined> {
    const config = await loadConfig()
    const context = await currentContext(env)
    if (typeof context === 'string') {
      await writeConfig({ ...config, 'current-context': '' })
      return context
    }
    const server = context.cluster.server
    const write = (token: string) => writeConfig(upsertServer(config, { cluster: context.cluster, token, namespace: context.namespace }))

    const known = tokens.get(server)
    if (known && known.expiresAt - RENEW_MARGIN_MS > system.now()) {
      await write(known.token)
      return undefined
    }
    // A token of unknown lifetime (from an earlier opencode run, or due for a
    // recheck): keep it while the API server still takes it. Only a rejected
    // token leads to minting, and only minting can open the dialog.
    const candidate = known ? (known.recheckOnly ? known.token : undefined) : storedToken(config, server)
    if (candidate) {
      await write(candidate)
      if (await tokenWorks(env)) {
        tokens.set(server, { token: candidate, expiresAt: system.now() + UNKNOWN_EXPIRY_RECHECK_MS, recheckOnly: true })
        return undefined
      }
    }
    tokens.delete(server)
    const minted = await mint(context, env)
    if (typeof minted === 'string') {
      await writeConfig(removeServer(config, server))
      return minted
    }
    tokens.set(server, minted)
    await write(minted.token)
    return undefined
  }

  return {
    scopedPath,

    /** `shell.create.before`: runs for every shell the agent starts. */
    async onShellCreate(input: { command: string; env: Env }): Promise<void> {
      const env = { ...input.env }
      input.env.KUBECONFIG = scopedPath
      if (!needsCluster(input.command)) return
      // A command the permission hook will deny must not open a dialog first.
      if (checkCommand(input.command)) return
      let failure: string | undefined
      try {
        failure = await serialize(() => prepare(env))
      } catch (err) {
        failure = `unexpected error: ${err instanceof Error ? err.message : String(err)}`
      }
      if (failure) input.command = failCommand(`${PLUGIN_ID}: ${failure}`)
    },

    /**
     * `permission.evaluate`: denies shell segments that would bypass the
     * token, and file tools (read, edit, glob, …) pointed at ~/.kube.
     */
    onPermission(input: { readonly action: string; readonly resources: ReadonlyArray<string>; effect: string; message?: string }): void {
      const check = input.action === 'shell' ? checkSegment : checkPath
      for (const resource of input.resources) {
        const reason = check(resource)
        if (reason) {
          input.effect = 'deny'
          input.message = denyMessage(reason)
          return
        }
      }
    },
  }
}

// One agent per opencode process, not per `setup` call: should opencode set
// the plugin up once per project location, the token cache and the
// remembered password are still shared, so a second project opens no second
// dialog.
let shared: ReturnType<typeof createReadonlyAgent> | undefined

// A plain object, not `Plugin.define(...)`: `define` is an identity function,
// and importing it would make @opencode/plugin a runtime dependency.
export const OpenShiftReadonlyAgentPlugin = {
  id: PLUGIN_ID,
  async setup(ctx: Plugin.Context) {
    shared ??= createReadonlyAgent()
    const agent = shared
    const registrations = [
      await ctx.shell.hook('create.before', (input) => agent.onShellCreate(input)),
      await ctx.permission.hook('evaluate', (input) => agent.onPermission(input)),
    ]
    return async () => {
      for (const registration of registrations) await registration.dispose()
    }
  },
} satisfies Plugin.Plugin
