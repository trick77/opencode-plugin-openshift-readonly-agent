// opencode-plugin-openshift-readonly-agent
//
// Every shell the opencode agent starts gets KUBECONFIG pointed at a
// kubeconfig this plugin owns. That file only ever holds OpenShift OAuth
// tokens scoped to `role:view:*`, so oc, kubectl and helm run by the agent can
// read but not change anything: the cluster itself refuses the rest.
//
// The file follows the user's own current context (API server, namespace,
// login). When a command needs a cluster and no valid read-only token exists
// for that server and login, the plugin asks for the user's password in a
// native desktop dialog and mints one through OpenShift's OAuth challenge
// flow. The password is kept in memory only, to renew the token silently
// until opencode restarts.
//
// Fail closed: KUBECONFIG is replaced for every shell, before anything else
// can go wrong. Without a token the agent's oc gets no credentials at all,
// never the user's.

import type { Plugin } from '@opencode/plugin'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { SCOPED_KUBECONFIG_NAME, checkCommand, checkPath, checkSegment, checkToolInput, denyMessage, needsCluster } from './guard.ts'
import {
  type ClusterEntry,
  type CurrentContext,
  type Kubeconfig,
  oauthLogin,
  parseCurrentContext,
  parseScopedKubeconfig,
  removeServer,
  storedToken,
  upsertServer,
} from './kubeconfig.ts'
import {
  CURL_TLS_ERRORS,
  type CurlTls,
  authorizeCurlConfig,
  discoveryCurlArgs,
  parseAuthorizeResponse,
  parseIssuer,
} from './oauth.ts'
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

/** One preparation: which user kubeconfig it follows and which file it writes. */
interface Target {
  /** The user's kubeconfig (KUBECONFIG value or `~/.kube/config`). */
  readonly source: string
  /** The plugin's kubeconfig for that source. */
  readonly scopedPath: string
}

export function createReadonlyAgent(options: AgentOptions = {}) {
  const system = options.system ?? nodeSystem
  const home = options.home ?? homedir()
  const kubeDir = join(home, '.kube')
  const defaultUserKubeconfig = join(kubeDir, 'config')

  const tokens = new Map<string, TokenState>()
  const issuers = new Map<string, string>()
  const passwords = new Map<string, string>()
  /** Modification times of each source when its scoped file was last written. */
  const seenSources = new Map<string, string>()
  let promptBlockedUntil = 0
  let queue: Promise<unknown> = Promise.resolve()

  /** One preparation at a time, so parallel shells never open two dialogs. */
  function serialize<T>(task: () => Promise<T>): Promise<T> {
    const next = queue.then(task, task)
    queue = next.catch(() => undefined)
    return next
  }

  /**
   * The user kubeconfig this shell would have used, and the plugin file for
   * it. Two opencode processes started with different KUBECONFIG values get
   * different files, so neither rewrites the other's current context.
   */
  function targetFor(env: Env): Target {
    const own = (path: string) => path.startsWith(`${kubeDir}/`) && /\/opencode-readonly-agent(-[0-9a-f]{12})?\.json$/.test(path)
    const parts = (env.KUBECONFIG ?? '').split(':').filter((p) => p !== '' && !own(p))
    const source = parts.length > 0 ? parts.join(':') : defaultUserKubeconfig
    if (source === defaultUserKubeconfig) return { source, scopedPath: join(kubeDir, SCOPED_KUBECONFIG_NAME) }
    const hash = createHash('sha256').update(source).digest('hex').slice(0, 12)
    return { source, scopedPath: join(kubeDir, `opencode-readonly-agent-${hash}.json`) }
  }

  async function sourceStamp(target: Target): Promise<string> {
    const times = await Promise.all(target.source.split(':').map((p) => system.mtime(p)))
    return times.map((t) => String(t ?? '-')).join(':')
  }

  async function writeConfig(target: Target, config: Kubeconfig): Promise<void> {
    await system.writePrivate(target.scopedPath, `${JSON.stringify(config, null, 2)}\n`)
  }

  async function loadConfig(target: Target): Promise<Kubeconfig> {
    return parseScopedKubeconfig(await system.readText(target.scopedPath))
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

  async function currentContext(env: Env, target: Target): Promise<CurrentContext | string> {
    const result = await cli(['config', 'view', '--minify', '--raw', '-o', 'json'], env, target.source)
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
    return {
      ...(caFile ? { caFile } : {}),
      ...(cluster['insecure-skip-tls-verify'] ? { insecure: true } : {}),
      ...(cluster['proxy-url'] ? { proxy: cluster['proxy-url'] } : {}),
    }
  }

  async function issuerFor(cluster: ClusterEntry, tls: CurlTls, env: Env): Promise<string | undefined> {
    const cached = issuers.get(cluster.server)
    if (cached) return cached
    const result = await system.run('curl', discoveryCurlArgs(cluster.server, tls), { env, timeoutMs: 20_000 })
    const issuer = result.code === 0 ? parseIssuer(result.stdout) : undefined
    if (issuer) issuers.set(cluster.server, issuer)
    return issuer
  }

  async function loginName(context: CurrentContext, env: Env, target: Target): Promise<string | undefined> {
    if (context.username) return context.username
    const result = await cli(['whoami'], env, target.source)
    return result.code === 0 ? oauthLogin(result.stdout.trim()) : undefined
  }

  /**
   * Asks the API server whether it takes the current token (`user:info` is in
   * scope). Only an authentication error counts as rejected: a timeout or a
   * dropped VPN must not throw away a good token and pop up the dialog.
   */
  async function tokenCheck(env: Env, target: Target): Promise<'ok' | 'rejected' | 'unreachable'> {
    const result = await cli(['get', '--raw', '/apis/user.openshift.io/v1/users/~'], env, target.scopedPath)
    if (result.code === 0) return 'ok'
    if (/Unauthorized|\b401\b|must be logged in|token (has )?expired|invalid bearer token/i.test(result.stderr)) return 'rejected'
    return 'unreachable'
  }

  /** One authorize request; retried with the kubeconfig CA after a TLS error. */
  async function authorize(input: { issuer: string; username: string; password: string; tls: CurlTls; env: Env }) {
    const base = {
      issuer: input.issuer,
      username: input.username,
      password: input.password,
      ...(input.tls.insecure ? { insecure: true } : {}),
      ...(input.tls.proxy ? { proxy: input.tls.proxy } : {}),
    }
    let curl = await system.run('curl', ['--config', '-'], { env: input.env, input: authorizeCurlConfig(base), timeoutMs: 40_000 })
    if (CURL_TLS_ERRORS.has(curl.code) && input.tls.caFile) {
      curl = await system.run('curl', ['--config', '-'], {
        env: input.env,
        input: authorizeCurlConfig({ ...base, caFile: input.tls.caFile }),
        timeoutMs: 40_000,
      })
    }
    const result = parseAuthorizeResponse(curl.stdout)
    if (result.kind === 'error' && curl.stdout.trim() === '' && curl.code !== 0) {
      return { kind: 'error' as const, message: `curl exit ${curl.code}: ${curl.stderr.trim().split('\n')[0] || 'no output'}` }
    }
    return result
  }

  async function mint(
    context: CurrentContext,
    username: string,
    env: Env,
    interactive: boolean,
  ): Promise<TokenState | string> {
    const host = new URL(context.cluster.server).host
    const tls = await tlsFor(context.cluster)
    const issuer = await issuerFor(context.cluster, tls, env)
    if (!issuer) return `cannot reach the OAuth discovery document of ${host}`
    const key = `${issuer}|${username}`

    for (let attempt = 0; attempt < 2; attempt++) {
      let password = passwords.get(key)
      const fromMemory = password !== undefined
      if (!password) {
        if (!interactive) return 'no read-only token yet; the next oc command will ask for the password'
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
      const result = await authorize({ issuer, username, password, tls, env })
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
        if (fromMemory && interactive) continue
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
   * Not interactive: never opens the dialog, used to keep the file in step
   * with the user's context for shells that do not call oc directly.
   */
  async function prepare(env: Env, target: Target, interactive: boolean): Promise<string | undefined> {
    const stamp = await sourceStamp(target)
    const config = await loadConfig(target)
    const context = await currentContext(env, target)
    const done = async (failure: string | undefined) => {
      seenSources.set(target.scopedPath, stamp)
      return failure
    }
    if (typeof context === 'string') {
      await writeConfig(target, { ...config, 'current-context': '' })
      return done(context)
    }
    const server = context.cluster.server
    const username = await loginName(context, env, target)
    if (!username) {
      await writeConfig(target, { ...config, 'current-context': '' })
      return done(`cannot tell your OpenShift login name from the kubeconfig for ${new URL(server).host}`)
    }
    const key = `${server}|${username}`
    const write = (token: string) =>
      writeConfig(target, upsertServer(config, { cluster: context.cluster, username, token, namespace: context.namespace }))

    const known = tokens.get(key)
    if (known && known.expiresAt - RENEW_MARGIN_MS > system.now()) {
      await write(known.token)
      return done(undefined)
    }
    // A token of unknown lifetime (from an earlier opencode run, or due for a
    // recheck): keep it while the API server still takes it. Only a rejected
    // token leads to minting, and only minting can open the dialog.
    const candidate = known ? (known.recheckOnly ? known.token : undefined) : storedToken(config, server, username)
    if (candidate) {
      await write(candidate)
      const check = await tokenCheck(env, target)
      if (check === 'ok') {
        tokens.set(key, { token: candidate, expiresAt: system.now() + UNKNOWN_EXPIRY_RECHECK_MS, recheckOnly: true })
        return done(undefined)
      }
      // Server unreachable: keep the token and let the command report the
      // network error itself; the next command checks again.
      if (check === 'unreachable') return done(undefined)
    }
    tokens.delete(key)
    const minted = await mint(context, username, env, interactive)
    if (typeof minted === 'string') {
      // Fail closed: no current context at all, not another login's entry.
      await writeConfig(target, { ...removeServer(config, server, username), 'current-context': '' })
      return done(minted)
    }
    tokens.set(key, minted)
    await write(minted.token)
    return done(undefined)
  }

  return {
    /** `shell.create.before`: runs for every shell the agent starts. */
    async onShellCreate(input: { command: string; env: Env }): Promise<void> {
      const env = { ...input.env }
      const target = targetFor(env)
      input.env.KUBECONFIG = target.scopedPath
      // helm takes credentials from these too (`--kube-token` and friends as
      // env): one exported in the user's profile would override the kubeconfig.
      for (const name of Object.keys(input.env)) if (name.startsWith('HELM_KUBE')) delete input.env[name]
      // A command the permission hook will deny must not open a dialog first.
      if (checkCommand(input.command)) return
      try {
        if (needsCluster(input.command)) {
          const failure = await serialize(() => prepare(env, target, true))
          if (failure) input.command = failCommand(`${PLUGIN_ID}: ${failure}`)
          return
        }
        // Scripts and make targets may call oc indirectly. When the user's
        // kubeconfig changed since the file was last written (`oc project`,
        // `oc login` in their terminal), bring the file in step, without a
        // dialog: a context with no token is cleared rather than left stale.
        const stamp = await sourceStamp(target)
        if (seenSources.get(target.scopedPath) !== stamp) {
          await serialize(() => prepare(env, target, false))
        }
      } catch (err) {
        if (needsCluster(input.command)) {
          input.command = failCommand(`${PLUGIN_ID}: unexpected error: ${err instanceof Error ? err.message : String(err)}`)
        }
      }
    },

    /**
     * `tool.execute.before`: the tool's own input, where grep and glob carry
     * their search root. `cwd` resolves relative and missing paths. Returns
     * why the call must not run.
     */
    checkTool(tool: string, input: unknown, cwd?: string): string | undefined {
      const reason = checkToolInput(tool, input, home, cwd)
      return reason ? denyMessage(reason) : undefined
    },

    /**
     * `permission.evaluate`: denies shell segments that would bypass the
     * token, and file tools (read, edit, …) pointed at ~/.kube.
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
    const cwd = ctx.location.directory
    const registrations = [
      await ctx.shell.hook('create.before', (input) => agent.onShellCreate(input)),
      await ctx.permission.hook('evaluate', (input) => agent.onPermission(input)),
      await ctx.tool.hook('execute.before', (input) => {
        // Throwing fails the tool call with this message, before it runs.
        const denied = agent.checkTool(input.tool, input.input, cwd)
        if (denied) throw new Error(denied)
      }),
    ]
    return async () => {
      for (const registration of registrations) await registration.dispose()
    }
  },
} satisfies Plugin.Plugin
