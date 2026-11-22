import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createReadonlyAgent, failCommand } from '../src/plugin.ts'
import type { PromptResult, RunOptions, RunResult, System } from '../src/system.ts'

const SERVER = 'https://api.example.com:6443'
const ISSUER = 'https://oauth-openshift.apps.example.com'

function userContext(namespace = 'team-a', server = SERVER, login = 'alice') {
  return JSON.stringify({
    clusters: [{ name: 'c', cluster: { server } }],
    contexts: [{ name: 'x', context: { cluster: 'c', user: `${login}/api-example-com:6443`, namespace } }],
    users: [{ name: `${login}/api-example-com:6443`, user: { token: 'sha256~FULL' } }],
  })
}

function redirect(token: string, expires = 86400) {
  return `HTTP/1.1 302 Found\r\nLocation: ${ISSUER}/oauth/token/implicit#access_token=${token}&expires_in=${expires}&token_type=Bearer\r\n\r\n`
}

interface Fake {
  system: System
  files: Map<string, string>
  prompts: number
  curlInputs: string[]
  runs: { command: string; args: readonly string[]; options: RunOptions }[]
  clock: number
  answers: PromptResult[]
  authorize: string[]
  context: string
  tokenAccepted: boolean
  networkDown: boolean
  mtimes: Map<string, number>
  /** curl exit codes for successive authorize calls (default 0). */
  authorizeCodes: number[]
}

function fake(): Fake {
  const f: Fake = {
    files: new Map(),
    prompts: 0,
    curlInputs: [],
    runs: [],
    clock: 1_000_000,
    answers: [],
    authorize: [],
    context: userContext(),
    tokenAccepted: true,
    networkDown: false,
    mtimes: new Map(),
    authorizeCodes: [],
    system: undefined as unknown as System,
  }
  f.system = {
    async run(command, args, options): Promise<RunResult> {
      f.runs.push({ command, args, options })
      if (command === 'oc' && args[0] === 'config') return { code: 0, stdout: f.context, stderr: '' }
      if (command === 'oc' && args[0] === 'get' && args[1] === '--raw') {
        if (f.networkDown) return { code: 1, stdout: '', stderr: 'Unable to connect to the server: dial tcp: i/o timeout' }
        return f.tokenAccepted ? { code: 0, stdout: '{}', stderr: '' } : { code: 1, stdout: '', stderr: 'error: You must be logged in to the server (Unauthorized)' }
      }
      if (command === 'curl' && args.includes('--config')) {
        f.curlInputs.push(options.input ?? '')
        const code = f.authorizeCodes.shift() ?? 0
        if (code !== 0) return { code, stdout: '', stderr: 'curl: (60) SSL certificate problem: unable to get local issuer certificate' }
        return { code: 0, stdout: f.authorize.shift() ?? '', stderr: '' }
      }
      if (command === 'curl') return { code: 0, stdout: JSON.stringify({ issuer: ISSUER }), stderr: '' }
      return { code: 127, stdout: '', stderr: 'ENOENT' }
    },
    async readText(path) {
      return f.files.get(path)
    },
    async mtime(path) {
      return f.mtimes.get(path) ?? 1
    },
    async writePrivate(path, content) {
      f.files.set(path, content)
    },
    async promptSecret() {
      f.prompts++
      return f.answers.shift() ?? { kind: 'cancelled' }
    },
    now: () => f.clock,
  }
  return f
}

const HOME = '/home/alice'
const SCOPED = '/home/alice/.kube/opencode-readonly-agent.json'

function shell(command: string, env: Record<string, string | undefined> = { PATH: '/usr/bin', KUBECONFIG: undefined }) {
  return { command, env: { ...env } }
}

test('every shell gets the read-only KUBECONFIG, even without a cluster command', async () => {
  const f = fake()
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const input = shell('ls -la', { PATH: '/usr/bin', KUBECONFIG: '/home/alice/.kube/config' })
  await agent.onShellCreate(input)
  assert.equal(input.env.KUBECONFIG, SCOPED)
  assert.equal(input.command, 'ls -la')
  assert.equal(f.prompts, 0)
})

test('indirect oc (scripts): a changed user kubeconfig is followed without a dialog', async () => {
  const f = fake()
  f.answers.push({ kind: 'answer', value: 'pw' })
  f.authorize.push(redirect('sha256~RO'))
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  await agent.onShellCreate(shell('oc get pods'))
  // The user runs `oc project other-ns` in their terminal: the file changes.
  f.context = userContext('other-ns')
  f.mtimes.set('/home/alice/.kube/config', 2)
  const script = shell('./scripts/status.sh')
  await agent.onShellCreate(script)
  assert.equal(script.command, './scripts/status.sh')
  assert.equal(JSON.parse(f.files.get(SCOPED)!).contexts[0].context.namespace, 'other-ns')
  // A login without a token is cleared, not left pointing at the old one.
  f.context = userContext('team-a', SERVER, 'bob')
  f.mtimes.set('/home/alice/.kube/config', 3)
  await agent.onShellCreate(shell('make status'))
  assert.equal(f.prompts, 1)
  assert.equal(JSON.parse(f.files.get(SCOPED)!)['current-context'], '')
})

test('a non-default KUBECONFIG gets its own read-only file', async () => {
  const f = fake()
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const prod = shell('ls', { PATH: '/usr/bin', KUBECONFIG: '/home/alice/prod.yaml' })
  const test = shell('ls', { PATH: '/usr/bin', KUBECONFIG: '/home/alice/test.yaml' })
  await agent.onShellCreate(prod)
  await agent.onShellCreate(test)
  assert.match(prod.env.KUBECONFIG!, /^\/home\/alice\/\.kube\/opencode-readonly-agent-[0-9a-f]{12}\.json$/)
  assert.notEqual(prod.env.KUBECONFIG, test.env.KUBECONFIG)
  // The plugin's own file in KUBECONFIG is never mistaken for the user's.
  const again = shell('ls', { PATH: '/usr/bin', KUBECONFIG: prod.env.KUBECONFIG })
  await agent.onShellCreate(again)
  assert.equal(again.env.KUBECONFIG, SCOPED)
})

test('OAuth route behind the kubeconfig CA: TLS error, then retry with the CA', async () => {
  const f = fake()
  f.context = JSON.stringify({
    clusters: [{ name: 'c', cluster: { server: SERVER, 'certificate-authority-data': Buffer.from('PEM').toString('base64'), 'proxy-url': 'http://bastion:3128' } }],
    contexts: [{ name: 'x', context: { cluster: 'c', user: 'alice/api-example-com:6443', namespace: 'team-a' } }],
    users: [{ name: 'alice/api-example-com:6443', user: { token: 'sha256~FULL' } }],
  })
  f.answers.push({ kind: 'answer', value: 'pw' })
  f.authorizeCodes.push(60)
  f.authorize.push(redirect('sha256~RO'))
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const input = shell('oc get pods')
  await agent.onShellCreate(input)
  assert.equal(input.command, 'oc get pods')
  assert.doesNotMatch(f.curlInputs[0]!, /cacert/)
  assert.match(f.curlInputs[1]!, /^cacert = "\/home\/alice\/\.cache\/opencode-plugin-openshift-readonly-agent\/ca-[0-9a-f]+\.pem"$/m)
  assert.match(f.curlInputs[1]!, /^proxy = "http:\/\/bastion:3128"$/m)
  const discovery = f.runs.find((r) => r.command === 'curl' && !r.args.includes('--config'))!
  assert.ok(discovery.args.includes('--proxy'))
  assert.ok(discovery.args.includes('--cacert'))
})

test('curl failure without output names the curl error', async () => {
  const f = fake()
  f.answers.push({ kind: 'answer', value: 'pw' })
  f.authorizeCodes.push(60)
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const input = shell('oc get pods')
  await agent.onShellCreate(input)
  assert.match(input.command, /curl exit 60: curl: \(60\) SSL certificate problem/)
})

test('first oc command: one dialog, token minted, file follows the user context', async () => {
  const f = fake()
  f.answers.push({ kind: 'answer', value: 'pw"1' })
  f.authorize.push(redirect('sha256~RO'))
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const input = shell('oc get pods')
  await agent.onShellCreate(input)

  assert.equal(input.command, 'oc get pods')
  assert.equal(input.env.KUBECONFIG, SCOPED)
  assert.equal(f.prompts, 1)
  const config = JSON.parse(f.files.get(SCOPED)!)
  assert.equal(config.users[0].user.token, 'sha256~RO')
  assert.equal(config.contexts[0].context.namespace, 'team-a')
  assert.equal(config.clusters[0].cluster.server, SERVER)
  assert.doesNotMatch(f.files.get(SCOPED)!, /FULL/)
  // The user kubeconfig was read through KUBECONFIG, the password went via stdin.
  assert.equal(f.runs[0]!.options.env.KUBECONFIG, '/home/alice/.kube/config')
  assert.match(f.curlInputs[0]!, /^user = "alice:pw\\"1"$/m)
  assert.ok(f.runs.every((r) => !r.args.join(' ').includes('pw')))
})

test('second command: no dialog; namespace switch in the user terminal carries over', async () => {
  const f = fake()
  f.answers.push({ kind: 'answer', value: 'pw' })
  f.authorize.push(redirect('sha256~RO'))
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  await agent.onShellCreate(shell('oc get pods'))
  f.context = userContext('other-ns')
  await agent.onShellCreate(shell('oc get deploy'))
  assert.equal(f.prompts, 1)
  assert.equal(JSON.parse(f.files.get(SCOPED)!).contexts[0].context.namespace, 'other-ns')
})

test('expired token renews silently with the remembered password', async () => {
  const f = fake()
  f.answers.push({ kind: 'answer', value: 'pw' })
  f.authorize.push(redirect('sha256~ONE', 3600), redirect('sha256~TWO', 3600))
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  await agent.onShellCreate(shell('oc get pods'))
  f.clock += 3600 * 1000
  await agent.onShellCreate(shell('oc get pods'))
  assert.equal(f.prompts, 1)
  assert.equal(JSON.parse(f.files.get(SCOPED)!).users[0].user.token, 'sha256~TWO')
})

test('cancelled dialog: command fails closed with a reason, no token in the file', async () => {
  const f = fake()
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const input = shell('oc get pods')
  await agent.onShellCreate(input)
  assert.match(input.command, /^printf '%s\\n' '.*cancelled.*' >&2; exit 1$/)
  assert.equal(input.env.KUBECONFIG, SCOPED)
  const config = JSON.parse(f.files.get(SCOPED)!)
  assert.equal(config.users.length, 0)
  assert.equal(config['current-context'], '')
  // Within the cooldown the next command fails without a new dialog.
  await agent.onShellCreate(shell('oc get pods'))
  assert.equal(f.prompts, 1)
})

test('wrong password is reported and not remembered', async () => {
  const f = fake()
  f.answers.push({ kind: 'answer', value: 'bad' }, { kind: 'answer', value: 'good' })
  f.authorize.push('HTTP/1.1 401 Unauthorized\r\n\r\n', redirect('sha256~RO'))
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const first = shell('oc get pods')
  await agent.onShellCreate(first)
  assert.match(first.command, /rejected the password/)
  const second = shell('oc get pods')
  await agent.onShellCreate(second)
  assert.equal(second.command, 'oc get pods')
  assert.equal(f.prompts, 2)
})

test('a token from an earlier opencode run is reused while the server accepts it', async () => {
  const f = fake()
  f.files.set(
    SCOPED,
    JSON.stringify({
      apiVersion: 'v1',
      kind: 'Config',
      clusters: [{ name: 'readonly-agent/alice@api.example.com:6443', cluster: { server: SERVER } }],
      users: [{ name: 'readonly-agent/alice@api.example.com:6443', user: { token: 'sha256~OLD' } }],
      contexts: [],
      'current-context': '',
    }),
  )
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const input = shell('oc get pods')
  await agent.onShellCreate(input)
  assert.equal(input.command, 'oc get pods')
  assert.equal(f.prompts, 0)
  assert.equal(JSON.parse(f.files.get(SCOPED)!).users[0].user.token, 'sha256~OLD')
})

test('a reused token keeps working past the recheck interval without a dialog', async () => {
  const f = fake()
  f.files.set(
    SCOPED,
    JSON.stringify({
      apiVersion: 'v1',
      kind: 'Config',
      clusters: [{ name: 'readonly-agent/alice@api.example.com:6443', cluster: { server: SERVER } }],
      users: [{ name: 'readonly-agent/alice@api.example.com:6443', user: { token: 'sha256~OLD' } }],
      contexts: [],
      'current-context': '',
    }),
  )
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  await agent.onShellCreate(shell('oc get pods'))
  f.clock += 60 * 60_000
  const later = shell('oc get pods')
  await agent.onShellCreate(later)
  assert.equal(later.command, 'oc get pods')
  assert.equal(f.prompts, 0)
  // Once the server rejects it, the next command mints a new one.
  f.tokenAccepted = false
  f.clock += 60 * 60_000
  f.answers.push({ kind: 'answer', value: 'pw' })
  f.authorize.push(redirect('sha256~NEW'))
  await agent.onShellCreate(shell('oc get pods'))
  assert.equal(f.prompts, 1)
  assert.equal(JSON.parse(f.files.get(SCOPED)!).users[0].user.token, 'sha256~NEW')
})

test('an OAuth hiccup keeps the remembered password', async () => {
  const f = fake()
  f.answers.push({ kind: 'answer', value: 'pw' })
  f.authorize.push(redirect('sha256~ONE', 3600), '', redirect('sha256~THREE', 3600))
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  await agent.onShellCreate(shell('oc get pods'))
  f.clock += 3600 * 1000
  const failed = shell('oc get pods')
  await agent.onShellCreate(failed)
  assert.match(failed.command, /refused a read-only token/)
  await agent.onShellCreate(shell('oc get pods'))
  assert.equal(f.prompts, 1)
  assert.equal(JSON.parse(f.files.get(SCOPED)!).users[0].user.token, 'sha256~THREE')
})

test('file tools pointed at ~/.kube are denied, the plugin file is not', () => {
  const agent = createReadonlyAgent({ system: fake().system, home: HOME })
  for (const resource of ['home/.kube/config', '/home/alice/.kube/config', '~/.kube', '.kube/prod.yaml']) {
    const evaluation = { action: 'read', resources: [resource], effect: 'allow', message: undefined as string | undefined }
    agent.onPermission(evaluation)
    assert.equal(evaluation.effect, 'deny', resource)
  }
  for (const resource of [
    '/home/alice/.kube/opencode-readonly-agent.json',
    'src/kube.ts',
    'docs/kubeconfig.md',
    '.kube-linter.yaml',
    'deploy/.kubernetes/app.yaml',
    '.kubeconform',
  ]) {
    const evaluation = { action: 'read', resources: [resource], effect: 'allow' }
    agent.onPermission(evaluation)
    assert.equal(evaluation.effect, 'allow', resource)
  }
})

test('HELM_KUBE* variables from the user profile are removed from the agent shell', async () => {
  const f = fake()
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const input = shell('ls', { PATH: '/usr/bin', HELM_KUBETOKEN: 'sha256~FULL', HELM_KUBEAPISERVER: 'https://x', HELM_DEBUG: '1' })
  await agent.onShellCreate(input)
  assert.equal(input.env.HELM_KUBETOKEN, undefined)
  assert.equal(input.env.HELM_KUBEAPISERVER, undefined)
  assert.equal(input.env.HELM_DEBUG, '1')
})

test('a network error during the token check keeps the token and opens no dialog', async () => {
  const f = fake()
  f.files.set(
    SCOPED,
    JSON.stringify({
      apiVersion: 'v1',
      kind: 'Config',
      clusters: [{ name: 'readonly-agent/alice@api.example.com:6443', cluster: { server: SERVER } }],
      users: [{ name: 'readonly-agent/alice@api.example.com:6443', user: { token: 'sha256~OLD' } }],
      contexts: [],
      'current-context': '',
    }),
  )
  f.networkDown = true
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const input = shell('oc get pods')
  await agent.onShellCreate(input)
  assert.equal(input.command, 'oc get pods')
  assert.equal(f.prompts, 0)
  assert.equal(JSON.parse(f.files.get(SCOPED)!).users[0].user.token, 'sha256~OLD')
  // Back online: the token is checked again and kept.
  f.networkDown = false
  await agent.onShellCreate(shell('oc get pods'))
  assert.equal(f.prompts, 0)
})

test('after the user logs in as someone else, the agent gets that login, not the old token', async () => {
  const f = fake()
  f.context = userContext('team-a', SERVER, 'admin-alice')
  f.answers.push({ kind: 'answer', value: 'pw1' }, { kind: 'answer', value: 'pw2' })
  f.authorize.push(redirect('sha256~ADMIN'), redirect('sha256~ALICE'))
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  await agent.onShellCreate(shell('oc get pods'))
  f.context = userContext('team-a', SERVER, 'alice')
  await agent.onShellCreate(shell('oc get pods'))
  assert.equal(f.prompts, 2)
  assert.match(f.curlInputs[1]!, /^user = "alice:pw2"$/m)
  const config = JSON.parse(f.files.get(SCOPED)!)
  const current = config.users.find((u: { name: string }) => u.name === config['current-context'])
  assert.equal(current.user.token, 'sha256~ALICE')
})

test('tool hook denies a recursive grep from home', () => {
  const agent = createReadonlyAgent({ system: fake().system, home: HOME })
  assert.match(agent.checkTool('grep', { pattern: 'token', path: HOME })!, /walk into ~\/\.kube/)
  assert.equal(agent.checkTool('grep', { pattern: 'token', path: `${HOME}/src/app` }), undefined)
  // opencode started in ~: no path, `.` and `..` resolve against the project directory.
  assert.ok(agent.checkTool('grep', { pattern: 'token' }, HOME))
  assert.ok(agent.checkTool('glob', { pattern: '**/config', path: '.' }, HOME))
  assert.ok(agent.checkTool('grep', { pattern: 'token', path: '../..' }, `${HOME}/src/app`))
  assert.equal(agent.checkTool('grep', { pattern: 'token' }, `${HOME}/src/app`), undefined)
})

test('commands the permission hook will deny never open a dialog', async () => {
  const f = fake()
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  await agent.onShellCreate(shell('oc get pods --kubeconfig ~/.kube/config'))
  assert.equal(f.prompts, 0)
})

test('no current context in the user kubeconfig fails closed', async () => {
  const f = fake()
  f.context = '{"clusters":[],"contexts":[],"users":[]}'
  const agent = createReadonlyAgent({ system: f.system, home: HOME })
  const input = shell('oc get pods')
  await agent.onShellCreate(input)
  assert.match(input.command, /oc login/)
  assert.equal(f.prompts, 0)
})

test('permission hook denies bypasses with a message', () => {
  const agent = createReadonlyAgent({ system: fake().system, home: HOME })
  const evaluation = { action: 'shell', resources: ['echo ok', 'KUBECONFIG=~/.kube/config oc delete pod x'], effect: 'allow', message: undefined as string | undefined }
  agent.onPermission(evaluation)
  assert.equal(evaluation.effect, 'deny')
  assert.match(evaluation.message!, /read-only by design/)
  const fine = { action: 'shell', resources: ['oc get pods'], effect: 'allow' }
  agent.onPermission(fine)
  assert.equal(fine.effect, 'allow')
  const other = { action: 'edit', resources: ['src/index.ts'], effect: 'allow' }
  agent.onPermission(other)
  assert.equal(other.effect, 'allow')
})

test('failCommand quotes single quotes', () => {
  assert.equal(failCommand("it's"), `printf '%s\\n' 'it'\\''s' >&2; exit 1`)
})
