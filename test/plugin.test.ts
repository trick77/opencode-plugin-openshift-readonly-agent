import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createReadonlyAgent, failCommand } from '../src/plugin.ts'
import type { PromptResult, RunOptions, RunResult, System } from '../src/system.ts'

const SERVER = 'https://api.example.com:6443'
const ISSUER = 'https://oauth-openshift.apps.example.com'

function userContext(namespace = 'team-a', server = SERVER) {
  return JSON.stringify({
    clusters: [{ name: 'c', cluster: { server } }],
    contexts: [{ name: 'x', context: { cluster: 'c', user: 'alice/api-example-com:6443', namespace } }],
    users: [{ name: 'alice/api-example-com:6443', user: { token: 'sha256~FULL' } }],
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
    system: undefined as unknown as System,
  }
  f.system = {
    async run(command, args, options): Promise<RunResult> {
      f.runs.push({ command, args, options })
      if (command === 'oc' && args[0] === 'config') return { code: 0, stdout: f.context, stderr: '' }
      if (command === 'oc' && args[0] === 'get' && args[1] === '--raw') {
        return f.tokenAccepted ? { code: 0, stdout: '{}', stderr: '' } : { code: 1, stdout: '', stderr: 'Unauthorized' }
      }
      if (command === 'curl' && args.includes('--config')) {
        f.curlInputs.push(options.input ?? '')
        return { code: 0, stdout: f.authorize.shift() ?? '', stderr: '' }
      }
      if (command === 'curl') return { code: 0, stdout: JSON.stringify({ issuer: ISSUER }), stderr: '' }
      return { code: 127, stdout: '', stderr: 'ENOENT' }
    },
    async readText(path) {
      return f.files.get(path)
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
  assert.equal(f.runs.length, 0)
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
      clusters: [{ name: 'readonly-agent/api.example.com:6443', cluster: { server: SERVER } }],
      users: [{ name: 'readonly-agent/api.example.com:6443', user: { token: 'sha256~OLD' } }],
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
      clusters: [{ name: 'readonly-agent/api.example.com:6443', cluster: { server: SERVER } }],
      users: [{ name: 'readonly-agent/api.example.com:6443', user: { token: 'sha256~OLD' } }],
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
  for (const resource of ['/home/alice/.kube/opencode-readonly-agent.json', 'src/kube.ts', 'docs/kubeconfig.md']) {
    const evaluation = { action: 'read', resources: [resource], effect: 'allow' }
    agent.onPermission(evaluation)
    assert.equal(evaluation.effect, 'allow', resource)
  }
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
