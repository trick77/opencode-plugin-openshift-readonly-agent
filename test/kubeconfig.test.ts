import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  emptyKubeconfig,
  entryName,
  loginFromUserEntry,
  parseCurrentContext,
  parseScopedKubeconfig,
  removeServer,
  storedToken,
  upsertServer,
} from '../src/kubeconfig.ts'

const minified = JSON.stringify({
  kind: 'Config',
  apiVersion: 'v1',
  clusters: [{ name: 'api-example-com:6443', cluster: { server: 'https://api.example.com:6443', 'certificate-authority-data': 'Q0E=' } }],
  contexts: [{ name: 'ns/api-example-com:6443/alice', context: { cluster: 'api-example-com:6443', user: 'alice/api-example-com:6443', namespace: 'team-a' } }],
  users: [{ name: 'alice/api-example-com:6443', user: { token: 'sha256~FULL' } }],
  'current-context': 'ns/api-example-com:6443/alice',
})

test('current context: cluster, namespace and login, never the token', () => {
  const ctx = parseCurrentContext(minified)
  assert.deepEqual(ctx, {
    cluster: { server: 'https://api.example.com:6443', 'certificate-authority-data': 'Q0E=' },
    namespace: 'team-a',
    username: 'alice',
  })
  assert.doesNotMatch(JSON.stringify(ctx), /FULL/)
})

test('no current context', () => {
  assert.equal(parseCurrentContext('{"clusters":[],"contexts":[],"users":[]}'), undefined)
  assert.equal(parseCurrentContext('garbage'), undefined)
})

test('login name only from oc-login style user entries', () => {
  assert.equal(loginFromUserEntry('alice/api-example-com:6443'), 'alice')
  assert.equal(loginFromUserEntry('admin'), undefined)
  assert.equal(loginFromUserEntry(undefined), undefined)
})

test('upsert keeps other servers and makes the new one current', () => {
  const a = upsertServer(emptyKubeconfig(), { cluster: { server: 'https://a:6443' }, token: 't1', namespace: 'x' })
  const b = upsertServer(a, { cluster: { server: 'https://b:6443' }, token: 't2', namespace: undefined })
  const a2 = upsertServer(b, { cluster: { server: 'https://a:6443' }, token: 't3', namespace: 'y' })
  assert.equal(a2['current-context'], entryName('https://a:6443'))
  assert.equal(a2.users.length, 2)
  assert.equal(storedToken(a2, 'https://a:6443'), 't3')
  assert.equal(storedToken(a2, 'https://b:6443'), 't2')
  assert.equal(a2.contexts.find((c) => c.name === entryName('https://a:6443'))?.context.namespace, 'y')
  assert.equal('namespace' in b.contexts.find((c) => c.name === entryName('https://b:6443'))!.context, false)
})

test('remove drops the entry and clears it as current', () => {
  const a = upsertServer(emptyKubeconfig(), { cluster: { server: 'https://a:6443' }, token: 't1', namespace: undefined })
  const r = removeServer(a, 'https://a:6443')
  assert.equal(r.users.length, 0)
  assert.equal(r['current-context'], '')
})

test('unreadable own file starts empty', () => {
  assert.deepEqual(parseScopedKubeconfig('nope'), emptyKubeconfig())
  assert.deepEqual(parseScopedKubeconfig(undefined), emptyKubeconfig())
})
