import { test } from 'node:test'
import assert from 'node:assert/strict'
import { authorizeCurlConfig, authorizeUrl, curlConfigValue, discoveryCurlArgs, parseAuthorizeResponse, parseIssuer } from '../src/oauth.ts'

test('authorize URL asks the challenging client for the read-only scopes', () => {
  const url = new URL(authorizeUrl('https://oauth-openshift.apps.example.com'))
  assert.equal(url.pathname, '/oauth/authorize')
  assert.equal(url.searchParams.get('client_id'), 'openshift-challenging-client')
  assert.equal(url.searchParams.get('response_type'), 'token')
  assert.equal(url.searchParams.get('scope'), 'user:info user:check-access role:view:*')
  assert.match(url.search, /scope=user%3Ainfo%20user%3Acheck-access%20role%3Aview%3A\*$/)
})

test('token from the Location fragment', () => {
  const headers = [
    'HTTP/1.1 302 Found',
    'Cache-Control: no-store',
    'Location: https://oauth-openshift.apps.example.com/oauth/token/implicit#access_token=sha256~abc&expires_in=86400&scope=role%3Aview%3A%2A&token_type=Bearer',
    '',
  ].join('\r\n')
  assert.deepEqual(parseAuthorizeResponse(headers), { kind: 'token', token: 'sha256~abc', expiresInSeconds: 86400 })
})

test('401 means a wrong password', () => {
  assert.deepEqual(parseAuthorizeResponse('HTTP/1.1 401 Unauthorized\r\nWww-Authenticate: Basic\r\n\r\n'), { kind: 'unauthorized' })
})

test('OAuth error in the redirect is reported', () => {
  const headers = 'HTTP/1.1 302 Found\r\nLocation: https://x/oauth/token/implicit#error=invalid_scope&error_description=scope+not+allowed\r\n'
  assert.deepEqual(parseAuthorizeResponse(headers), { kind: 'error', message: 'invalid_scope: scope not allowed' })
})

test('no response at all', () => {
  assert.equal(parseAuthorizeResponse('').kind, 'error')
})

test('curl config quotes the password safely', () => {
  assert.equal(curlConfigValue('a"b\\c'), '"a\\"b\\\\c"')
  const config = authorizeCurlConfig({ issuer: 'https://oauth.example.com', username: 'alice', password: 'p"w' })
  assert.match(config, /^user = "alice:p\\"w"$/m)
  assert.match(config, /^header = "X-CSRF-Token: 1"$/m)
  assert.doesNotMatch(config, /insecure/)
  assert.match(authorizeCurlConfig({ issuer: 'https://o', username: 'u', password: 'p', insecure: true }), /^insecure$/m)
})

test('discovery uses the kubeconfig CA', () => {
  const args = discoveryCurlArgs('https://api.example.com:6443', { caFile: '/tmp/ca.pem' })
  assert.deepEqual(args.slice(-3), ['--cacert', '/tmp/ca.pem', 'https://api.example.com:6443/.well-known/oauth-authorization-server'])
})

test('issuer must be https', () => {
  assert.equal(parseIssuer('{"issuer":"https://oauth-openshift.apps.example.com"}'), 'https://oauth-openshift.apps.example.com')
  assert.equal(parseIssuer('{"issuer":"http://evil"}'), undefined)
  assert.equal(parseIssuer('nope'), undefined)
})
