// OpenShift OAuth: getting a scoped token through the challenge flow.
//
// `openshift-challenging-client` answers a Basic-auth request to
// /oauth/authorize with a 302 whose Location fragment carries the token. The
// scope `role:view:*` limits the token to what the `view` cluster role allows
// in every namespace, intersected with the user's own rights. Without `:!` at
// the end, escalating resources such as Secrets stay out of reach.
//
// A bearer token cannot stand in for the password here: the OAuth server
// answers 401 to it. That is why minting needs the password at all.

/** Read access, plus what `oc whoami` and `oc auth can-i` need. */
export const READONLY_SCOPES = ['user:info', 'user:check-access', 'role:view:*'] as const

export const CHALLENGING_CLIENT = 'openshift-challenging-client'

export function authorizeUrl(issuer: string, scopes: readonly string[] = READONLY_SCOPES): string {
  // Built by hand rather than with URLSearchParams, which writes spaces as
  // `+`: `%20` is the form verified against a real OpenShift OAuth server.
  const base = new URL('/oauth/authorize', issuer).toString()
  const query = [
    `client_id=${encodeURIComponent(CHALLENGING_CLIENT)}`,
    'response_type=token',
    `scope=${scopes.map(encodeURIComponent).join('%20')}`,
  ].join('&')
  return `${base}?${query}`
}

export type AuthorizeResult =
  | { readonly kind: 'token'; readonly token: string; readonly expiresInSeconds: number | undefined }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'error'; readonly message: string }

/** Reads the status line and Location header out of `curl --dump-header -` output. */
export function parseAuthorizeResponse(headers: string): AuthorizeResult {
  const lines = headers.split(/\r?\n/)
  // curl prints one header block per response; follow-ups are not requested,
  // so the last status line is the one that counts.
  const statuses = lines.filter((l) => /^HTTP\/\S+\s+\d{3}/.test(l))
  const status = Number(statuses.at(-1)?.split(/\s+/)[1])
  if (status === 401) return { kind: 'unauthorized' }
  const location = lines.find((l) => /^location:/i.test(l))?.replace(/^location:\s*/i, '').trim()
  if (!location) {
    return { kind: 'error', message: Number.isFinite(status) ? `OAuth server answered HTTP ${status} without a redirect` : 'no response from the OAuth server' }
  }
  const url = new URL(location)
  const params = new URLSearchParams(url.hash.replace(/^#/, '') || url.search.replace(/^\?/, ''))
  const error = params.get('error')
  if (error) {
    const description = params.get('error_description')
    return { kind: 'error', message: description ? `${error}: ${description}` : error }
  }
  const token = params.get('access_token')
  if (!token) return { kind: 'error', message: 'the OAuth redirect carried no access_token' }
  const expires = Number(params.get('expires_in'))
  return { kind: 'token', token, expiresInSeconds: Number.isFinite(expires) && expires > 0 ? expires : undefined }
}

/** Quotes a value for a curl config file (`curl --config -`). */
export function curlConfigValue(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t')}"`
}

/** How curl reaches a cluster, taken from its kubeconfig entry. */
export interface CurlTls {
  /** PEM file with the CA from the kubeconfig. */
  readonly caFile?: string
  /** The kubeconfig sets insecure-skip-tls-verify for this cluster. */
  readonly insecure?: boolean
  /** The kubeconfig's `proxy-url` for this cluster. */
  readonly proxy?: string
}

/**
 * curl exit codes for TLS trouble (35 handshake, 51/60 peer certificate,
 * 58/59 local certificate, 77 CA file, 83/90/91 issuer/pinning/status).
 */
export const CURL_TLS_ERRORS: ReadonlySet<number> = new Set([35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91])

/**
 * The curl config for the authorize request. It goes to curl on stdin, so the
 * password never appears in a process listing. `caFile` is only set on a
 * retry: the OAuth route usually sits behind the ingress certificate, which
 * the system trust store knows and the kubeconfig's API-server CA may not.
 */
export function authorizeCurlConfig(input: {
  readonly issuer: string
  readonly username: string
  readonly password: string
  readonly insecure?: boolean
  readonly caFile?: string
  readonly proxy?: string
}): string {
  return [
    `url = ${curlConfigValue(authorizeUrl(input.issuer))}`,
    `user = ${curlConfigValue(`${input.username}:${input.password}`)}`,
    `header = ${curlConfigValue('X-CSRF-Token: 1')}`,
    'dump-header = "-"',
    'output = "/dev/null"',
    'silent',
    'show-error',
    'max-time = 30',
    ...(input.insecure ? ['insecure'] : []),
    ...(input.caFile ? [`cacert = ${curlConfigValue(input.caFile)}`] : []),
    ...(input.proxy ? [`proxy = ${curlConfigValue(input.proxy)}`] : []),
    '',
  ].join('\n')
}

/** curl arguments for the unauthenticated discovery document of an API server. */
export function discoveryCurlArgs(server: string, tls: CurlTls): string[] {
  const url = new URL('/.well-known/oauth-authorization-server', server).toString()
  return [
    '--silent',
    '--show-error',
    '--fail',
    '--max-time',
    '15',
    ...(tls.caFile ? ['--cacert', tls.caFile] : []),
    ...(tls.insecure ? ['--insecure'] : []),
    ...(tls.proxy ? ['--proxy', tls.proxy] : []),
    url,
  ]
}

/** Pulls `issuer` out of the discovery document. */
export function parseIssuer(body: string): string | undefined {
  try {
    const issuer = (JSON.parse(body) as { issuer?: unknown }).issuer
    return typeof issuer === 'string' && /^https:\/\//.test(issuer) ? issuer : undefined
  } catch {
    return undefined
  }
}
