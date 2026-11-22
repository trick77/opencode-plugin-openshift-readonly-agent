// The user's current context in, the agent's read-only kubeconfig out.
//
// The read-only kubeconfig follows the user's own current context: the same
// API server and namespace, so an `oc project x` in the user's terminal
// carries over to the agent, but with the scoped token instead of the user's.
// It is written as JSON (a kubeconfig may be JSON), so no YAML parser is
// needed and the plugin keeps zero runtime dependencies.

export interface ClusterEntry {
  readonly server: string
  readonly 'certificate-authority'?: string
  readonly 'certificate-authority-data'?: string
  readonly 'insecure-skip-tls-verify'?: boolean
  readonly 'tls-server-name'?: string
  readonly 'proxy-url'?: string
}

export interface Kubeconfig {
  readonly apiVersion: 'v1'
  readonly kind: 'Config'
  readonly clusters: readonly { readonly name: string; readonly cluster: ClusterEntry }[]
  readonly users: readonly { readonly name: string; readonly user: { readonly token: string } }[]
  readonly contexts: readonly {
    readonly name: string
    readonly context: { readonly cluster: string; readonly user: string; readonly namespace?: string }
  }[]
  readonly 'current-context': string
}

/** What the plugin needs to know about the user's current context. */
export interface CurrentContext {
  readonly cluster: ClusterEntry
  readonly namespace: string | undefined
  /** OpenShift login name, when the kubeconfig user entry reveals it. */
  readonly username: string | undefined
}

const CLUSTER_KEYS = [
  'certificate-authority',
  'certificate-authority-data',
  'insecure-skip-tls-verify',
  'tls-server-name',
  'proxy-url',
] as const

/**
 * Parses `oc config view --minify --raw -o json`. `--minify` leaves only the
 * current context, its cluster and its user. Credentials of the user are read
 * here and dropped: only the cluster entry, namespace and login name survive.
 */
export function parseCurrentContext(json: string): CurrentContext | undefined {
  let config: {
    clusters?: { cluster?: Record<string, unknown> }[]
    contexts?: { context?: { namespace?: unknown } }[]
    users?: { name?: unknown }[]
  }
  try {
    config = JSON.parse(json)
  } catch {
    return undefined
  }
  const raw = config.clusters?.[0]?.cluster
  if (!raw || typeof raw.server !== 'string' || raw.server === '') return undefined
  const cluster: Record<string, unknown> = { server: raw.server }
  for (const key of CLUSTER_KEYS) if (raw[key] !== undefined) cluster[key] = raw[key]
  const namespace = config.contexts?.[0]?.context?.namespace
  return {
    cluster: cluster as unknown as ClusterEntry,
    namespace: typeof namespace === 'string' && namespace !== '' ? namespace : undefined,
    username: loginFromUserEntry(config.users?.[0]?.name),
  }
}

/**
 * `oc login` names kubeconfig users `<login>/<api-host-with-dashes>:<port>`.
 * Anything else (a context written by hand, an exec plugin) reveals nothing.
 */
export function loginFromUserEntry(name: unknown): string | undefined {
  if (typeof name !== 'string') return undefined
  const slash = name.indexOf('/')
  if (slash <= 0 || slash === name.length - 1) return undefined
  return name.slice(0, slash)
}

/** Stable entry name for one API server, e.g. `readonly-agent/api.example.com:6443`. */
export function entryName(server: string): string {
  return `readonly-agent/${new URL(server).host}`
}

export function emptyKubeconfig(): Kubeconfig {
  return { apiVersion: 'v1', kind: 'Config', clusters: [], users: [], contexts: [], 'current-context': '' }
}

/** Parses the plugin's own file; anything unreadable starts over empty. */
export function parseScopedKubeconfig(json: string | undefined): Kubeconfig {
  if (!json) return emptyKubeconfig()
  try {
    const parsed = JSON.parse(json) as Partial<Kubeconfig>
    if (!Array.isArray(parsed.clusters) || !Array.isArray(parsed.users) || !Array.isArray(parsed.contexts)) {
      return emptyKubeconfig()
    }
    return { ...emptyKubeconfig(), ...parsed } as Kubeconfig
  } catch {
    return emptyKubeconfig()
  }
}

/** The token stored for an API server, if any. */
export function storedToken(config: Kubeconfig, server: string): string | undefined {
  const name = entryName(server)
  return config.users.find((u) => u.name === name)?.user.token
}

/**
 * Puts one API server's entry into the file and makes it current. Entries of
 * other API servers stay, so switching clusters does not cost a new token.
 */
export function upsertServer(
  config: Kubeconfig,
  input: { readonly cluster: ClusterEntry; readonly token: string; readonly namespace: string | undefined },
): Kubeconfig {
  const name = entryName(input.cluster.server)
  const others = <T extends { readonly name: string }>(list: readonly T[]) => list.filter((e) => e.name !== name)
  return {
    apiVersion: 'v1',
    kind: 'Config',
    clusters: [...others(config.clusters), { name, cluster: input.cluster }],
    users: [...others(config.users), { name, user: { token: input.token } }],
    contexts: [
      ...others(config.contexts),
      { name, context: { cluster: name, user: name, ...(input.namespace ? { namespace: input.namespace } : {}) } },
    ],
    'current-context': name,
  }
}

/** Drops an API server's entry and current context, e.g. after a failed renewal. */
export function removeServer(config: Kubeconfig, server: string): Kubeconfig {
  const name = entryName(server)
  const others = <T extends { readonly name: string }>(list: readonly T[]) => list.filter((e) => e.name !== name)
  return {
    ...config,
    clusters: others(config.clusters),
    users: others(config.users),
    contexts: others(config.contexts),
    'current-context': config['current-context'] === name ? '' : config['current-context'],
  }
}
