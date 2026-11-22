// Recognises shell commands that would route an agent's cluster access around
// the read-only kubeconfig this plugin injects.
//
// This is a guardrail against mistakes, not a security boundary: it reads the
// command text, not what the command does. `bash -c "$(echo … | base64 -d)"`
// or a script written to disk and executed later are not caught. The real
// limit is the token itself, which the cluster only accepts for reads.

/** The CLIs whose credentials come from a kubeconfig. */
const CLUSTER_CLIS = new Set(['oc', 'kubectl', 'helm'])

/** The kubeconfig this plugin owns. References to it are harmless. */
export const SCOPED_KUBECONFIG_NAME = 'opencode-readonly-agent.json'

/**
 * Flags that hand oc/kubectl/helm credentials or a different identity, or
 * point the read-only token at another API server.
 */
const CREDENTIAL_FLAGS = new Set([
  '--kubeconfig',
  '--token',
  '--as',
  '--as-group',
  '--as-uid',
  '--username',
  '--password',
  '--client-certificate',
  '--client-key',
  '--server',
  '--kube-token',
  '--kube-as-user',
  '--kube-as-group',
  '--kube-apiserver',
])

/** Flags whose next word is a value, not a subcommand. */
const VALUE_FLAGS = new Set([
  '-n',
  '--namespace',
  '--context',
  '--cluster',
  '--user',
  '-l',
  '--selector',
  '-o',
  '--output',
  '-c',
  '--container',
  '-f',
  '--filename',
  '--request-timeout',
  '--kube-context',
])

/** `oc config` / `kubectl config` subcommands that only read. */
const CONFIG_READ_SUBCOMMANDS = new Set(['view', 'get-contexts', 'current-context', 'get-clusters', 'get-users'])

/** Programs that run the command after them: `watch oc get pods`. */
const WRAPPERS = new Set(['watch', 'timeout', 'xargs', 'time', 'nice', 'nohup', 'env', 'command', 'exec'])

/** Subcommands and flags that never reach a cluster. */
const LOCAL_ONLY_SUBCOMMANDS = new Set(['completion', 'help', 'options', 'plugin', 'env'])

function words(segment: string): string[] {
  return segment.trim().split(/\s+/).filter(Boolean)
}

/** Strips leading `VAR=value` assignments and returns the remaining words. */
function commandWords(segment: string): string[] {
  const all = words(segment)
  let i = 0
  while (i < all.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(all[i]!)) i++
  return all.slice(i)
}

/** Checks text that matters in any segment, whatever program it runs. */
function checkAnySegment(segment: string): string | undefined {
  if (/\bKUBECONFIG\s*=/.test(segment)) return 'it sets KUBECONFIG'
  if (/\b(unset|export|typeset|declare)\b[^;|&]*\bKUBECONFIG\b/.test(segment)) return 'it changes KUBECONFIG'
  if (/(^|\s)env\b[^;|&]*(\s-i\b|\s--ignore-environment\b|\s-u\s*KUBECONFIG\b|\s--unset[= ]KUBECONFIG\b)/.test(segment)) {
    return 'it runs a command without the read-only KUBECONFIG'
  }
  const kubeDir = /\.kube\/([^\s'"`;|&)]*)/g
  for (const match of segment.matchAll(kubeDir)) {
    if (match[1] !== SCOPED_KUBECONFIG_NAME) return 'it touches a kubeconfig in ~/.kube that holds your full credentials'
  }
  return undefined
}

/** Checks one oc/kubectl/helm invocation. */
function checkClusterInvocation(cli: string, args: string[]): string | undefined {
  for (const arg of args) {
    const flag = arg.split('=')[0]!
    if (CREDENTIAL_FLAGS.has(flag)) return `${cli} ${flag} would bypass the read-only token`
    if (cli !== 'helm' && flag === '-s') return `${cli} -s would point the token at another server`
  }
  const positional: string[] = []
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    if (arg.startsWith('-')) {
      if (VALUE_FLAGS.has(arg)) i++
      continue
    }
    positional.push(arg)
  }
  const [sub, next] = positional
  if (cli === 'helm') return undefined
  if (sub === 'login' || sub === 'logout') return `${cli} ${sub} would replace the read-only login`
  if (sub === 'whoami' && args.some((a) => a === '-t' || a === '--show-token')) {
    return `${cli} whoami --show-token would print the token into the conversation`
  }
  if (sub === 'project' && next !== undefined) {
    return `${cli} project <name> switches the namespace for good; pass -n <namespace> instead`
  }
  if (sub === 'config') {
    if (next === undefined || !CONFIG_READ_SUBCOMMANDS.has(next)) return `${cli} config ${next ?? ''} would change the kubeconfig`.trimEnd()
    if (args.includes('--raw')) return `${cli} config view --raw would print the token into the conversation`
  }
  return undefined
}

/**
 * Returns why one command segment must not run, or undefined when it may.
 * opencode splits a command on `&&`, `||`, `;` and `|` before evaluating
 * permissions, so a segment is normally one simple command.
 */
export function checkSegment(segment: string): string | undefined {
  const any = checkAnySegment(segment)
  if (any) return any
  const all = commandWords(segment)
  // `watch oc …`, `xargs kubectl …`: check the cluster CLI wherever it sits.
  const at = all.findIndex((w) => CLUSTER_CLIS.has(w.split('/').pop()!))
  if (at < 0) return undefined
  const program = all[0]!.split('/').pop()!
  if (at > 0 && !WRAPPERS.has(program)) return undefined
  return checkClusterInvocation(all[at]!.split('/').pop()!, all.slice(at + 1))
}

function splitSegments(command: string): string[] {
  return command.split(/&&|\|\||[;|\n]/)
}

/** True when this segment calls oc/kubectl/helm against a cluster. */
function segmentNeedsCluster(segment: string): boolean {
  const all = commandWords(segment)
  const program = all[0]?.split('/').pop()
  if (program === undefined) return false
  let rest: string[]
  if (CLUSTER_CLIS.has(program)) {
    rest = all
  } else if (WRAPPERS.has(program)) {
    const at = all.findIndex((w) => CLUSTER_CLIS.has(w.split('/').pop()!))
    if (at < 0) return false
    rest = all.slice(at)
  } else {
    return false
  }
  const args = rest.slice(1)
  if (args.some((a) => a === '--help' || a === '-h' || a === '--client')) return false
  const sub = args.find((a) => !a.startsWith('-'))
  return sub === undefined || !LOCAL_ONLY_SUBCOMMANDS.has(sub)
}

/**
 * True when the command will talk to a cluster through oc, kubectl or helm,
 * which is when the plugin makes sure a read-only token is in place.
 * `which oc` or `brew upgrade helm` do not count.
 */
export function needsCluster(command: string): boolean {
  return splitSegments(command).some(segmentNeedsCluster)
}

/** Checks a whole command line the way opencode would see its segments. */
export function checkCommand(command: string): string | undefined {
  for (const segment of splitSegments(command)) {
    const reason = checkSegment(segment)
    if (reason) return reason
  }
  return undefined
}

/**
 * For file tools (read, edit, write, glob, grep, …): a path under `~/.kube`
 * other than the plugin's own file. opencode hands these resources over
 * relative to the project when they sit inside it (`home/.kube/config`), so
 * the match does not depend on the home directory prefix.
 */
export function checkPath(resource: string): string | undefined {
  const match = /(^|[/~])\.kube(?:\/([^/]*))?/.exec(resource)
  if (!match) return undefined
  if (match[2] === SCOPED_KUBECONFIG_NAME) return undefined
  return 'it touches ~/.kube, where your full credentials live'
}

/** The message the agent sees when a command is denied. */
export function denyMessage(reason: string): string {
  return (
    `opencode-plugin-openshift-readonly-agent blocked this: ${reason}. ` +
    'Cluster access from this agent is read-only by design. ' +
    'Ask the user to run commands that need more than read access.'
  )
}
