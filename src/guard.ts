// Recognises shell commands and file-tool calls that would route an agent's
// cluster access around the read-only kubeconfig this plugin injects.
//
// This is a guardrail against mistakes, not a security boundary: it reads the
// command text, not what the command does. `python -c "open(…)"`, an
// obfuscated command or a script written to disk and run later are not
// caught. The real limit is the token itself, which the cluster only accepts
// for reads.

/** The CLIs whose credentials come from a kubeconfig. */
const CLUSTER_CLIS = new Set(['oc', 'kubectl', 'helm'])

/**
 * The kubeconfig this plugin owns. A source kubeconfig other than the default
 * gets its own file with a hash suffix (see plugin.ts). References to these
 * files are harmless.
 */
export const SCOPED_KUBECONFIG_NAME = 'opencode-readonly-agent.json'
const OWN_FILE = /^opencode-readonly-agent(-[0-9a-f]{12})?\.json$/

/** Words that may stand in front of the program in a simple command. */
const SHELL_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', '{', '(', 'time'])

/**
 * Programs that run the command after them (`watch oc get pods`, `sudo oc …`),
 * with the options that take a separate value word (`sudo -u me`).
 */
const WRAPPERS: Record<string, ReadonlySet<string>> = {
  watch: new Set(['-n', '--interval']),
  timeout: new Set(['-s', '--signal', '-k', '--kill-after']),
  xargs: new Set(['-I', '-i', '-n', '--max-args', '-L', '-l', '-P', '--max-procs', '-d', '--delimiter', '-E', '-e', '-s', '-a', '--arg-file']),
  time: new Set(['-f', '--format', '-o', '--output']),
  nice: new Set(['-n', '--adjustment']),
  nohup: new Set(),
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']),
  command: new Set(),
  exec: new Set(['-a']),
  sudo: new Set(['-u', '--user', '-g', '--group', '-h', '--host', '-p', '--prompt', '-C', '--close-from', '-D', '--chdir', '-R', '--chroot', '-T', '--command-timeout', '-U', '--other-user', '-r', '--role', '-t', '--type']),
  doas: new Set(['-u', '-C']),
  stdbuf: new Set(['-i', '--input', '-o', '--output', '-e', '--error']),
  ionice: new Set(['-c', '--class', '-n', '--classdata', '-p', '--pid', '-P', '--pgid', '-u', '--uid']),
  caffeinate: new Set(['-t', '-w']),
}

/** Shells whose `-c` string is checked like a command line of its own. */
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh'])

/** Subcommands that never reach a cluster, per CLI. */
const LOCAL_ONLY_SUBCOMMANDS: Record<string, ReadonlySet<string>> = {
  oc: new Set(['completion', 'help', 'options', 'plugin', 'config', 'kustomize']),
  kubectl: new Set(['completion', 'help', 'options', 'plugin', 'config', 'kustomize']),
  helm: new Set([
    'completion',
    'create',
    'dep',
    'dependency',
    'env',
    'fetch',
    'help',
    'inspect',
    'lint',
    'package',
    'plugin',
    'pull',
    'push',
    'registry',
    'repo',
    'search',
    'show',
    'template',
    'verify',
    'version',
  ]),
}

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
  '--kube-ca-file',
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
  '-v',
  '--v',
  '--loglevel',
  '--vmodule',
  '--log-file',
  '--log-dir',
  '--certificate-authority',
  '--tls-server-name',
  '--cache-dir',
  '--profile',
  '--profile-output',
  '--registry-config',
  '--repository-config',
  '--repository-cache',
  '--burst-limit',
  '--qps',
])

/** The positional words of a CLI's arguments, skipping flags and their values. */
function positionals(args: readonly string[]): string[] {
  const found: string[] = []
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    if (arg.startsWith('-')) {
      if (VALUE_FLAGS.has(arg)) i++
      continue
    }
    found.push(arg)
  }
  return found
}

/** `oc config` / `kubectl config` subcommands that only read. */
const CONFIG_READ_SUBCOMMANDS = new Set(['view', 'get-contexts', 'current-context', 'get-clusters', 'get-users'])

function words(text: string): string[] {
  return text.trim().split(/\s+/).filter(Boolean)
}

/** `$(oc` → `oc`, `"oc"` → `oc`, `\oc` → `oc`, `{` stays `{`. */
function bareWord(word: string): string {
  const stripped = word.replace(/^(?:\$\(|[(`'"\\])+/, '').replace(/[)`'"]+$/, '')
  return stripped === '' ? word : stripped
}

/**
 * A program looked up by substitution runs as that program:
 * `$(command -v oc) login` and `` `which oc` login `` are `oc login`.
 */
function resolveLookups(segment: string): string {
  return segment
    .replace(/\$\(\s*(?:command\s+-[vV]|which|type\s+-[pP]|whence(?:\s+-p)?)\s+([^\s()]+)\s*\)/g, '$1')
    .replace(/`\s*(?:command\s+-[vV]|which|type\s+-[pP]|whence(?:\s+-p)?)\s+([^\s`]+)\s*`/g, '$1')
}

const basename = (word: string) => word.split('/').pop() ?? word

type Invocation =
  | { readonly kind: 'cluster'; readonly cli: string; readonly args: readonly string[] }
  | { readonly kind: 'nested'; readonly command: string }

/**
 * Finds what a segment runs: an oc/kubectl/helm call (possibly behind shell
 * keywords, env assignments and wrappers), or the `-c` string of a shell.
 */
function invocation(segment: string): Invocation | undefined {
  const all = words(resolveLookups(segment))
  let i = 0
  while (i < all.length) {
    const word = bareWord(all[i]!)
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word) || SHELL_KEYWORDS.has(word)) {
      i++
      continue
    }
    const program = basename(word)
    const valueOptions = WRAPPERS[program]
    if (valueOptions) {
      // `command -v oc` only looks the program up.
      if (program === 'command' && /^-[vV]$/.test(all[i + 1] ?? '')) return undefined
      i++
      // Wrapper options, their values and bare numbers: `sudo -u me`, `timeout -s KILL 5`.
      while (i < all.length) {
        const option = all[i]!
        if (option === '--') {
          i++
          break
        }
        if (option.startsWith('-')) {
          i += valueOptions.has(option) ? 2 : 1
          continue
        }
        if (/^\d+(\.\d+)?[smhd]?$/.test(option)) {
          i++
          continue
        }
        break
      }
      continue
    }
    if (CLUSTER_CLIS.has(program)) return { kind: 'cluster', cli: program, args: all.slice(i + 1).map(bareWord) }
    if (SHELLS.has(program)) {
      const flag = all.indexOf('-c', i + 1)
      if (flag < 0) return undefined
      const rest = all.slice(flag + 1).join(' ')
      const quoted = /^(['"])([\s\S]*)\1$/.exec(rest)
      return { kind: 'nested', command: quoted ? quoted[2]! : rest }
    }
    return undefined
  }
  return undefined
}

/** Translates one glob path component into an anchored, case-insensitive regex. */
function globComponent(component: string): RegExp {
  let source = ''
  for (let i = 0; i < component.length; i++) {
    const c = component[i]!
    if (c === '*') source += '[^/]*'
    else if (c === '?') source += '[^/]'
    else if (c === '[') {
      const end = component.indexOf(']', i + 1)
      if (end < 0) {
        source += '\\['
        continue
      }
      source += `[${component.slice(i + 1, end).replace(/^!/, '^').replace(/\\/g, '\\\\')}]`
      i = end
    } else if (c === '{') {
      const end = component.indexOf('}', i + 1)
      if (end < 0) {
        source += '\\{'
        continue
      }
      source += `(?:${component
        .slice(i + 1, end)
        .split(',')
        .map((alt) => alt.replace(/[.+^$()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]'))
        .join('|')})`
      i = end
    } else source += c.replace(/[.+^$()|\\\]}]/g, '\\$&')
  }
  return new RegExp(`^${source}$`, 'i')
}

/**
 * True when a path component is, or as a glob could be, `.kube`. Like a
 * shell, a leading `*`, `?` or `[` does not match the leading dot.
 */
function couldBeKubeDir(component: string): boolean {
  if (component.toLowerCase() === '.kube') return true
  if (!/[*?[{]/.test(component) || /^[*?[]/.test(component)) return false
  return globComponent(component).test('.kube')
}

/**
 * True when the text names `~/.kube` or something inside it, other than the
 * plugin's own file. Quotes are ignored; `=` and `:` separate paths too
 * (`--kubeconfig=…`, `KUBECONFIG=a:b`). Commas do not: they belong to
 * brace alternatives (`{.kube,x}`).
 */
export function namesKubeDir(text: string): boolean {
  for (const word of words(text.replace(/['"]/g, ''))) {
    for (const path of word.split(/[=:]/)) {
      const components = path.split('/')
      for (let i = 0; i < components.length; i++) {
        if (!couldBeKubeDir(components[i]!)) continue
        const isOwnFile =
          components[i]!.toLowerCase() === '.kube' && OWN_FILE.test(components[i + 1] ?? '') && i + 2 === components.length
        if (!isOwnFile) return true
      }
    }
  }
  return false
}

/** Checks text that matters in any segment, whatever program it runs. */
function checkAnySegment(segment: string): string | undefined {
  if (/\b(KUBECONFIG|HELM_KUBE\w*)\s*=/.test(segment)) return 'it sets KUBECONFIG or a HELM_KUBE* variable'
  if (/\b(unset|export|typeset|declare)\b[^;|&]*\b(KUBECONFIG|HELM_KUBE\w*)\b/.test(segment)) return 'it changes KUBECONFIG or a HELM_KUBE* variable'
  if (/(^|\s)env\b[^;|&]*(\s-i\b|\s--ignore-environment\b|\s-u\s*KUBECONFIG\b|\s--unset[= ]KUBECONFIG\b)/.test(segment)) {
    return 'it runs a command without the read-only KUBECONFIG'
  }
  if (namesKubeDir(segment)) return 'it touches ~/.kube, where your full credentials live'
  return undefined
}

/** Checks one oc/kubectl/helm invocation. */
function checkClusterInvocation(cli: string, args: readonly string[]): string | undefined {
  for (const arg of args) {
    const flag = arg.split('=')[0]!
    if (CREDENTIAL_FLAGS.has(flag)) return `${cli} ${flag} would bypass the read-only token`
    // pflag also takes the value attached: `-shttps://other:6443`.
    if (cli !== 'helm' && arg.startsWith('-s') && !arg.startsWith('--')) return `${cli} -s would point the token at another server`
  }
  const flags = new Set(args.filter((a) => a.startsWith('-')).map((a) => a.split('=')[0]!))
  const [sub, next] = positionals(args)
  if (cli === 'helm') return undefined
  if (sub === 'login' || sub === 'logout') return `${cli} ${sub} would replace the read-only login`
  if (sub === 'whoami' && (flags.has('-t') || flags.has('--show-token'))) {
    return `${cli} whoami --show-token would print the token into the conversation`
  }
  if (sub === 'project' && next !== undefined) {
    return `${cli} project <name> switches the namespace for good; pass -n <namespace> instead`
  }
  if (sub === 'config') {
    if (next === undefined || !CONFIG_READ_SUBCOMMANDS.has(next)) return `${cli} config ${next ?? ''} would change the kubeconfig`.trimEnd()
    if (flags.has('--raw')) return `${cli} config view --raw would print the token into the conversation`
  }
  return undefined
}

/**
 * Splits on `&&`, `||`, `;`, `|`, newlines and a lone `&` (background), but
 * not on the `&` of redirections (`>&2`, `&>file`, `2>&1`).
 */
function splitSegments(command: string): string[] {
  return command.split(/&&|\|\||[;|\n]|(?<![<>&])&(?![&>])/)
}

/** The insides of `$(…)` and backtick command substitutions (one level deep). */
function substitutions(segment: string): string[] {
  const found: string[] = []
  for (const m of segment.matchAll(/\$\(([^()]*)\)|`([^`]*)`/g)) found.push((m[1] ?? m[2])!)
  return found
}

/**
 * Returns why one command segment must not run, or undefined when it may.
 * opencode splits a command on `&&`, `||`, `;` and `|` before evaluating
 * permissions, so a segment is normally one simple command.
 */
export function checkSegment(segment: string, depth = 0): string | undefined {
  const any = checkAnySegment(segment)
  if (any) return any
  if (depth < 3) {
    for (const inner of substitutions(segment)) {
      const reason = checkCommand(inner, depth + 1)
      if (reason) return reason
    }
  }
  const found = invocation(segment)
  if (!found) return undefined
  if (found.kind === 'nested') return depth < 3 ? checkCommand(found.command, depth + 1) : undefined
  return checkClusterInvocation(found.cli, found.args)
}

/** Checks a whole command line the way opencode would see its segments. */
export function checkCommand(command: string, depth = 0): string | undefined {
  for (const segment of splitSegments(command)) {
    const reason = checkSegment(segment, depth)
    if (reason) return reason
  }
  return undefined
}

function segmentNeedsCluster(segment: string, depth: number): boolean {
  if (depth < 3 && substitutions(segment).some((inner) => needsCluster(inner, depth + 1))) return true
  const found = invocation(segment)
  if (!found) return false
  if (found.kind === 'nested') return depth < 3 && needsCluster(found.command, depth + 1)
  const { cli, args } = found
  if (args.some((a) => a === '--help' || a === '-h' || a === '--client' || a.startsWith('--client='))) return false
  const [sub] = positionals(args)
  return sub !== undefined && !LOCAL_ONLY_SUBCOMMANDS[cli]!.has(sub)
}

/**
 * True when the command will talk to a cluster through oc, kubectl or helm,
 * which is when the plugin makes sure a read-only token is in place.
 * `which oc`, `helm template` or `brew upgrade helm` do not count.
 */
export function needsCluster(command: string, depth = 0): boolean {
  return splitSegments(command).some((segment) => segmentNeedsCluster(segment, depth))
}

/**
 * For file tools (read, edit, write, …): a path under `~/.kube` other than
 * the plugin's own file. opencode hands these resources over relative to the
 * project when they sit inside it (`home/.kube/config`), so the match does not
 * depend on the home directory prefix.
 */
export function checkPath(resource: string): string | undefined {
  return namesKubeDir(resource) ? 'it touches ~/.kube, where your full credentials live' : undefined
}

/** Collapses `.` and `..` components of an absolute path. */
function resolvePath(path: string): string {
  const out: string[] = []
  for (const part of path.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') out.pop()
    else out.push(part)
  }
  return `/${out.join('/')}`
}

/** Tools that walk a directory tree from their `path`. */
const RECURSIVE_TOOLS = new Set(['grep', 'glob', 'list'])

/**
 * Checks a file tool's own input, where the real path is (the permission
 * request for grep and glob only carries the search pattern). A recursive
 * search from `~` or one of its ancestors would walk into `~/.kube`.
 * Relative paths, and a missing path (the tool then searches the project),
 * are resolved against `cwd`, the project directory.
 */
export function checkToolInput(tool: string, input: unknown, home: string, cwd?: string): string | undefined {
  if (typeof input !== 'object' || input === null) return undefined
  const record = input as Record<string, unknown>
  const kubeDir = `${home.replace(/\/+$/, '')}/.kube`
  const walksIntoKube = (root: string) => {
    const normalized = resolvePath(root).replace(/\/+$/, '') || '/'
    const prefix = normalized === '/' ? '/' : `${normalized}/`
    return kubeDir.toLowerCase().startsWith(prefix.toLowerCase())
  }
  const recursive = RECURSIVE_TOOLS.has(tool)
  let sawPath = false
  for (const key of ['path', 'filePath', 'file_path', 'directory']) {
    const value = record[key]
    if (typeof value !== 'string' || value === '') continue
    sawPath = true
    const expanded = value.replace(/^~(?=\/|$)/, home)
    if (namesKubeDir(expanded)) return 'it touches ~/.kube, where your full credentials live'
    const absolute = expanded.startsWith('/') ? expanded : cwd ? `${cwd}/${expanded}` : undefined
    if (recursive && absolute && walksIntoKube(absolute)) {
      return `a recursive ${tool} from ${value} would walk into ~/.kube, where your full credentials live`
    }
  }
  if (recursive && !sawPath && cwd && walksIntoKube(cwd)) {
    return `a recursive ${tool} from the project directory ${cwd} would walk into ~/.kube, where your full credentials live`
  }
  return undefined
}

/** The message the agent sees when something is denied. */
export function denyMessage(reason: string): string {
  return (
    `opencode-plugin-openshift-readonly-agent blocked this: ${reason}. ` +
    'Cluster access from this agent is read-only by design. ' +
    'Ask the user to run commands that need more than read access.'
  )
}
