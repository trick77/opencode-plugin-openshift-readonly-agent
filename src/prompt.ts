// Asking the user for their password in a native desktop dialog.
//
// The opencode service has no terminal, so the dialog must come from the
// desktop session. The answer always arrives on a child's stdout, never on a
// command line where a process listing would show it.
//
// - macOS: osascript `display dialog … with hidden answer`.
// - Linux (RHEL Workstation/GNOME first): zenity, then kdialog, then
//   pinentry. pinentry ships with gnupg2, so it is there on practically every
//   RHEL desktop even without zenity; it speaks the Assuan protocol on stdin.
//
// The dialog's environment is the agent shell's environment: on Linux it
// carries DISPLAY / WAYLAND_DISPLAY / DBUS_SESSION_BUS_ADDRESS from the session
// opencode was started in.

export interface PromptRunResult {
  readonly code: number
  readonly stdout: string
  readonly stderr: string
}

export type PromptRun = (
  command: string,
  args: readonly string[],
  options: { readonly env: Record<string, string | undefined>; readonly input?: string; readonly timeoutMs?: number },
) => Promise<PromptRunResult>

export type PromptResult =
  | { readonly kind: 'answer'; readonly value: string }
  | { readonly kind: 'cancelled' }
  | { readonly kind: 'unavailable'; readonly reason: string }

export interface PromptRequest {
  readonly title: string
  readonly message: string
  readonly env: Record<string, string | undefined>
  readonly platform: NodeJS.Platform
}

/** The user may take their time; a forgotten dialog must not hang the shell forever. */
const DIALOG_TIMEOUT_MS = 5 * 60_000

const notFound = (r: PromptRunResult) => r.code === 127 || /ENOENT/.test(r.stderr)

function appleScriptString(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

function stripNewline(value: string): string {
  return value.replace(/\r?\n$/, '')
}

async function osascript(run: PromptRun, req: PromptRequest): Promise<PromptResult> {
  const script = `text returned of (display dialog ${appleScriptString(req.message)} with title ${appleScriptString(req.title)} default answer "" with hidden answer with icon caution)`
  const result = await run('osascript', ['-'], { env: req.env, input: script, timeoutMs: DIALOG_TIMEOUT_MS })
  if (result.code === 0) return { kind: 'answer', value: stripNewline(result.stdout) }
  if (/-128/.test(result.stderr)) return { kind: 'cancelled' }
  return { kind: 'unavailable', reason: `osascript failed: ${result.stderr.trim() || `exit ${result.code}`}` }
}

/** zenity: exit 0 answer, 1 cancel/close, 5 timeout, anything else an error. */
async function zenity(run: PromptRun, req: PromptRequest): Promise<PromptResult | undefined> {
  const result = await run('zenity', ['--entry', '--hide-text', `--title=${req.title}`, `--text=${req.message}`], {
    env: req.env,
    timeoutMs: DIALOG_TIMEOUT_MS,
  })
  if (notFound(result)) return undefined
  if (result.code === 0) return { kind: 'answer', value: stripNewline(result.stdout) }
  if (result.code === 1 || result.code === 5) return { kind: 'cancelled' }
  return { kind: 'unavailable', reason: `zenity failed: ${result.stderr.trim() || `exit ${result.code}`}` }
}

/** kdialog: exit 0 answer, 1 cancel. */
async function kdialog(run: PromptRun, req: PromptRequest): Promise<PromptResult | undefined> {
  const result = await run('kdialog', ['--title', req.title, '--password', req.message], { env: req.env, timeoutMs: DIALOG_TIMEOUT_MS })
  if (notFound(result)) return undefined
  if (result.code === 0) return { kind: 'answer', value: stripNewline(result.stdout) }
  if (result.code === 1) return { kind: 'cancelled' }
  return { kind: 'unavailable', reason: `kdialog failed: ${result.stderr.trim() || `exit ${result.code}`}` }
}

/** Assuan percent-escaping for SETDESC and friends. */
export function assuanEscape(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')
}

/** Assuan percent-decoding of a `D` line. */
export function assuanUnescape(value: string): string {
  return value.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
}

/** The whole pinentry conversation, written up front: pinentry reads it line by line. */
export function pinentryScript(req: Pick<PromptRequest, 'title' | 'message'>): string {
  return [
    `SETTITLE ${assuanEscape(req.title)}`,
    `SETDESC ${assuanEscape(req.message)}`,
    'SETPROMPT Password:',
    'GETPIN',
    'BYE',
    '',
  ].join('\n')
}

/** Reads the PIN, a cancel, or an error out of pinentry's Assuan replies. */
export function parsePinentry(stdout: string): PromptResult {
  const lines = stdout.split(/\r?\n/)
  const data = lines.filter((l) => l.startsWith('D ')).map((l) => assuanUnescape(l.slice(2)))
  if (data.length > 0) return { kind: 'answer', value: data.join('') }
  const err = lines.find((l) => l.startsWith('ERR '))
  // 83886179 = GPG_ERR_CANCELED from the pinentry source; some builds only
  // say "Operation cancelled".
  if (err && (/\b83886179\b/.test(err) || /cancel/i.test(err))) return { kind: 'cancelled' }
  // A GETPIN that returns OK without D means an empty entry.
  const okCount = lines.filter((l) => l.startsWith('OK')).length
  if (!err && okCount >= 5) return { kind: 'answer', value: '' }
  return { kind: 'unavailable', reason: `pinentry failed: ${err ?? 'no answer'}` }
}

async function pinentry(run: PromptRun, req: PromptRequest): Promise<PromptResult | undefined> {
  const result = await run('pinentry', [], { env: req.env, input: pinentryScript(req), timeoutMs: DIALOG_TIMEOUT_MS })
  if (notFound(result)) return undefined
  return parsePinentry(result.stdout)
}

export async function promptSecret(run: PromptRun, req: PromptRequest): Promise<PromptResult> {
  if (req.platform === 'darwin') return osascript(run, req)
  if (req.platform !== 'linux') return { kind: 'unavailable', reason: `no password dialog on ${req.platform}` }
  if (!req.env.DISPLAY && !req.env.WAYLAND_DISPLAY) {
    return { kind: 'unavailable', reason: 'no desktop session (neither DISPLAY nor WAYLAND_DISPLAY is set for opencode)' }
  }
  for (const dialog of [zenity, kdialog, pinentry]) {
    const result = await dialog(run, req)
    if (result) return result
  }
  return { kind: 'unavailable', reason: 'none of zenity, kdialog or pinentry is installed' }
}
