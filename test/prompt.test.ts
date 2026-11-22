import { test } from 'node:test'
import assert from 'node:assert/strict'
import { type PromptRun, type PromptRunResult, assuanEscape, parsePinentry, pinentryScript, promptSecret } from '../src/prompt.ts'

const GNOME = { DISPLAY: ':0', WAYLAND_DISPLAY: 'wayland-0', DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/1000/bus' }
const missing: PromptRunResult = { code: 127, stdout: '', stderr: 'spawn ENOENT' }

/** Records calls; answers per program from the table, ENOENT otherwise. */
function fakeRun(table: Record<string, PromptRunResult>) {
  const calls: { command: string; args: readonly string[]; input?: string; env: Record<string, string | undefined> }[] = []
  const run: PromptRun = async (command, args, options) => {
    calls.push({ command, args, env: options.env, ...(options.input !== undefined ? { input: options.input } : {}) })
    return table[command] ?? missing
  }
  return { run, calls }
}

const req = (platform: NodeJS.Platform, env: Record<string, string | undefined> = GNOME) => ({
  title: 'OpenShift read-only agent',
  message: 'Password for alice:',
  env,
  platform,
})

test('RHEL/GNOME: zenity first, hidden entry, session env passed through', async () => {
  const { run, calls } = fakeRun({ zenity: { code: 0, stdout: 's3cret\n', stderr: '' } })
  assert.deepEqual(await promptSecret(run, req('linux')), { kind: 'answer', value: 's3cret' })
  assert.equal(calls.length, 1)
  assert.ok(calls[0]!.args.includes('--hide-text'))
  assert.equal(calls[0]!.env.WAYLAND_DISPLAY, 'wayland-0')
  assert.ok(!calls[0]!.args.some((a) => a.includes('s3cret')))
})

test('zenity cancel', async () => {
  const { run } = fakeRun({ zenity: { code: 1, stdout: '', stderr: '' } })
  assert.deepEqual(await promptSecret(run, req('linux')), { kind: 'cancelled' })
})

test('no zenity: kdialog', async () => {
  const { run, calls } = fakeRun({ kdialog: { code: 0, stdout: 'pw\n', stderr: '' } })
  assert.deepEqual(await promptSecret(run, req('linux')), { kind: 'answer', value: 'pw' })
  assert.deepEqual(calls.map((c) => c.command), ['zenity', 'kdialog'])
})

test('neither: pinentry over Assuan on stdin', async () => {
  const { run, calls } = fakeRun({
    pinentry: { code: 0, stdout: 'OK Pleased to meet you\nOK\nOK\nOK\nD p%25w%0Ax\nOK\nOK closing connection\n', stderr: '' },
  })
  assert.deepEqual(await promptSecret(run, req('linux')), { kind: 'answer', value: 'p%w\nx' })
  assert.deepEqual(calls.map((c) => c.command), ['zenity', 'kdialog', 'pinentry'])
  assert.match(calls[2]!.input!, /^GETPIN$/m)
})

test('pinentry cancel and errors', () => {
  assert.deepEqual(parsePinentry('OK Pleased\nOK\nOK\nOK\nERR 83886179 Operation cancelled <Pinentry>\n'), { kind: 'cancelled' })
  assert.equal(parsePinentry('OK Pleased\nERR 83918950 Inappropriate ioctl for device\n').kind, 'unavailable')
})

test('pinentry script escapes the description', () => {
  assert.equal(assuanEscape('a%b\nc'), 'a%25b%0Ac')
  assert.match(pinentryScript({ title: 't', message: 'line1\nline2' }), /^SETDESC line1%0Aline2$/m)
})

test('Linux without a desktop session does not try any dialog', async () => {
  const { run, calls } = fakeRun({})
  const result = await promptSecret(run, req('linux', {}))
  assert.equal(result.kind, 'unavailable')
  assert.equal(calls.length, 0)
})

test('Linux with no dialog program installed', async () => {
  const { run } = fakeRun({})
  const result = await promptSecret(run, req('linux'))
  assert.equal(result.kind, 'unavailable')
})

test('macOS: osascript with hidden answer, cancel is -128', async () => {
  const ok = fakeRun({ osascript: { code: 0, stdout: 'pw\n', stderr: '' } })
  assert.deepEqual(await promptSecret(ok.run, req('darwin', {})), { kind: 'answer', value: 'pw' })
  assert.match(ok.calls[0]!.input!, /with hidden answer/)
  const cancel = fakeRun({ osascript: { code: 1, stdout: '', stderr: 'execution error: User canceled. (-128)' } })
  assert.deepEqual(await promptSecret(cancel.run, req('darwin', {})), { kind: 'cancelled' })
})

test('other platforms: no dialog', async () => {
  const { run } = fakeRun({})
  assert.equal((await promptSecret(run, req('win32'))).kind, 'unavailable')
})
