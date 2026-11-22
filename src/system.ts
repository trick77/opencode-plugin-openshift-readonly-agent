// Everything that touches processes, files or the screen. plugin.ts takes
// these through the `System` interface so tests can replace them.

import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import { type PromptResult, promptSecret } from './prompt.ts'

export interface RunResult {
  readonly code: number
  readonly stdout: string
  readonly stderr: string
}

export interface RunOptions {
  readonly env: Record<string, string | undefined>
  readonly input?: string
  readonly timeoutMs?: number
}

export type { PromptResult }

export interface System {
  run(command: string, args: readonly string[], options: RunOptions): Promise<RunResult>
  readText(path: string): Promise<string | undefined>
  /** Writes a file readable by the owner only. */
  writePrivate(path: string, content: string): Promise<void>
  /** Desktop dialog with hidden input; `env` carries the session's DISPLAY and friends. */
  promptSecret(title: string, message: string, env: Record<string, string | undefined>): Promise<PromptResult>
  now(): number
}

function run(command: string, args: readonly string[], options: RunOptions): Promise<RunResult> {
  return new Promise((resolve) => {
    const env: Record<string, string> = {}
    for (const [k, v] of Object.entries(options.env)) if (v !== undefined) env[k] = v
    let child
    try {
      child = spawn(command, [...args], { env, stdio: ['pipe', 'pipe', 'pipe'] })
    } catch (err) {
      resolve({ code: 127, stdout: '', stderr: String(err) })
      return
    }
    let stdout = ''
    let stderr = ''
    let done = false
    const finish = (result: RunResult) => {
      if (done) return
      done = true
      clearTimeout(timer)
      resolve(result)
    }
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      finish({ code: 124, stdout, stderr: `${stderr}\n${command} timed out` })
    }, options.timeoutMs ?? 30_000)
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()))
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()))
    child.on('error', (err) => finish({ code: 127, stdout, stderr: String(err) }))
    child.on('close', (code) => finish({ code: code ?? 1, stdout, stderr }))
    child.stdin.on('error', () => {})
    child.stdin.end(options.input ?? '')
  })
}

async function readText(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, 'utf8')
  } catch {
    return undefined
  }
}

async function writePrivate(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  // Write next to the target and rename, so a concurrent `oc` never reads a
  // half-written file.
  // `wx` refuses to follow anything already sitting at the temp name.
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  await writeFile(tmp, content, { mode: 0o600, flag: 'wx' })
  await chmod(tmp, 0o600)
  await rename(tmp, path)
}

export const nodeSystem: System = {
  run,
  readText,
  writePrivate,
  promptSecret: (title, message, env) => promptSecret(run, { title, message, env, platform: process.platform }),
  now: () => Date.now(),
}
