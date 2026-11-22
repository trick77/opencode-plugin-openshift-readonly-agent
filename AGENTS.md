# AGENTS.md

## Build / test

- Relative imports carry `.ts`. Extensionless breaks `node --test`.
- ZERO runtime deps. `@opencode/plugin` = devDependency, `import type` only in `src/`. No `Plugin.define` (identity fn, would make it a runtime dep). Not `@opencode-ai/plugin`: that is the 1.x SDK, a 1.x-shaped plugin fails to load in opencode 2 with only a WARN in the log.
- opencode runs the plugin on Bun; tests run on Node. Hook behaviour only shows in a real opencode → probe: isolated `HOME`, `opencode run --standalone --auto -m fake/fake` against a fake OpenAI-compatible server that answers with a `shell` tool call, fake `oc`/`curl`/dialog first on `PATH`. Never against the real `~/.config/opencode`.

## opencode 2.3.2 host facts (measured)

- Agent tool is `shell`, not `bash`. Permission action is `shell` too.
- Order per call: `tool.execute.before` → `shell.create.before` → `permission.evaluate`. The env/dialog work happens BEFORE the deny → `onShellCreate` skips commands `checkCommand` would deny, else a denied command still pops the password dialog.
- `permission.evaluate` gets `resources` already split on `&&`/`||`/`;`/`|`. Deny on one segment blocks the whole command, nothing runs.
- `shell.create.before`: mutating `env` and `command` both reach the shell. Fail closed = replace `command` with `printf … >&2; exit 1` so the agent reads the reason.
- `opencode api shell.create` (user shells via API) does NOT fire `shell.create.before`.
- Subagent shells fire the same hooks (probed). `execute` (Code Mode) = JS with `fetch` + opencode session/worktree tools only, no shell, no fs.
- File tools hit `permission.evaluate` with action `read`/`edit`/…; `resources` is project-relative when inside the project (`home/.kube/config`), so `checkPath` matches `.kube/` without a home prefix.
- `setup` may run per location → agent state is module-scoped (one dialog per process, not per project).

## OpenShift OAuth (verified on a real cluster, 2026-11)

- Challenge flow with `scope=user%3Ainfo%20user%3Acheck-access%20role%3Aview%3A%2A` → token; writes and Secrets → `Forbidden … scopes [...] prevent this action`.
- Bearer token instead of Basic auth at `/oauth/authorize` → 401. No password-free minting from an existing login; that is why the dialog exists.
- `user:info` keeps `oc whoami` / `get --raw /apis/user.openshift.io/v1/users/~` working (token check); `user:check-access` keeps `oc auth can-i` working.
- Scope query built by hand with `%20`: the verified form. URLSearchParams writes `+`.

## Design decisions

- Password only via stdin (curl `--config -`, dialog stdout), never argv. Kept in memory for silent renewal; never disk, never Keychain.
- Dialog over the alternatives: terminal login (not automatic), Keychain (stored password), ServiceAccount via `oc create token` (RoleBinding per project, audit shows the SA). Primary target RHEL Workstation (GNOME): zenity → kdialog → pinentry; osascript on macOS. zenity verified in CentOS Stream 9 under Xvfb (answer with `"`, `%`, `$` intact); cancel/kdialog/pinentry only unit-tested.
- Kubeconfig written as JSON: no YAML parser, zero deps.
- Cluster + namespace follow the user's current context on every cluster command: `oc project x` in the own terminal moves the agent too.

## Release

- Tag-driven: bump `version`, push `vX.Y.Z` on master after merge; CI publishes via OIDC. Never `npm publish` by hand.
- Released → update `../opencode-presets/presets/plugin-openshift-readonly-agent.conf`: `@pins`, body spec, its `@version`.
