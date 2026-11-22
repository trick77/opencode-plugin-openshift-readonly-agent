# opencode-plugin-openshift-readonly-agent

An [opencode](https://opencode.ai) 2 plugin that makes every `oc`, `kubectl` and `helm` command run by the agent use a **read-only OpenShift OAuth token**, never your own login.

You keep your full rights in your own terminal. The agent can look at everything you can look at, and change nothing.

## How it works

- **Every agent shell gets its own kubeconfig.** The plugin sets `KUBECONFIG` to `~/.kube/opencode-readonly-agent.json`, a file it owns (mode `0600`). That happens for every shell, before anything else, so the agent never falls back to your kubeconfig.
- **The token is scoped by OpenShift itself.** It is minted through OpenShift's OAuth challenge flow with the scopes `user:info user:check-access role:view:*`. The API server answers anything beyond `view` with `Forbidden … scopes [...] prevent this action`: no create, patch, delete, exec, rsh or port-forward, and no Secrets. This holds no matter how the agent phrases a command.
- **It follows your current context.** The API server and namespace come from your own current context, so `oc project foo` in your terminal also moves the agent to `foo`, still read-only. Tokens for several clusters are kept side by side.
- **It asks for your password once.** The first time the agent needs a cluster, a native desktop dialog asks for your OpenShift password. The plugin keeps the password in memory only and uses it to renew the token silently when it expires, until opencode restarts. It is never written to disk and never appears on a command line.
- **It blocks the obvious ways around it.** Commands that would swap the credentials are denied with a message to the agent: `--kubeconfig`, `KUBECONFIG=…`, `unset KUBECONFIG`, `env -i`, any path under `~/.kube/` other than the plugin's file, `--token`, `--as`, `--server`, `oc login`/`logout`, `oc config use-context`/`set-*`, `oc project <name>`, `oc whoami --show-token` and `oc config view --raw`. opencode's file tools (read, edit, glob, grep, …) are refused any path under `~/.kube/` as well.
- **Subagents are covered too.** Their shells go through the same hook. opencode's `execute` (Code Mode) tool has no shell and no file access of its own.

### Password dialog

| Platform | Dialog |
|---|---|
| Linux (RHEL Workstation / GNOME) | `zenity`, then `kdialog`, then `pinentry` (ships with gnupg2) |
| macOS | `osascript` |

On Linux the dialog needs the desktop session's `DISPLAY` or `WAYLAND_DISPLAY`. Start opencode from a terminal inside your desktop session, not over SSH.

If you cancel the dialog, the agent's command fails with a message saying so, and the plugin does not ask again for a minute.

## Requirements

- opencode 2
- OpenShift 4 with the integrated OAuth server, and an identity provider that accepts a username and password (LDAP, htpasswd, Keystone and similar). A pure browser SSO setup cannot mint tokens this way.
- `oc` (or `kubectl`) and `curl` on `PATH`
- You are logged in with `oc login` in your own terminal, so a current context exists.

Check that your cluster hands out scoped tokens before you install. Run this in your own terminal (bash or zsh); curl asks for your password:

```sh
S=$(oc whoami --show-server); I=$(curl -s "$S/.well-known/oauth-authorization-server" | sed -nE 's/.*"issuer": *"([^"]+)".*/\1/p'); T=$(curl -s -u "$(oc whoami)" -H "X-CSRF-Token: 1" -D - -o /dev/null "$I/oauth/authorize?client_id=openshift-challenging-client&response_type=token&scope=user%3Ainfo%20user%3Acheck-access%20role%3Aview%3A%2A" | tr -d '\r' | sed -nE 's/^[Ll]ocation:.*access_token=([^&]+).*/\1/p'); oc auth can-i get pods --token="$T"; oc auth can-i create configmaps --token="$T"; oc auth can-i get secrets --token="$T"
```

Expected: `yes`, then twice `no - scopes [...] prevent this action`.

## Install

Not on npm yet. Until the first release, load a checkout as a local plugin:

```json
{
  "plugins": ["/path/to/opencode-plugin-openshift-readonly-agent"]
}
```

Once released, with [opencode-presets](https://github.com/trick77/opencode-presets):

```sh
opencode-presets install openshift-readonly-agent
```

Or add it to `opencode.json` by hand:

```json
{
  "plugins": ["opencode-plugin-openshift-readonly-agent@0.1.0"]
}
```

## Limitations

This plugin protects the default path and catches agent mistakes. It is not a sandbox, and it does not make a determined agent harmless.

- **opencode has no OS sandbox.** The agent runs as your user. Your full credentials stay readable on disk, in `~/.kube/config` and wherever else you keep them. A command the plugin does not recognise can still reach them, for example a Python one-liner that reads `~/.kube/config`, an obfuscated command (`base64 -d | sh`), or a script written to disk first and run later. The deny list only reads command text.
- **If the plugin does not load, there is no protection, and nothing tells you.** opencode only logs a warning when a plugin fails to load. The agent then uses your normal kubeconfig with your full rights. Re-check after every opencode upgrade: ask the agent to run `oc auth can-i create configmaps` and expect `no - scopes [...] prevent this action`.
- **Read-only still means read.** The agent sees everything the `view` role shows you, including pod logs, ConfigMaps and environment variables in `describe` output, and all of it goes to your model provider. Secrets are excluded by the scope, but credentials that sit in ConfigMaps or logs are not.
- **The read-only token is visible to the agent.** It sits in the plugin's kubeconfig, and the agent can read the file. That only exposes read access, for the lifetime of the token (often 24 hours).
- **The password is in opencode's memory** for as long as opencode runs, so that tokens can renew without another dialog. Another process running as your user could read it from memory.
- **A desktop dialog that asks for your password is a phishing pattern.** Any program can draw one. The plugin's dialog is titled `OpenShift read-only agent` and only appears right after the agent starts an `oc`, `kubectl` or `helm` command. Be suspicious of one at any other time.
- **Other ways to a cluster are not covered.** The plugin handles kubeconfig-based CLIs. Tools that bring their own credentials (an MCP server, `argocd`, `tkn` with its own config, a browser session) are outside its reach.
- **The token is yours, scoped down.** The audit log shows your user. The intersection with your own rights still applies: in projects where you cannot read, neither can the agent.
- **Only OpenShift.** Scoped OAuth tokens are an OpenShift feature. Plain Kubernetes clusters have no equivalent, and the plugin cannot mint a token for them; on such a cluster the agent gets no credentials at all.

## License

MIT
