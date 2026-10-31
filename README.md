# LLLanyard

By **Ethan Askew T/A LLLanyard**. Source-available under the Business Source License 1.1 (see [License](#license)).

Keep API keys out of AI agents. Your keys live in the **OS keychain**; tools like Claude Code, Cursor
or AutoGPT only ever hold a worthless placeholder token and talk to a local proxy that injects the real key.

```
agent (token lly_…)  ──►  127.0.0.1:3000  ──►  api.openai.com / api.anthropic.com
                          │  verifies token, rate-limits, adds the real key from the OS keychain
                          └─ macOS Keychain · Windows Credential Manager (DPAPI) · Linux Secret Service
```

## Quick start

```bash
npm install -g @lllanyard/cli     # needs Node 22 or later; from source: npm install && npm run build && npm link -w packages/cli

lllanyard doctor                  # confirms the OS keychain works
lllanyard ui                      # or use the visual app for everything below
lllanyard add anthropic           # hidden prompt – the key never touches argv/history
lllanyard add openai
lllanyard setup claude-desktop --scripts-dir ~/Scripts   # Claude Desktop on a subscription: see below
lllanyard agent create claude-code   # API-key mode: prints a placeholder token ONCE + the env vars to set
lllanyard start                   # proxy on 127.0.0.1:3000
```

Then, in the shell that launches your tool, set the values `agent create` printed, e.g.:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:3000/anthropic
export ANTHROPIC_API_KEY=lly_...        # placeholder, useless outside the proxy
export OPENAI_BASE_URL=http://127.0.0.1:3000/openai/v1
export OPENAI_API_KEY=lly_...
```

Compatibility notes:
- Claude Code reads its base URL and key from these environment variables; if `ANTHROPIC_AUTH_TOKEN` is also set it may take precedence, so unset it. Only API-key mode is proxied, not subscription logins. The Claude Desktop app ignores these variables; for Desktop (and subscription use generally) see [Claude Desktop](#3-claude-desktop-and-subscription-chat-apps) below.
- Cursor makes some model calls from its own servers, so a localhost base URL may not work there.

## Commands

| Command | What it does |
|---|---|
| `add <provider> [--label N] [--rotate-days N] [--env-name VAR]` | Store a key (hidden prompt or `--stdin`). `--label` doubles as a *client* name for agency/freelancer use. |
| `env <provider>[:label] VAR` | The environment variable a key is given to scripts as, e.g. `lllanyard env github GITHUB_TOKEN`. |
| `exec <command> [args…]` | Run a script with the keys it uses: `lllanyard exec pwsh -File ./Deploy-App.ps1 -DryRun`. LLLanyard reads the script, and the helper files it loads (quoted paths, `source`/`.` lines, Python imports), for your keys' variable names and passes only those, for that run only. Keys in the output are redacted; each run is logged and shown by `usage`. `exec --keys github,sendgrid -- <command>` names the keys yourself (needed for programs that aren't scripts). Run from a terminal, the script gets a real terminal of its own (prompts like `Read-Host`, colours and window size work) on macOS, Linux and Windows, and its output is still redacted. |
| `list`, `remove`, `rotate`, `status` | Manage keys; `status` shows rotation due dates and exits 1 if anything is overdue (cron/CI friendly). |
| `agent create <name> [--client N] [--providers a,b]` / `list` / `revoke` | Placeholder tokens. `--client acme` pins an agent to the `acme` key; `--providers` limits which APIs it may reach (least privilege). |
| `provider add <id> --upstream https://… [--auth bearer\|header --header NAME --prefix TXT]` / `list` / `remove` | Teach the proxy a new API host (GitHub, Slack, your own service). Built-ins: openai, anthropic, gemini, openrouter, github, slack, stripe, notion. |
| `tool add <name> --env VAR=provider[:label] [--allow-host H] [--kill-on-leak] [--pass-env V] [--inherit-env] [--no-scrub] -- <command> [args…]` / `list` / `remove` | Approve a command (e.g. an MCP server) to receive keys as environment variables, with the safeguards below. |
| `run <name> [-- args…]` | Run an approved tool with its keys injected and scrubbed from its output. Extra args are appended only if the tool was approved with `--allow-args`. For script tools (python, node, sh, pwsh…) the script file is pinned by hash at approval and `run` refuses if it has changed since; `--allow-args` is refused for bare interpreters (`python3 -c`, `-m`) and launchers (`env`, `xargs`, `sudo`, `npx`). `run --env … -- <cmd>` is a one-off that needs a human to confirm at a terminal. |
| `scan [paths] [--import --apply [--redact]]` | Find plaintext keys in `.env` files, MCP/IDE configs and shell profiles, then move them into the keychain. Dry run unless `--apply`. |
| `backup [--out FILE] [--passphrase-file F]` | Write one encrypted file (AES-256-GCM, scrypt passphrase) holding your keys and their metadata, custom providers, approved tools, agents and license. Agents are saved as token hashes, so existing agent tokens keep working after a restore. |
| `restore <file> [--overwrite] [--dry-run] [--passphrase-file F]` | Merge a backup into this machine's keychain or vault. Every item is validated and the key limit checked before anything is written; existing items are kept unless `--overwrite`, and nothing is ever deleted. |
| `start [--port N]` | Run the proxy (loopback only). Logs JSON lines to stdout. |

## Using it with tools (APIs and MCP servers)

Three routes, depending on how the tool talks:

**1. HTTP APIs go through the proxy** (the tool only holds the placeholder token):

```bash
lllanyard add github                              # hidden prompt
lllanyard agent create reviewer --providers github,anthropic
# point the tool's API base URL at http://127.0.0.1:3000/github and use the lly_ token as its key
lllanyard provider add acme --upstream https://api.acme.dev --auth header --header X-Api-Key   # your own API
```

**2. MCP servers and CLI tools read keys from environment variables**, so the proxy can't help. Approve the command once, then
reference it by name so no secret ever appears in the MCP config file:

```bash
lllanyard tool add github-mcp --env GITHUB_PERSONAL_ACCESS_TOKEN=github \\
  --allow-host api.github.com --allow-host registry.npmjs.org --kill-on-leak \\
  -- npx -y @modelcontextprotocol/server-github
# MCP client config (Claude Desktop / Claude Code / Cursor style):
#   { "command": "lllanyard", "args": ["run", "github-mcp"] }
```

**3. Claude Desktop and Claude Code on a subscription.** These sign in to an account, not an API key, so there is no API
call to proxy and no extra API billing. Connect them once, from the command line or from the app's Scripts tab
("Connect AI apps"):

```bash
lllanyard setup claude-desktop --scripts-dir ~/Scripts   # --restart quits and reopens Claude Desktop if it's open (macOS)
lllanyard setup claude-code                              # adds a short section to ~/.claude/CLAUDE.md
lllanyard setup                                          # shows what's connected; --remove undoes either
```

Claude Desktop rewrites its config file when it quits, so a change made while it's open is lost. `setup` therefore only
changes it while the app is closed: on macOS it offers to quit Claude Desktop, make the change and reopen it (`--restart`
does this without asking); on Windows and Linux, quit it first (including from the system tray).

`setup claude-desktop` adds LLLanyard's MCP server to `claude_desktop_config.json` (macOS `~/Library/Application Support/Claude/`,
Windows `%APPDATA%\Claude\`, Linux `~/.config/Claude/`). It keeps your other settings, saves the old file as
`claude_desktop_config.json.lllanyard-backup`, and uses absolute paths plus your current `PATH`, since desktop apps start
MCP servers with a minimal one. If you move or reinstall Node or LLLanyard, run it again (`setup` warns when the paths are
stale). `setup claude-code` adds a marked section telling Claude Code to run scripts with `lllanyard exec` and never read
keys from `.env` files. It leaves the rest of the file alone.

In Claude Desktop, Claude then sees `list_scripts` and `run_script` for tools you approved with `lllanyard tool add`:
the script runs with its keys, the output (keys redacted) and exit code go back to Claude, and the run is logged
(`lllanyard usage`). It can't run anything you haven't approved, can't change the command, and only adds arguments
where you said `--allow-args`. Scripts get no input, so ones that prompt (`Read-Host`) need a non-interactive switch.
Runs stop after 10 minutes.

With `--scripts-dir DIR` (repeatable) you don't have to approve scripts one by one. Claude also gets
`run_file`, which can run any `.ps1`, `.py`, `.sh`, `.zsh` or `.js` file in those folders, but only after **you** click
Run in a dialog LLLanyard shows (Deny is the default; it gives up after 2 minutes). The dialog shows the script, its
arguments, the keys it will get (only the ones it uses, as with `exec`), and a warning if the script or a helper changed
in the last day, since an AI may have written it. The files are hashed before the dialog and checked again at launch,
so a script edited while you decide isn't run. Symlinks out of the folder, your home directory and `/` are refused.
Dialogs: macOS built in, Windows built in, Linux needs `zenity`; with no dialog, nothing runs.

Why "approve once": if `run` could inject any key into any command, an agent that can edit your MCP config could point it at
`curl https://evil` and walk off with the key. Approved tools live in the keychain, with the command pinned to its absolute
path, so editing a file can't change what receives a key. Custom providers are stored in the keychain for the same reason.

### Leak safeguards for tool processes

A tool started with `run` holds its key, so LLLanyard puts guard rails around it:

| Safeguard | What it does | Default |
|---|---|---|
| Minimal environment | The tool inherits only basics (PATH, HOME, temp dirs, locale, CA settings), so it can't see your *other* API keys or cloud credentials. `--pass-env VAR` adds specific variables; `--inherit-env` restores everything. | on |
| Output scrubbing | Removes the key from the tool's stdout/stderr, including base64, base64url, hex and URL-encoded copies. Streams, so MCP's newline-delimited stdio never stalls. | on |
| Leak alert / kill | The first time the tool prints its key you get a warning on stderr; with `--kill-on-leak` the tool is stopped at once (exit code 70). A tool echoing its own token is a strong sign it is buggy or compromised. | warn |
| Egress allowlist | `--allow-host api.github.com` (repeatable, `*.example.com` wildcards) starts a loopback proxy protected by a per-run password; the tool's proxy variables point at it, so it can only open HTTPS tunnels to listed hosts on public IPs. Denied attempts are logged. | off |
| Clean shutdown | Signals are forwarded and the tool is killed if LLLanyard exits. Keys go only into the child's environment, never the parent's. | on |
| Pinned command | The command is stored as an absolute path in the keychain, so a PATH swap or config edit can't change what receives the key. | on |

### Enforced isolation: `--sandbox`

Without a sandbox the safeguards above are advisory: a malicious tool can ignore proxy settings. `--sandbox` makes them
OS-enforced:

```
lllanyard tool add github-mcp --sandbox --allow-host api.github.com --allow-host registry.npmjs.org \
  --env GITHUB_PERSONAL_ACCESS_TOKEN=github -- npx -y @modelcontextprotocol/server-github
lllanyard doctor        # reports whether a sandbox works on this machine
```

| | Linux (bubblewrap) | macOS (Seatbelt `sandbox-exec`) |
|---|---|---|
| Network | No network at all. The only way out is a unix socket to the host egress proxy (via a tiny in-sandbox bridge), which allows only `--allow-host` hosts. DNS is resolved on the host. | Denied, except loopback to the egress proxy port |
| Home directory | Replaced by an empty tmpfs: no `~/.ssh`, `~/.aws`, browser profiles, shell history | Reads under `$HOME` denied except the project and shares |
| Writes | Only the current folder (and `--share-rw`); `/tmp` is private | Only the current folder, `--share-rw` and temp |
| Your keychain | No D-Bus/Secret Service socket, no `/run`; fresh `/proc` shows no other processes, so the parent's environment can't be read | Keychain services blocked (`SecurityServer`, `securityd`) |
| Other | `--unshare-all`, all capabilities dropped, dies with LLLanyard, `--new-session` when non-interactive | |

- **Fails closed.** Before each run a throwaway sandbox is started; if it can't start, the tool is **not** run (no silent
  fallback). A tool with `--sandbox` and no `--allow-host` gets no network.
- Run it from the project folder: only the current directory is writable, and running from your home directory is refused.
  Credential folders (`~/.ssh`, `~/.aws`, `~/.gnupg`, ...) cannot be shared even with `--share-ro/--share-rw`.
- Linux needs `sudo apt install bubblewrap`. Ubuntu 24.04+ restricts unprivileged user namespaces; `doctor` explains the fix.
- **Windows:** no sandbox. Use WSL2 (Debian/Ubuntu) to get the Linux one.
- **Beta.** The sandbox is tested in CI on Linux and macOS, but it is the newest part of LLLanyard. Run `lllanyard doctor`
  first.

Honest limits:

- **Without `--sandbox`, the egress allowlist is best-effort.** It constrains tools that honour proxy settings (most HTTP
  clients; recent Node via `NODE_USE_ENV_PROXY`, which may print an "experimental" notice). Tools launched with `npx` also
  need `registry.npmjs.org` allowed; pre-installing the package is better.
- A sandboxed tool still holds its own key and can send it to any allowlisted host, so allow only hosts you trust.
- **The key is still in the tool's memory and environment**; unsandboxed, it is readable by your OS user (`/proc/<pid>/environ`, Task Manager).
- **Scrubbing covers UTF-8 text.** Binary output, or a tool that splits or otherwise encodes the key (encryption, custom
  alphabets), gets through. `--no-scrub` exists for binary tools.
- If LLLanyard itself is force-killed (SIGKILL), the tool can be orphaned; a normal exit or Ctrl+C stops it.

Use `run` for tools you trust, and give each tool the narrowest key you can (a read-only GitHub token, not your admin one).

Env: `LLLANYARD_PORT`, `LLLANYARD_RPM` (requests/min per agent, default 120), `LLLANYARD_ALLOW_ORIGIN=1` (allow Electron-style requests that carry an Origin header).

## Security model

**Protects against:** keys sitting in `.env`/config files an agent can read; keys leaking into prompts, logs, screenshots or
git; prompt-injected agents echoing their "key" (it is only a placeholder); runaway request loops (rate limit + kill switch).

**Does NOT protect against:** malicious code running *as your OS user*. A fully compromised agent that can run shell
commands can ask the OS keychain for the key directly (macOS prompts; Windows and Linux generally do not). For
untrusted agents, run the proxy under a separate OS user or on another machine (see [Sharing with a team](#sharing-with-a-team-pro)).

Built-in hardening:
- Zero runtime dependencies in the proxy (Node built-ins only); the only native dependency is `@napi-rs/keyring`.
- Binds to `127.0.0.1` only; rejects non-loopback `Host` headers (DNS rebinding) and browser `Origin` requests.
- Agent tokens are 256-bit, stored only as SHA-256 hashes, compared in constant time.
- Upstream host is fixed per provider; request paths can't change it; redirects are never followed.
- Cookies are stripped both ways; logs contain agent/provider/status only (no keys, bodies or query strings).
- No command ever prints a stored key. `scan` masks keys, and findings hold plaintext in a private field that is
  excluded from JSON/inspect output. `--redact` edits atomically and writes **no backup** (a backup is another plaintext copy).
- Keys given on the command line are refused by default (`--allow-argv` overrides).
- Custom providers must use https and a public hostname (no IPs, no credentials in the URL). The proxy also refuses to connect
  to private, loopback, link-local (cloud metadata) or CGNAT addresses, including hostnames that resolve to them, unless a
  provider was explicitly created with `--allow-local` for a loopback server.
- Built-in provider names can't be redefined; names like `constructor` are never treated as providers.
- Agents created with `--providers` get a 403 for anything else.
- `run`: keys go only into the child's environment (never the parent's), blocked variables (`LD_*`, `DYLD_*`, `PATH`,
  `NODE_OPTIONS`...) are refused, and on Windows `.cmd` shims (npx) run through a shell only if every argument is plain.
- Limits: JavaScript cannot wipe strings from memory; the proxy caches a key for 30 s. Revoking an agent takes ≤10 s to apply.

Keys that sat in plaintext should be treated as exposed: after `scan --import`, create new keys at the provider and run `rotate`.

## Platform notes

- **macOS / Windows:** work out of the box (Keychain / Credential Manager).
- **Debian/Ubuntu:** needs a Secret Service: `sudo apt install gnome-keyring libsecret-1-0`, inside a desktop/D-Bus session.
  Headless servers are not supported yet.

## Tiers

Free: up to 10 keys and 5 agent tokens, local only. Pro and Team ([pricing](https://lllanyard.app/pricing)) raise the key
limit and add the shared proxy for a team and the usage dashboard.

### Desktop app and rotation assistant

`lllanyard ui` opens a private local page in your browser (`apps/desktop` wraps the same page in a native Tauri window):
keys with rotation badges, add/replace/remove (keys are write-only: only the last 4 characters are ever shown), agent
tokens, usage, proxy start/stop, license, and the **rotation assistant**.

- The assistant gets **metadata only** (provider, label, age, due date, request counts), never a key, and only talks to a model
  **on this computer** (Ollama at `127.0.0.1:11434` by default, or an OpenAI-compatible local server such as LM Studio or
  llama.cpp). A non-localhost endpoint is refused. With no model running, "Quick review" still gives a rule-based plan.
- The UI server listens on loopback only and needs a random per-run session secret (in the link's `#` fragment, removed from the
  address bar on load) on every API call. It also checks the Host header (DNS rebinding), refuses foreign Origins and
  cross-site fetches, requires JSON for writes, caps request size, and serves a strict Content-Security-Policy with a per-run
  nonce. All text is inserted with `textContent`, never as HTML.
- Honest limits: any program running as your user could still read the session secret from the process list or the printed
  link, as it could read your keychain; this protects against web pages and other websites, not against local malware.

### MCP server for agents

`lllanyard mcp` is a read-only [MCP](https://modelcontextprotocol.io) server over stdio. Add it to Claude Code, Cursor, etc.:

```json
{ "mcpServers": { "lllanyard": { "command": "lllanyard", "args": ["mcp"] } } }
```

Tools: `list_providers`, `key_status` (age and rotation due dates), `usage_summary`, `how_to_connect`. It can answer "is my
OpenAI key due for rotation?" or "what is the base URL for GitHub?" and cannot return a key, a token or any hint of one
(not even the last 4 characters), nor change anything. `--client acme` limits it to one client's keys. With the file vault the
passphrase must come from `LLLANYARD_VAULT_PASSPHRASE_FILE` (no prompt is possible on stdio). Note that anything an agent can
run as your user can also run `lllanyard` directly; the MCP server is a safe *information* channel, not an access boundary.

### Sharing with a team (Pro)

One computer (a small server, or an always-on workstation) holds the real keys; teammates get their own agent tokens.

```
lllanyard serve --host 0.0.0.0 --port 3443 --tls-cert cert.pem --tls-key key.pem --allow-host keys.example.com
lllanyard agent create alice-laptop --client acme --providers openai --expires 90d
```

Teammates point their tools at `https://keys.example.com:3443/openai/v1` and use their token as the API key. They can
*use* a key but never read it. Revoking a token cuts that person off within ~10 seconds.

| Safeguard | |
|---|---|
| TLS required | Non-loopback binds refuse to start without `--tls-cert/--tls-key` (TLS 1.2+); the key file must be `chmod 600` |
| Host allowlist | Only the names given with `--allow-host` (plus loopback) are accepted: DNS-rebinding protection stays on |
| Brute-force lockout | 10 bad tokens in 10 minutes locks that address out for 15 minutes, even for a valid token |
| Per-person scope | Each token is limited to a client (`--client`), optionally to providers, and can expire (`--expires`) |
| Audit trail | Every request is logged with agent name and caller address; `lllanyard usage` breaks it down by agent and client |
| Rate limits + kill switch | Per token, as before |
| Seats | Free: 5 agent tokens. Licensed: 3 tokens per seat |

Put it behind a VPN (Tailscale, WireGuard) or a firewall if you can; the lockout and TLS are a second layer, not a reason to
expose it to the whole internet. `X-Forwarded-For` is deliberately ignored, so a reverse proxy in front shows as one address.

**Headless servers and containers: the encrypted file vault.** The OS keychain needs a desktop login, so on a server use
`LLLANYARD_BACKEND=file`. Everything (keys, agents, tools, license) then lives in one encrypted file,
`~/.lllanyard/vault.enc` (override with `LLLANYARD_VAULT_PATH`): AES-256-GCM, key from your passphrase via scrypt, atomic
writes, safe with several processes. Wrong passphrases and edited files are detected.

```
echo 'a long random passphrase' > /etc/lllanyard/pass && chmod 600 /etc/lllanyard/pass
export LLLANYARD_BACKEND=file LLLANYARD_VAULT_PASSPHRASE_FILE=/etc/lllanyard/pass
lllanyard add openai --stdin < key.txt && lllanyard serve --host 0.0.0.0 ...
```

On a terminal with no passphrase file you are prompted instead (hidden). Under systemd use `LoadCredential=` and point
`LLLANYARD_VAULT_PASSPHRASE_FILE` at `$CREDENTIALS_DIRECTORY/pass`. Honest limit: it protects the vault at rest (backups,
disk images, other users); someone who can read both the vault and the passphrase file as your user can open it. The
passphrase can't be changed once the vault is created.

### Usage and dashboard

The proxy keeps a metadata-only request log (`~/.lllanyard/usage.jsonl`, owner-only, rotates at 10 MB; no keys, bodies or
query strings). Blocked egress attempts from sandboxed tools are added too.

```
lllanyard usage --since 7d      # free: requests, errors, 429s, kill-switch trips, p50/p95 by provider/agent/client
lllanyard dashboard             # Pro: self-contained HTML page (no scripts, no network requests)
```

### Licenses

Buy Pro or Team at [lllanyard.app](https://lllanyard.app/pricing). Paid tiers are unlocked by a signed license key that
is verified **offline** (Ed25519):

```
lllanyard license activate lly1.…     # or --key lly1.…, or --stdin
lllanyard license status
lllanyard license refresh             # fetch the renewed key after your subscription renews
```

The only time LLLanyard contacts anything of ours: in the last 7 days before a paid license runs out, `start` and `ui`
send that license (nothing else) to lllanyard.app to fetch its renewed key. Set `LLLANYARD_NO_LICENSE_REFRESH=1` to turn
this off; each renewed key is also emailed.

Pro lifts the key cap to 250, Team to 500 (`TIER_LIMITS` in `packages/core/src/license.ts`). An expired license drops
back to free: existing keys keep working, you just can't add past the free cap.

**Honest limit:** a local check can be patched in private. The license (see License) forbids it and makes such use
unlicensed.

## License

LLLanyard is source-available under the **Business Source License 1.1** (`LICENSE.md`), licensor **Ethan Askew T/A LLLanyard**.
In plain words (the license text is what counts):

- You can read, copy, modify and **evaluate or develop** with it freely.
- **Production use** is free within the free tier (10 keys, 5 agent tokens, local only). Beyond that you need a paid license key
  from Ethan Askew T/A LLLanyard.
- You **may not remove, bypass or tamper with the license-key checks or usage limits**, or help others do so. Doing it makes
  your use unlicensed, and the license terminates.
- You may not resell it as a hosted/embedded competing product.
- Each version converts to Apache 2.0 four years after its release.

Licensing questions: sales@lllanyard.co.uk.

## Verifying on your machine

`node tools/smoke.mjs` (add `--keychain` to also test your real OS keychain once) runs the real CLI, proxy, UI and MCP server
against a throwaway vault and prints PASS/FAIL plus a one-line report for bug reports.

## Tests

`npm test` runs the suite (tsx + node:test): storage, tokens, scanner and redaction, rotation, provider and tool validation,
the output scrubber, the `run` engine with real child processes, the egress proxy, the sandbox, and proxy integration tests
against a fake upstream. CI (`.github/workflows/ci.yml`) runs it on Linux, macOS and Windows with Node 22 and 24, with a full
type-check and `npm audit`.
