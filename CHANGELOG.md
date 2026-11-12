# Changelog

Each release of LLLanyard and what changed in it. Versions follow [semantic versioning](https://semver.org): while
LLLanyard is 0.x, a new minor version (0.2.0) can change behaviour, and a patch (0.1.5) is for fixes and security updates.

## Unreleased

## 0.2.0 (12 November 2026)

- SSH logins. `lllanyard ssh add <name> --host HOST` stores a private key (pasted with no echo, or from a file) or a
  password in the keychain, `lllanyard ssh generate` makes a new key there and prints its public half, and
  `lllanyard ssh <name>` opens the session. The key is loaded into a throwaway ssh-agent for that session only (never
  written to a file); a password is passed through ssh's askpass helper. `lllanyard ssh with <name> -- <command>` runs
  scp, rsync, git or a script with the login available. SSH logins are included in backups and count towards the
  key limit.
- SSH tab in the app: add a login (paste a key, or a password), make a new key, copy its public half, remove a login.
- Claude Desktop (`lllanyard mcp --run`) gets `list_ssh` and `ssh_run`. Claude can run one command on a stored login,
  but only after you click Run in a dialog that shows the login and the exact command, every time. It never sees the
  key or password, the output has them redacted, and each request is logged.
- Large keys such as RSA 4096 are stored across several keychain entries, so they fit Windows' size limit.

## 0.1.5 (1 November 2026)

- `lllanyard --version` shows the installed version.
- A changelog, listing what changed in each release.

## 0.1.4 (1 November 2026)

- **Pro: up to 3 paired devices.** `lllanyard device add <name>` on the main computer makes a one-time code. On the
  other device, `lllanyard device join https://main:port` swaps it for a device token, which works only on the
  computer it was paired on. `device list`, `device remove`, `device status` and `device leave` manage them.
- **`lllanyard exec --remote`** on a paired device runs a script or tool with the keys it needs from the main computer.
  The keys are kept in memory for that run only, never saved on the device, and redacted from the output. Each one is
  logged on the main computer, and `lllanyard usage` lists them.
- **`lllanyard relay`** gives apps on a paired device, such as an editor, a fixed local address. Keys never reach the
  device. `device add --no-keys` makes a device that only ever works this way.
- On Pro, agent tokens now work on the main computer only. Other computers are paired as devices.
- **Team: personal keys alongside the team's.** `lllanyard team join https://team-server:port` links your own
  LLLanyard to the team server. Your personal keys stay on your computer, and anything you have no key for goes to the
  team server. `team status` and `team leave` manage the link.

## 0.1.3 (1 November 2026)

- Agent tokens (one per AI tool or app you link in): Free 5, Pro 10 per user, Team unlimited. Tokens you already have
  keep working.
- Where each plan runs, stated plainly. Free: this computer. Pro: your own devices. Team: your team on your network.

## 0.1.2 (31 October 2026)

- Generic examples and clearer wording in the documentation.

## 0.1.1 (31 October 2026)

- Documentation tidied for the public release.

## 0.1.0 (31 October 2026)

- First public release: keys in the OS keychain (or an encrypted file vault on servers), a local proxy that gives AI
  agents placeholder tokens, `lllanyard exec` for scripts with output redaction, approved tools with an optional
  sandbox, an MCP server for Claude Desktop, key scanning and import, encrypted backups, usage reports and the local
  app (`lllanyard ui`).
