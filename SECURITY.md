# Security policy

LLLanyard exists to protect API keys, so we take reports seriously.

**Report privately.** Email security@lllanyard.app (or use GitHub's "Report a vulnerability" on this repository). Please do not
open a public issue for a vulnerability. Include steps to reproduce, the version, and your OS.

**What to expect:** an acknowledgement within 3 working days and a fix or mitigation plan within 14 days for confirmed issues.
We credit reporters who want credit.

**In scope:** key disclosure (logs, errors, process arguments, files), authentication or authorisation bypass on the proxy,
request smuggling or SSRF through the proxy, sandbox escapes in `--sandbox`, vault or license-signature weaknesses.

**Known and documented limits** (see "Security model" and "Honest limits" in the README) are not vulnerabilities: a process
already running as your user can read your keychain or an unsandboxed tool's environment; the egress allowlist is
advisory without `--sandbox`; a source-available license check can be patched locally.
