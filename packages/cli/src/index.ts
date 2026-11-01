#!/usr/bin/env node
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import {
  AgentStore, APP_NAME, createMcpHandler, serveMcpStdio, allProviders, FileBackend, LicenseStore, refreshDue, refreshLicense, MIN_PASSPHRASE, backendKind, defaultBackend, setVaultPassphrase, vaultPassphrase, createUsageLog, parseSince, readUsage, renderDashboard, summarize, usageLogPath, type Row, BUILTIN_PROVIDERS, DEFAULT_PORT, KeyringBackend, KeyringStore, ProviderStore, ToolStore,
  defaultRoots, parseKeyRef, redactFile, rotationStatus, runTool, sandboxSelfTest, scan, type AuthSpec, type Finding,
  createBackup, describeItem, readBackup, restoreBackup, pinScript, findCommand, pinFiles, bindingsForKeys, bindingsForAllKeys, scriptOf, neededEnv, type RunResult, type ToolDef,
  resolveScriptDirs, planScriptRun, describePlan, confirmDialog, type Launch,
  stableNodePath, withClaudeDesktopClosed, claudeDesktopRunning, canRestartClaudeDesktop, claudeDesktopStatus, connectClaudeDesktop, disconnectClaudeDesktop, claudeCodeStatus, connectClaudeCode, disconnectClaudeCode,
} from '@lllanyard/core';
import { startEgressProxy, startProxy } from '@lllanyard/proxy';
import { openBrowser, startUi } from '@lllanyard/ui';

const BOOL = new Set(['run', 'remove', 'restart', 'clear', 'stdin', 'allow-argv', 'import', 'redact', 'apply', 'json', 'help', 'allow-local', 'no-scrub', 'no-resolve', 'kill-on-leak', 'inherit-env', 'sandbox', 'no-open', 'print-url', 'overwrite', 'dry-run', 'allow-args']);
const MULTI = new Set(['scripts-dir', 'pin', 'env', 'allow-host', 'pass-env', 'share-ro', 'share-rw']);

function parse(argv: string[]) {
  const pos: string[] = [];
  const flags: Record<string, string | boolean> = {};
  const multi: Record<string, string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith('--')) { pos.push(a); continue; }
    const [k, v] = a.slice(2).split(/=(.*)/s) as [string, string | undefined];
    if (BOOL.has(k)) { flags[k] = true; continue; }
    const val = v ?? argv[++i] ?? '';
    if (MULTI.has(k)) (multi[k] ??= []).push(val);
    else flags[k] = val;
  }
  return { pos, flags, multi };
}

const out = (s = '') => process.stdout.write(s + '\n');
const fail = (s: string): never => { throw new Error(s); };
const str = (v: string | boolean | undefined) => (typeof v === 'string' ? v : undefined);

const HELP = `${APP_NAME} - keep API keys out of AI agents

Keys
  add <provider> [--label NAME] [--rotate-days N] [--env-name VAR]   store a key (hidden prompt; or pipe it with --stdin)
  env <provider>[:label] VAR | --clear              the variable name tools get this key as (e.g. GITHUB_TOKEN)
  list                                              show stored keys and their variable names (never shows secrets)
  remove <provider> [--label NAME]
  rotate <provider> [--label NAME]                  replace a key and reset its rotation clock
  status                                            rotation status for every key (exit 1 if any overdue)

Run scripts with your keys
  exec <command> [args...]                          run a script with the keys it uses, e.g.
                                                      lllanyard exec pwsh -File Deploy-App.ps1 -DryRun
                                                    It reads the script (and helper files it names) for your keys' variable
                                                    names and passes only those. Keys are never printed: any in the output
                                                    are redacted. --keys github,sendgrid -- <command> names them yourself.

Agents
  agent create <name> [--client NAME] [--providers a,b] [--expires 30d]   placeholder token; --providers limits what it can reach
  agent list | agent revoke <name>

Tools (GitHub, Slack, Stripe, your own APIs...)
  provider add <id> --upstream https://api.x.com [--auth bearer|header] [--header NAME] [--prefix TXT] [--allow-local]
  provider list | provider remove <id>              custom API hosts the proxy may call with a stored key
  tool add <name> --keys github,sendgrid [safeguards] -- <command> [args...]
                                                    approve a command (e.g. a script or MCP server) to receive keys;
                                                    --keys uses each key's variable name, --env VAR=provider[:label] picks one
      safeguards: --allow-host api.x.com (repeat; limits where the tool can connect, best-effort)
                  --kill-on-leak  --pass-env VAR (repeat)  --inherit-env  --no-scrub
      sandbox:    --sandbox (OS-enforced: no network except --allow-host, empty home, only the current folder writable;
                  refuses to run if no sandbox is available)  --share-ro DIR / --share-rw DIR (repeat)
      scripts:    for python/node/sh/pwsh... the script file is pinned: run refuses if it changes (approve again to update)
                  --allow-args lets "run <name> -- args" add arguments after the stored ones
                  --pin FILE (repeat) also pins files the script loads, e.g. a shared helper
  tool list | tool remove <name>
  run <name> [-- args...]                           run an approved tool with its keys injected (never printed)
  run --env VAR=provider -- <command> [args...]     one-off run; asks for confirmation in a terminal

Connect AI apps
  setup                                             show which apps are connected
  setup claude-desktop [--scripts-dir DIR] [--remove] [--restart]
                                                    let Claude Desktop run your approved tools, and with --scripts-dir (repeat)
                                                    any script in DIR after you click Run in a dialog. Claude Desktop must be
                                                    closed (it rewrites its settings on quit); --restart quits and reopens it (macOS)
  setup claude-code [--remove]                      tell Claude Code (~/.claude/CLAUDE.md) to use lllanyard exec, not .env files

Hygiene
  scan [paths...] [--import --apply [--redact]]     find plaintext keys; move them into the keychain

Backup
  backup [--out FILE] [--passphrase-file F]         encrypted backup of keys, providers, tools, agents and license
  restore <file> [--overwrite] [--dry-run] [--passphrase-file F]
                                                    merge a backup in; existing items are kept unless --overwrite

Run
  start [--port N]                                 start the local proxy (127.0.0.1 only)
  usage [--since 7d] [--json]                       request counts, errors, latency by provider/agent/client
  dashboard [--since 30d] [--out file]              visual HTML dashboard (Pro)
  license activate|status|refresh|remove            unlock Pro/Team with a signed license key; refresh fetches
                                                    the renewed key (done for you at start-up in the last week)
  ui [--no-open]                                    desktop-style window in your browser: keys, agents, usage, rotation assistant
  mcp [--client NAME] [--run [--timeout SECS]]     MCP server for Claude Desktop etc.: key status, never shows keys.
                                                    --run also lets it run your approved tools (lllanyard tool add) by name,
                                                    with keys injected and output redacted (default time limit 600s)
                                                    --scripts-dir DIR (repeat) also lets it run any script in DIR,
                                                    after you click Run in a dialog that shows the script and its keys
  serve --host H --port P --tls-cert F --tls-key F --allow-host NAME   share the proxy with your team (Pro; keys stay in this keychain)
  doctor                                            check OS keychain and sandbox access
`;

async function readStdin(): Promise<string> {
  let s = '';
  process.stdin.setEncoding('utf8');
  for await (const c of process.stdin) s += c;
  return s.trim();
}

async function readSecret(prompt: string, forceStdin = false): Promise<string> {
  if (forceStdin || !process.stdin.isTTY) return readStdin();
  process.stderr.write(prompt);
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    let buf = '';
    const done = () => { stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData); process.stderr.write('\n'); };
    const onData = (chunk: string) => {
      for (const c of chunk) {
        if (c === '\r' || c === '\n') { done(); return resolve(buf.trim()); }
        if (c === '\u0003') { done(); return reject(new Error('Cancelled')); }
        if (c === '\u007f' || c === '\b') { buf = buf.slice(0, -1); continue; }
        buf += c;
      }
    };
    stdin.setRawMode(true);
    stdin.setEncoding('utf8');
    stdin.resume();
    stdin.on('data', onData);
  });
}

const PREFIX: Record<string, string> = { openai: 'sk-', anthropic: 'sk-ant-' };
const day = (iso: string) => iso.slice(0, 10);

function envSnippet(token: string, providers?: string[]) {
  const port = process.env.LLLANYARD_PORT ?? DEFAULT_PORT;
  const base = `http://127.0.0.1:${port}`;
  const want = (p: string) => !providers || providers.includes(p);
  const rows: [string, string][] = [];
  if (want('anthropic')) rows.push(['ANTHROPIC_BASE_URL', `${base}/anthropic`], ['ANTHROPIC_API_KEY', token]);
  if (want('openai')) rows.push(['OPENAI_BASE_URL', `${base}/openai/v1`], ['OPENAI_API_KEY', token]);
  const lines = process.platform === 'win32'
    ? rows.map(([k, v]) => `  $env:${k}="${v}"`)
    : rows.map(([k, v]) => `  export ${k}=${v}`);
  for (const p of providers ?? []) {
    if (p !== 'anthropic' && p !== 'openai') lines.push(`  # ${p}: API base URL ${base}/${p}  (use the token above wherever the tool wants that API's key)`);
  }
  return lines.join('\n');
}

async function maybeEgress(name: string, hosts: string[] | undefined, sandbox = false) {
  if (!hosts?.length) return undefined;
  const debug = Boolean(process.env.LLLANYARD_DEBUG);
  const usage = createUsageLog();
  const log = (r: Record<string, unknown>) => { if (r.decision === 'deny') usage.write(r); if (r.decision === 'deny' || debug) process.stderr.write(`lllanyard: ${JSON.stringify(r)}\n`); };
  if (sandbox && process.platform === 'linux') {
    // The sandbox has no network; its only way out is this unix socket, in a private directory.
    const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-'));
    const p = await startEgressProxy({ allow: hosts, label: name, log, unixSocket: path.join(dir, 'egress.sock') });
    return { ...p, close: () => { p.close(); rmSync(dir, { recursive: true, force: true }); } };
  }
  return startEgressProxy({ allow: hosts, label: name, log });
}

function describeSafeguards(t: { sandbox?: boolean; scrub: boolean; allowHosts?: string[]; killOnLeak?: boolean; inheritEnv?: boolean; passEnv?: string[]; scriptSha256?: string; pins?: Record<string, string>; allowArgs?: boolean }) {
  const pinned = (t.scriptSha256 ? 1 : 0) + Object.keys(t.pins ?? {}).length;
  return [
    ...(pinned ? [`${pinned} file(s) pinned`] : []),
    ...(t.allowArgs ? ['extra args allowed'] : []),
    t.sandbox ? 'OS sandbox' : 'no OS sandbox',
    t.scrub ? 'output scrubbed' : 'output NOT scrubbed',
    t.allowHosts?.length ? `network limited to ${t.allowHosts.join(', ')}` : 'network unrestricted',
    t.inheritEnv ? 'full environment inherited' : `minimal environment${t.passEnv?.length ? ` + ${t.passEnv.join(', ')}` : ''}`,
    t.killOnLeak ? 'kill-on-leak' : 'warn-on-leak',
  ].join('; ');
}

function parseBindings(items: string[] | undefined): Record<string, string> {
  const env: Record<string, string> = {};
  for (const it of items ?? []) {
    const i = it.indexOf('=');
    if (i < 1) fail(`Bad --env "${it}" (use VAR=provider or VAR=provider:label)`);
    const name = it.slice(0, i), ref = it.slice(i + 1);
    parseKeyRef(ref);
    env[name] = ref;
  }
  return env;
}

async function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY || !process.stderr.isTTY) return false;
  const rl = (await import('node:readline')).createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((r) => rl.question(question, (a) => { rl.close(); r(/^y(es)?$/i.test(a.trim())); }));
}

process.stdout.on('error', (e: NodeJS.ErrnoException) => { if (e.code !== 'EPIPE') throw e; process.exit(0); }); // e.g. `lllanyard usage | head`

async function main() {
  const [cmd, ...all] = process.argv.slice(2);
  const dd = all.indexOf('--');
  const rest = dd >= 0 ? all.slice(0, dd) : all;
  const tail = dd >= 0 ? all.slice(dd + 1) : [];
  const { pos, flags, multi } = parse(rest);
  if (!cmd || cmd === 'help' || (flags.help && cmd !== 'exec')) return out(HELP);

  // File vault: get the passphrase (from a file/env if configured, else a hidden prompt on a terminal).
  if (backendKind() === 'file' && !vaultPassphrase() && cmd !== 'mcp') {
    if (!process.stdin.isTTY || flags.stdin) fail('LLLANYARD_BACKEND=file needs a passphrase: set LLLANYARD_VAULT_PASSPHRASE_FILE to a chmod 600 file (a terminal prompt is not possible here).');
    const fresh = !new FileBackend().exists();
    const p1 = await readSecret(fresh ? `Choose a vault passphrase (min ${MIN_PASSPHRASE} characters, input hidden): ` : 'Vault passphrase (input hidden): ');
    if (fresh) {
      if (p1.length < MIN_PASSPHRASE) fail(`Passphrase must be at least ${MIN_PASSPHRASE} characters.`);
      if ((await readSecret('Repeat passphrase: ')) !== p1) fail('Passphrases did not match.');
    }
    setVaultPassphrase(p1);
  }
  const store = () => new KeyringStore(undefined, { maxKeys: new LicenseStore().limits().maxKeys });
  const label = str(flags.label);

  switch (cmd) {
    case 'add': {
      const provider = pos[0] ?? fail('Usage: lllanyard add <provider> [--label NAME] [--rotate-days N]');
      let secret: string;
      if (pos[1]) {
        if (!flags['allow-argv'])
          fail('Refusing a key on the command line: it would end up in shell history and process lists.\n' +
               'Run without the key for a hidden prompt, or pipe it with --stdin. (Override: --allow-argv)');
        secret = pos[1];
      } else secret = await readSecret(`${provider} API key (input hidden): `, Boolean(flags.stdin));
      const want = PREFIX[provider.toLowerCase()];
      if (want && !secret.startsWith(want)) process.stderr.write(`Warning: ${provider} keys normally start with "${want}". Stored anyway.\n`);
      const days = str(flags['rotate-days']);
      const m = store().set(provider, secret, { label, rotateAfterDays: days ? Number(days) : undefined, envName: str(flags['env-name']) });
      return out(`Stored ${m.id} (…${m.last4})${m.envName ? ` as ${m.envName}` : ''}. Rotate by ${day(new Date(Date.parse(m.createdAt) + m.rotateAfterDays * 86_400_000).toISOString())}.`);
    }
    case 'list': {
      const keys = store().list();
      if (!keys.length) return out('No keys stored. Add one with: lllanyard add openai');
      for (const k of keys) out(`${k.id.padEnd(28)} …${k.last4}  ${(k.envName ?? '-').padEnd(26)} added ${day(k.createdAt)}`);
      return;
    }
    case 'env': {
      const ref = pos[0] ?? fail('Usage: lllanyard env <provider>[:label] VARIABLE_NAME   (or --clear)');
      const { provider: p, label: l } = parseKeyRef(ref);
      const name = flags.clear ? undefined : pos[1] ?? fail('Give the variable name, e.g.  lllanyard env github GITHUB_TOKEN   (or --clear)');
      const m = store().setEnvName(p, l, name);
      return out(m.envName ? `${m.id} is given to tools as ${m.envName}.` : `${m.id} has no variable name now.`);
    }
    case 'remove': {
      const p = pos[0] ?? fail('Usage: lllanyard remove <provider> [--label NAME]');
      return out(store().remove(p, label) ? `Removed ${p}:${label ?? 'default'}` : 'Nothing to remove.');
    }
    case 'rotate': {
      const p = pos[0] ?? fail('Usage: lllanyard rotate <provider> [--label NAME]');
      const s = store();
      if (!s.get(p, label)) fail(`No ${p}:${label ?? 'default'} key to rotate. Use "add" first.`);
      const secret = await readSecret(`NEW ${p} API key (input hidden): `, Boolean(flags.stdin));
      const m = s.set(p, secret, { label });
      out(`Rotated ${m.id} (…${m.last4}). Now revoke the OLD key at the provider so it stops working.`);
      const st = rotationStatus(m);
      return st.rotateUrl && out(`  ${st.rotateUrl}`);
    }
    case 'status': {
      const keys = store().list();
      if (!keys.length) return out('No keys stored.');
      let overdue = false;
      for (const k of keys) {
        const s = rotationStatus(k);
        if (s.state === 'overdue') overdue = true;
        const when = s.dueInDays < 0 ? `${-s.dueInDays}d overdue` : `due in ${s.dueInDays}d`;
        out(`${s.state === 'ok' ? 'OK     ' : s.state === 'due-soon' ? 'SOON   ' : 'OVERDUE'} ${s.id.padEnd(26)} age ${s.ageDays}d, ${when}${s.state !== 'ok' && s.rotateUrl ? `  ${s.rotateUrl}` : ''}`);
      }
      if (overdue) process.exitCode = 1;
      return;
    }
    case 'agent': {
      const [sub, name] = pos;
      const agents = new AgentStore();
      if (sub === 'create') {
        if (!name) fail('Usage: lllanyard agent create <name> [--client NAME]');
        const client = str(flags.client) ?? 'default';
        const provs = str(flags.providers)?.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
        const lic = new LicenseStore();
        const limit = lic.maxAgents();
        if (!agents.list().some((a) => a.name === name.toLowerCase()) && agents.list().length >= limit)
          fail(`${lic.status().tier === 'free' ? 'Free tier allows' : 'Your license allows'} ${limit} agents. Revoke one${lic.status().tier === 'free' ? ' or upgrade (lllanyard license activate)' : ' or add seats'}.`);
        const exp = str(flags.expires);
        const token = agents.create(name, client, provs, exp ? { expiresAt: new Date(2 * Date.now() - parseSince(exp)) } : {});
        out(`Agent "${name}" created (client: ${client}${provs ? `, providers: ${provs.join(', ')}` : ''}${exp ? `, expires in ${exp}` : ''}). This token is shown ONCE and cannot be recovered:\n\n  ${token}\n`);
        out(`Point the tool at the proxy:\n${envSnippet(token, provs)}\n`);
        return out('The token is worthless outside the proxy. The real key never leaves your keychain.');
      }
      if (sub === 'list') {
        const l = agents.list();
        return l.length ? l.forEach((a) => out(`${a.name.padEnd(24)} client=${a.client}  providers=${a.providers?.join(',') ?? 'all'}  created ${day(a.createdAt)}${a.expiresAt ? `  expires ${day(a.expiresAt)}` : ''}`)) : out('No agents.');
      }
      if (sub === 'revoke') {
        if (!name) fail('Usage: lllanyard agent revoke <name>');
        return out(agents.revoke(name) ? `Revoked ${name} (takes effect within ~10s on a running proxy).` : 'No such agent.');
      }
      return fail('Usage: lllanyard agent create|list|revoke');
    }
    case 'scan': {
      const findings = await scan({ roots: pos.length ? pos : defaultRoots() });
      if (flags.json) return out(JSON.stringify(findings, null, 2)); // secrets are never serialised
      if (!findings.length) return out('No plaintext keys found.');
      for (const f of findings) out(`${f.provider.padEnd(10)} ${f.masked.padEnd(16)} ${f.file}:${f.line}${f.importable ? '' : '  (detected only)'}`);
      if (!flags.import) return out(`\n${findings.length} found. Run again with --import to move supported keys into the keychain (dry run unless --apply).`);
      return importFindings(findings, store(), Boolean(flags.apply), Boolean(flags.redact));
    }
    case 'provider': {
      const [sub, id] = pos;
      const ps = new ProviderStore();
      if (sub === 'add') {
        if (!id) fail('Usage: lllanyard provider add <id> --upstream https://api.example.com [--auth bearer|header] [--header NAME] [--prefix TXT] [--allow-local]');
        const kind = str(flags.auth) ?? 'bearer';
        let auth: AuthSpec;
        if (kind === 'bearer') auth = { type: 'bearer' };
        else if (kind === 'header') {
          const name = str(flags.header) ?? fail('--auth header needs --header NAME (e.g. X-Api-Key)');
          auth = { type: 'header', name, ...(str(flags.prefix) !== undefined ? { prefix: str(flags.prefix) } : {}) };
        } else return fail('--auth must be bearer or header');
        const v = ps.set({ id, upstream: str(flags.upstream) ?? fail('--upstream is required'), auth, allowLocal: Boolean(flags['allow-local']) });
        out(`Provider "${v.id}" saved: ${v.upstream} (${v.auth.type === 'bearer' ? 'Authorization: Bearer' : `${v.auth.name} header`}).`);
        return out(`Store its key:  lllanyard add ${v.id}\nThen call it via http://127.0.0.1:${process.env.LLLANYARD_PORT ?? DEFAULT_PORT}/${v.id}/...`);
      }
      if (sub === 'list') {
        for (const p of BUILTIN_PROVIDERS) out(`${p.id.padEnd(14)} ${p.upstream}  (built-in)`);
        for (const p of ps.list()) out(`${p.id.padEnd(14)} ${p.upstream}${p.allowLocal ? '  (local)' : ''}`);
        return;
      }
      if (sub === 'remove') return out(id && ps.remove(id) ? `Removed provider ${id}` : 'No such custom provider.');
      return fail('Usage: lllanyard provider add|list|remove');
    }
    case 'tool': {
      const [sub, name] = pos;
      const ts = new ToolStore();
      if (sub === 'add') {
        if (!name) fail('Usage: lllanyard tool add <name> --env VAR=provider[:label] -- <command> [args...]');
        const [command, ...rawArgs] = tail;
        if (!command) fail('Put the command after "--", e.g.  tool add github-mcp --env GITHUB_PERSONAL_ACCESS_TOKEN=github -- npx -y @modelcontextprotocol/server-github');
        const exe = flags['no-resolve'] ? command : findCommand(command);
        const { args, scriptSha256 } = pinScript(exe, rawArgs);
        const fromKeys = bindingsForKeys(str(flags.keys)?.split(',').map((x) => x.trim()).filter(Boolean) ?? [], store());
        const t = ts.set({
          name, command: exe, args, scriptSha256, pins: multi.pin?.length ? pinFiles(multi.pin) : undefined, allowArgs: Boolean(flags['allow-args']),
          env: { ...fromKeys, ...parseBindings(multi.env) }, scrub: !flags['no-scrub'],
          allowHosts: multi['allow-host'], passEnv: multi['pass-env'], killOnLeak: Boolean(flags['kill-on-leak']), inheritEnv: Boolean(flags['inherit-env']),
          sandbox: Boolean(flags.sandbox), shareRo: multi['share-ro'], shareRw: multi['share-rw'],
        });
        out(`Tool "${t.name}" approved: ${[t.command, ...t.args].join(' ')}`);
        out(`Keys: ${Object.entries(t.env).map(([k, v]) => `${k}<-${v}`).join(', ')}`);
        out(`Safeguards: ${describeSafeguards(t)}`);
        if (t.sandbox && !t.allowHosts?.length) out('Sandboxed with NO network (no --allow-host). Add --allow-host if the tool must reach an API.');
        else if (!t.allowHosts?.length) out('Tip: add --allow-host api.example.com so the tool can only reach the hosts it needs (npx tools also need registry.npmjs.org).');
        out(`\nMCP client config (no secrets in the file):\n  { "command": "lllanyard", "args": ["run", "${t.name}"] }`);
        return out('If your app can\'t find "lllanyard", use its absolute path (run: which lllanyard / where lllanyard).');
      }
      if (sub === 'list') {
        const l = ts.list();
        return l.length ? l.forEach((t) => out(`${t.name.padEnd(18)} ${[t.command, ...t.args].join(' ')}   keys: ${Object.entries(t.env).map(([k, v]) => `${k}<-${v}`).join(', ')}\n${' '.repeat(19)}${describeSafeguards(t)}`)) : out('No tools approved yet.');
      }
      if (sub === 'remove') return out(name && ts.remove(name) ? `Removed tool ${name}` : 'No such tool.');
      return fail('Usage: lllanyard tool add|list|remove');
    }
    case 'exec': {
      // Everything after "exec" (and an optional "--keys a,b") is the command, passed through untouched.
      let argv = process.argv.slice(3);
      let only: string[] | undefined;
      if (argv[0] === '--keys') { only = (argv[1] ?? '').split(',').map((x) => x.trim()).filter(Boolean); argv = argv.slice(2); }
      if (argv[0] === '--') argv = argv.slice(1);
      const [command, ...args] = argv;
      if (!command) fail('Usage: lllanyard exec <command> [args...]   e.g.  lllanyard exec pwsh -File ./Deploy-App.ps1 -DryRun\n       lllanyard exec --keys github,sendgrid -- <command> [args...]   to name the keys yourself');
      const keys = store();
      // The script being run: the file after an interpreter (python3 x.py, pwsh -File x.ps1), or the command itself.
      let script: string | null = null;
      try { script = scriptOf({ command, args: args.map((a) => (a.startsWith('-') ? a : path.resolve(a))) }); } catch { /* not a plain script run */ }
      // A command given as a path counts only if it's a text script (./sync.sh), not a program (/usr/bin/env).
      if (!script && /[\\/]/.test(command)) {
        try { if (statSync(command).isFile() && !readFileSync(command).subarray(0, 4096).includes(0)) script = path.resolve(command); } catch { /* not a file */ }
      }
      let env: Record<string, string>;
      if (only) env = bindingsForKeys(only, keys);
      else {
        if (!script) fail(`Can't tell which keys "${command}" needs (it isn't a script file). Name them: lllanyard exec --keys github,sendgrid -- ${command} ...`);
        const all = bindingsForAllKeys(keys);
        const { needed, files } = neededEnv(script!, Object.keys(all));
        env = Object.fromEntries(needed.map((n) => [n, all[n]!]));
        const shown = files.map((f) => path.basename(f));
        process.stderr.write(`lllanyard: giving ${needed.length ? needed.join(', ') : 'no keys'} (checked ${shown.slice(0, 4).join(', ')}${shown.length > 4 ? ` +${shown.length - 4} more` : ''})\n`);
      }
      const what = path.basename(command) + (script && path.resolve(command) !== script ? ` ${path.basename(script)}` : '');
      createUsageLog().write({ ts: new Date().toISOString(), event: 'exec', tool: what, cwd: process.cwd(), keys: Object.keys(env) });
      process.exitCode = await runTool({ command, args, env, scrub: true, inheritEnv: true }, { store: keys });
      return;
    }
    case 'run': {
      const keys = store();
      const name = pos[0];
      if (name) {
        const t = new ToolStore().get(name) ?? fail(`No approved tool "${name}". See: lllanyard tool list`);
        if (tail.length && !t.allowArgs) fail(`Tool "${t.name}" does not accept extra arguments. To allow them, approve it again with --allow-args.`);
        if (tail.length > 100 || tail.some((a) => a.length > 1000 || a.includes('\0'))) fail('Too many or too long extra arguments.');
        process.exitCode = await runTool({ ...t, args: [...t.args, ...tail] }, { store: keys, egress: await maybeEgress(t.name, t.allowHosts, t.sandbox) });
        return;
      }
      // One-off mode: injecting keys into an arbitrary command is exactly what a hijacked agent would ask for,
      // so it needs a human at a terminal and is refused when run non-interactively.
      const [command, ...args] = tail;
      const env = parseBindings(multi.env);
      if (!command || !Object.keys(env).length) fail('Usage: lllanyard run <approved-tool>   or   lllanyard run --env VAR=provider -- <command> [args...]');
      const ok = await confirm(`Give ${Object.values(env).join(', ')} to \`${[command, ...args].join(' ')}\`? [y/N] `);
      if (!ok) fail('Not confirmed (one-off runs need an interactive terminal). To allow this command permanently: lllanyard tool add');
      const hosts = multi['allow-host'];
      process.exitCode = await runTool(
        { command, args, env, scrub: !flags['no-scrub'], killOnLeak: Boolean(flags['kill-on-leak']), inheritEnv: Boolean(flags['inherit-env']), passEnv: multi['pass-env'], allowHosts: hosts, sandbox: Boolean(flags.sandbox), shareRo: multi['share-ro'], shareRw: multi['share-rw'] },
        { store: keys, egress: await maybeEgress(command, hosts, Boolean(flags.sandbox)) }
      );
      return;
    }
    case 'start': {
      autoRefreshLicense();
      const port = str(flags.port) ? Number(flags.port) : undefined;
      const s = await startProxy({ port });
      out(`${APP_NAME} proxy on http://127.0.0.1:${s.port} (loopback only). JSON request log on stdout. Ctrl+C to stop.`);
      process.on('SIGINT', () => { s.close(); process.exit(0); });
      return;
    }
    case 'ui': {
      autoRefreshLicense();
      const ui = await startUi({ port: str(flags.port) ? Number(str(flags.port)) : 0, proxyPort: Number(process.env.LLLANYARD_PORT ?? DEFAULT_PORT), launch: launch() });
      if (flags['print-url']) out(ui.url); // used by the desktop app
      else out(`${APP_NAME} is running. Open this private link (it works only for you, on this computer):\n\n  ${ui.url}\n`);
      if (!flags['no-open']) openBrowser(ui.url);
      process.on('SIGINT', () => { ui.close(); process.exit(0); });
      process.on('SIGTERM', () => { ui.close(); process.exit(0); });
      return;
    }
    case 'mcp': {
      // stdout is the protocol channel: nothing else may be printed to it.
      const base = `http://127.0.0.1:${process.env.LLLANYARD_PORT ?? DEFAULT_PORT}`;
      const ks = new KeyringStore();
      const timeout = str(flags.timeout) ? Number(str(flags.timeout)) : 600;
      if (!Number.isFinite(timeout) || timeout <= 0) fail('--timeout is a number of seconds, e.g. --timeout 600');
      if (multi['scripts-dir'] && !flags.run) fail('--scripts-dir needs --run.');
      const scriptDirs = resolveScriptDirs(multi['scripts-dir'] ?? []);
      // One dialog at a time: requests queue rather than stacking dialogs on top of each other.
      let queue: Promise<unknown> = Promise.resolve();
      const handler = createMcpHandler({
        listKeys: () => ks.list(),
        providerIds: () => Object.keys(allProviders(new ProviderStore())),
        usage: (since) => summarize(readUsage(usageLogPath(), since), since),
        proxyBase: base, client: str(flags.client),
        runner: flags.run ? {
          // Read on every call, so tools approved while the app is open show up without restarting it.
          list: () => new ToolStore().list().map((t) => ({
            name: t.name, runs: [path.basename(t.command), ...t.args.map((a) => (path.isAbsolute(a) ? path.basename(a) : a))].join(' '),
            keys: Object.keys(t.env), acceptsArgs: Boolean(t.allowArgs), sandbox: Boolean(t.sandbox),
          })),
          run: (name, args) => runForMcp(new ToolStore().get(name) ?? fail(`No approved tool "${name}".`), args, ks, timeout),
          scriptDirs,
          runFile: (file, args) => {
            const next = queue.then(async () => {
              const plan = planScriptRun(file, args, scriptDirs, bindingsForAllKeys(ks), { pathVar: process.env.PATH });
              const allowed = await confirmDialog(describePlan(plan, args));
              createUsageLog().write({ ts: new Date().toISOString(), event: 'mcp-file', tool: plan.script, decision: allowed ? 'allow' : 'deny', keys: Object.keys(plan.env) });
              if (!allowed) return null;
              const { script, helpers, modifiedRecently, ...def } = plan;
              return runForMcp({ name: path.basename(script), ...def, scrub: true }, [], ks, timeout);
            });
            queue = next.catch(() => {});
            return next;
          },
        } : undefined,
      });
      process.stderr.write(`${APP_NAME} MCP server (${flags.run ? `runs approved tools${scriptDirs.length ? ` and, after a dialog, scripts in ${scriptDirs.join(', ')}` : ''}` : 'read-only'}, never reveals keys) on stdio${flags.client ? `, client "${str(flags.client)}"` : ''}.\n`);
      await serveMcpStdio(handler, process.stdin, process.stdout);
      return;
    }
    case 'serve': {
      const host = str(flags.host) ?? fail('Usage: lllanyard serve --host 0.0.0.0 --port 3443 --tls-cert cert.pem --tls-key key.pem --allow-host keys.example.com');
      const certFile = str(flags['tls-cert']), keyFile = str(flags['tls-key']);
      let tls: { cert: Buffer; key: Buffer } | undefined;
      if (certFile && keyFile) {
        if (process.platform !== 'win32' && (statSync(keyFile).mode & 0o077) !== 0) fail(`TLS key ${keyFile} is readable by other users. Fix with: chmod 600 ${keyFile}`);
        tls = { cert: readFileSync(certFile), key: readFileSync(keyFile) };
      }
      const allowed = multi['allow-host']?.map((h) => h.toLowerCase());
      const port = str(flags.port) ? Number(str(flags.port)) : 3443;
      const s = await startProxy({ port, host, tls, allowedHosts: allowed });
      out(`${APP_NAME} shared proxy on ${tls ? 'https' : 'http'}://${host}:${s.port}  (hosts: ${allowed?.join(', ') ?? 'loopback'}). Keys stay in this computer's keychain.`);
      out(`Other devices use: base URL https://${allowed?.[0] ?? host}:${s.port}/openai/v1 with their own agent token as the API key.`);
      out('Create a token per AI tool: lllanyard agent create laptop-claude-code --client acme --expires 90d');
      if (new LicenseStore().status().tier === 'pro') out('Pro covers your own devices. To share this proxy with other people, they need Team seats.');
      process.on('SIGINT', () => { s.close(); process.exit(0); });
      return;
    }
    case 'usage': {
      const now = Date.now();
      const since = parseSince(str(flags.since) ?? '7d', now);
      const sum = summarize(readUsage(usageLogPath(), since), since, now);
      if (flags.json) return out(JSON.stringify(sum, null, 2));
      out(`Usage since ${new Date(since).toISOString().slice(0, 16).replace('T', ' ')} UTC (from ${usageLogPath()})`);
      out(`Requests ${sum.requests}   errors ${sum.errors}   rate-limited ${sum.rateLimited}   kill-switch trips ${sum.killSwitch}   blocked ${sum.denied}`);
      const table = (title: string, rows: Row[]) => {
        if (!rows.length) return;
        out(`\n${title}`);
        for (const r of rows.slice(0, 15)) out(`  ${r.name.padEnd(22).slice(0, 22)} ${String(r.requests).padStart(7)} req  ${String(r.errors).padStart(4)} err  ${String(r.rateLimited).padStart(4)} 429  p50 ${r.p50}ms  p95 ${r.p95}ms`);
      };
      table('By provider', sum.byProvider); table('By agent', sum.byAgent); table('By client', sum.byClient);
      for (const e of sum.egressDenied.slice(0, 10)) out(`  blocked egress: ${e.tool} -> ${e.host} x${e.count}`);
      if (sum.scriptRuns.length) out('\nScripts run with your keys (lllanyard exec)');
      for (const r of sum.scriptRuns) out(`  ${r.tool.padEnd(22).slice(0, 22)} ${String(r.count).padStart(5)}x  last ${r.last.slice(0, 16).replace('T', ' ')} UTC`);
      if (!sum.requests && !sum.scriptRuns.length) out('\nNo requests recorded yet. Start the proxy with: lllanyard start');
      return out('\nVisual dashboard (Pro): lllanyard dashboard');
    }
    case 'dashboard': {
      const lic = new LicenseStore().status();
      if (lic.tier === 'free') fail('The visual dashboard is a Pro feature. See: lllanyard license activate  (the text report is free: lllanyard usage)');
      const now = Date.now();
      const since = parseSince(str(flags.since) ?? '30d', now);
      const html = renderDashboard(summarize(readUsage(usageLogPath(), since), since, now), lic.tier);
      const file = path.resolve(str(flags.out) ?? path.join(os.homedir(), '.lllanyard', 'dashboard.html'));
      mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      writeFileSync(file, html, { mode: 0o600 });
      return out(`Dashboard written to ${file}. Open it in your browser (it is self-contained and makes no network requests).`);
    }
    case 'license': {
      const [sub] = pos;
      const ls = new LicenseStore();
      if (sub === 'activate') {
        const token = flags.stdin ? (await readStdin()).trim() : str(flags.key) ?? pos[1] ?? fail('Usage: lllanyard license activate <license>   (or --key <license>, or --stdin)');
        const p = ls.activate(token);
        return out(`License active: ${p.tier}, ${p.seats} seat(s), valid until ${new Date(p.exp * 1000).toISOString().slice(0, 10)}.`);
      }
      if (sub === 'remove') { ls.remove(); return out('License removed. Back to the free tier (existing keys keep working).'); }
      if (sub === 'refresh') {
        const r = await refreshLicense(ls);
        if (r.kind === 'renewed') return out(`Renewed: ${r.payload.tier}, ${r.payload.seats} seat(s), valid until ${new Date(r.payload.exp * 1000).toISOString().slice(0, 10)}.`);
        if (r.kind === 'current') return out(r.message);
        if (r.kind === 'none') return out('No license from lllanyard.app is stored, so there is nothing to refresh.');
        return fail(r.message);
      }
      if (sub === 'status' || !sub) {
        const st = ls.status();
        out(st.payload ? `Tier: ${st.tier} (${st.payload.seats} seat(s), until ${new Date(st.payload.exp * 1000).toISOString().slice(0, 10)}). Key limit: ${ls.limits().maxKeys}.` : `Tier: free. Key limit: ${ls.limits().maxKeys}.`);
        if (st.problem) out(`Note: stored license not applied: ${st.problem}`);
        return;
      }
      return fail('Usage: lllanyard license activate|status|refresh|remove');
    }
    case 'backup': {
      const file = path.resolve(str(flags.out) ?? path.join(os.homedir(), `lllanyard-backup-${new Date().toISOString().slice(0, 19).replace(/[-:]/g, '').replace('T', '-')}.enc`));
      const pass = await backupPassphrase(str(flags['passphrase-file']), true);
      const { text, items } = createBackup(pass);
      if (!items.length) fail('Nothing to back up yet.');
      mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      try { writeFileSync(file, text, { mode: 0o600, flag: 'wx' }); }
      catch (e: any) { fail(e.code === 'EEXIST' ? `${file} already exists; choose another --out.` : e.message); }
      out(`Backed up ${items.length} item(s) to ${file}:`);
      for (const it of items) out(`  ${describeItem(it)}`);
      return out('\nThe file holds your keys, encrypted with the passphrase. Keep both safe and separate: without the passphrase it cannot be restored.');
    }
    case 'restore': {
      const file = pos[0] ?? fail('Usage: lllanyard restore <file> [--overwrite] [--dry-run]');
      const payload = readBackup(readFileSync(file, 'utf8'), await backupPassphrase(str(flags['passphrase-file']), false));
      const dry = Boolean(flags['dry-run']);
      const r = restoreBackup(payload, undefined, { overwrite: Boolean(flags.overwrite), dryRun: dry, maxKeys: new LicenseStore().limits().maxKeys });
      out(`Backup from ${payload.createdAt.slice(0, 16).replace('T', ' ')} UTC${dry ? ' (dry run: nothing written)' : ''}:`);
      for (const it of r.added) out(`  ${dry ? 'would add    ' : 'added        '} ${describeItem(it)}`);
      for (const it of r.replaced) out(`  ${dry ? 'would replace' : 'replaced     '} ${describeItem(it)}`);
      for (const it of r.kept) out(`  kept current  ${describeItem(it)}`);
      for (const { item, reason } of r.invalid) out(`  SKIPPED       ${describeItem(item)}: ${reason}`);
      if (r.kept.length) out(`\n${r.kept.length} item(s) already exist and were left as they are. Use --overwrite to replace them with the backup's copy.`);
      if (r.invalid.length) process.exitCode = 1;
      return;
    }
    case 'setup': {
      const app = pos[0];
      if (!app) {
        const d = claudeDesktopStatus(), c = claudeCodeStatus();
        out(`Claude Desktop  ${d.connected ? `connected${d.scriptDirs.length ? `; scripts in ${d.scriptDirs.join(', ')} run after a dialog` : ''}` : 'not connected'}   (${d.file})`);
        if (d.problem) out(`                ${d.problem}`);
        out(`Claude Code     ${c.connected ? 'connected' : 'not connected'}   (${c.file})`);
        return out('\nConnect with: lllanyard setup claude-desktop [--scripts-dir DIR]   or   lllanyard setup claude-code');
      }
      if (app === 'claude-desktop') {
        // Claude Desktop saves its settings over ours when it quits, so change them only while it's closed.
        let restart = Boolean(flags.restart);
        if (!restart && claudeDesktopRunning() && canRestartClaudeDesktop())
          restart = await confirm('Claude Desktop is open. It rewrites its settings when it quits, which would undo this. Quit it, make the change and reopen it? [y/N] ');
        if (flags.remove) {
          const { result: r, restarted } = await withClaudeDesktopClosed(() => disconnectClaudeDesktop(), { restart });
          return out(r.removed ? `Removed LLLanyard from ${r.file} (old file kept as ${r.backup}).${restarted ? ' Claude Desktop was restarted.' : ''}` : 'Claude Desktop was not connected.');
        }
        const scriptDirs = multi['scripts-dir'] ?? [];
        const { result: r, restarted } = await withClaudeDesktopClosed(() => connectClaudeDesktop(launch(), scriptDirs), { restart });
        out(`Connected Claude Desktop: ${r.file}${r.backup ? ` (old file kept as ${r.backup})` : ''}.`);
        out(r.scriptDirs.length ? `Claude can run your approved tools, and any script in ${r.scriptDirs.join(', ')} after you click Run in a dialog.` : 'Claude can run your approved tools (lllanyard tool add). Add --scripts-dir DIR to let it run scripts from a folder, with a dialog each time.');
        return out(restarted ? 'Claude Desktop was restarted and has loaded it.' : 'Open Claude Desktop to use it.');
      }
      if (app === 'claude-code') {
        if (flags.remove) { const r = disconnectClaudeCode(); return out(r.removed ? `Removed the LLLanyard section from ${r.file}.` : 'Claude Code was not connected.'); }
        const r = connectClaudeCode();
        return out(`Claude Code will use lllanyard exec for keys: added to ${r.file}${r.backup ? ` (old file kept as ${r.backup})` : ''}. New sessions pick it up.`);
      }
      return fail('Usage: lllanyard setup [claude-desktop [--scripts-dir DIR] | claude-code] [--remove]');
    }
    case 'doctor': {
      const b = backendKind() === 'file' ? defaultBackend() : new KeyringBackend();
      b.set('__doctor__', 'ok');
      const ok = b.get('__doctor__') === 'ok';
      b.delete('__doctor__');
      out(ok ? `OK: ${backendKind() === 'file' ? 'encrypted file vault' : 'OS keychain'} is usable on ${process.platform}.` : 'FAILED: keychain read-back mismatch.');
      const sb = sandboxSelfTest();
      return out(sb.ok ? `OK: tool sandbox works (${sb.kind}). Use --sandbox on tools.` : `Sandbox not available: ${sb.reason}`);
    }
    default:
      return fail(`Unknown command "${cmd}". Try: lllanyard help`);
  }
}

/** Backup passphrase: from a chmod 600 file (scripts), else a hidden prompt (asked twice when creating). */
/** How an app should start this CLI: this Node and this file, by absolute path, with the PATH it was set up from. */
function launch(): Launch {
  const pathVar = process.env.PATH ?? '';
  return { node: stableNodePath(process.execPath, pathVar), cli: fileURLToPath(import.meta.url), pathVar };
}

/**
 * Runs an approved tool for the MCP server: no input (stdin is the protocol channel), output captured and returned rather
 * than printed (stdout is the protocol channel too), a time limit, and each run logged like `exec`.
 */
async function runForMcp(t: ToolDef, extra: string[], keys: KeyringStore, timeoutSec: number): Promise<RunResult> {
  const LIMIT = 100_000;
  let output = '', dropped = false;
  const capture = () => new Writable({ write(chunk, _enc, done) {
    output += String(chunk);
    if (output.length > LIMIT) { output = output.slice(-LIMIT); dropped = true; }
    done();
  } });
  // Scripts run from their own folder; anything else from an empty temp folder (never the app's own working directory).
  const script = scriptOf(t);
  const tmp = script ? undefined : mkdtempSync(path.join(os.tmpdir(), 'lllanyard-mcp-'));
  const ac = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; ac.abort(); }, timeoutSec * 1000);
  createUsageLog().write({ ts: new Date().toISOString(), event: 'exec', tool: `mcp ${t.name}`, cwd: script ? path.dirname(script) : tmp, keys: Object.keys(t.env) });
  try {
    const exitCode = await runTool({ ...t, args: [...t.args, ...extra] }, {
      store: keys, stdout: capture(), stderr: capture(), noStdin: true, tty: false, signal: ac.signal,
      cwd: script ? path.dirname(script) : tmp, egress: await maybeEgress(t.name, t.allowHosts, t.sandbox),
    });
    return { exitCode, output, truncated: dropped, timedOut };
  } finally {
    clearTimeout(timer);
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  }
}

async function backupPassphrase(file: string | undefined, creating: boolean): Promise<string> {
  if (file) {
    if (process.platform !== 'win32' && (statSync(file).mode & 0o077) !== 0) fail(`Passphrase file ${file} is readable by other users. Fix with: chmod 600 ${file}`);
    return readFileSync(file, 'utf8').replace(/\r?\n$/, '');
  }
  if (!process.stdin.isTTY) fail('Backups need a passphrase: run in a terminal, or pass --passphrase-file F (a chmod 600 file).');
  const p1 = await readSecret(creating ? `Choose a backup passphrase (min ${MIN_PASSPHRASE} characters, input hidden): ` : 'Backup passphrase (input hidden): ');
  if (creating) {
    if (p1.length < MIN_PASSPHRASE) fail(`Passphrase must be at least ${MIN_PASSPHRASE} characters.`);
    if ((await readSecret('Repeat passphrase: ')) !== p1) fail('Passphrases did not match.');
  }
  return p1;
}

async function importFindings(findings: Finding[], store: KeyringStore, apply: boolean, redact: boolean) {
  if (redact && !apply) fail('--redact requires --import --apply.');
  const existing = new Set(store.list().map((m) => `${m.provider}\0${store.get(m.provider, m.label)}`));
  const plan = new Map<string, Finding>();
  for (const f of findings) {
    if (f.importable && !existing.has(`${f.provider}\0${f.reveal()}`)) plan.set(f.reveal(), plan.get(f.reveal()) ?? f);
  }
  if (!plan.size) return out('\nNothing new to import.');
  out(`\n${apply ? 'Importing' : 'Would import'} ${plan.size} key(s):`);
  const used = new Set(store.list().map((m) => m.id));
  for (const [secret, f] of plan) {
    const lbl = used.has(`${f.provider}:default`) ? `imported-${secret.slice(-4).toLowerCase()}` : 'default';
    used.add(`${f.provider}:${lbl}`);
    out(`  ${f.provider}:${lbl}  ${f.masked}`);
    if (!apply) continue;
    store.set(f.provider, secret, { label: lbl });
    if (store.get(f.provider, lbl) !== secret) fail('Read-back check failed; stopping before touching any file.');
    if (redact) {
      for (const file of new Set(findings.filter((x) => x.reveal() === secret).map((x) => x.file))) {
        out(`    redacted ${await redactFile(file, [secret])}x in ${file}`);
      }
    }
  }
  if (!apply) return out('\nDry run only. Add --apply to import (and --redact to blank the keys out of those files).');
  out('\nImportant: these keys sat in plaintext, so treat them as exposed. Create new ones at the provider,');
  out('then run "lllanyard rotate <provider>" and revoke the old key.');
}

main().catch((e: Error) => {
  process.stderr.write(`Error: ${e.message}\n`);
  if (process.env.LLLANYARD_DEBUG) process.stderr.write(`${e.stack}\n`);
  process.exit(1);
});

/** In the last week of a paid license, fetch its renewed key in the background (LLLANYARD_NO_LICENSE_REFRESH=1 turns this off). */
function autoRefreshLicense() {
  const ls = new LicenseStore();
  if (!refreshDue(ls)) return;
  void refreshLicense(ls).then((r) => {
    if (r.kind === 'renewed') process.stderr.write(`License renewed: valid until ${new Date(r.payload.exp * 1000).toISOString().slice(0, 10)}.\n`);
    else if (r.kind === 'failed') process.stderr.write(`License renewal check: ${r.message} Run lllanyard license refresh later.\n`);
  }).catch(() => {});
}
