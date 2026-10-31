import { defaultBackend, type SecretBackend } from './storage/backend.js';
import { createHash } from 'node:crypto';
import { accessSync, constants as fsc, readdirSync, readFileSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { assertSafeMount } from './sandbox.js';
import { assertName, StoreError } from './storage/keyring-store.js';
import type { SecureStore } from './storage/types.js';

export interface ToolDef {
  name: string;
  command: string; // pinned at "tool add" time (absolute path where possible)
  args: string[];
  env: Record<string, string>; // ENV_VAR -> key reference ("provider" or "provider:label")
  scrub: boolean; // redact injected secrets from the tool's stdout/stderr
  allowHosts?: string[]; // egress allowlist (best-effort, via a local proxy); omitted = network unrestricted
  killOnLeak?: boolean; // stop the tool the first time it prints its key
  inheritEnv?: boolean; // pass the whole parent environment (default: a minimal one)
  passEnv?: string[]; // extra environment variables to pass through from the parent
  sandbox?: boolean; // run inside an OS sandbox (Linux bubblewrap / macOS Seatbelt); fails closed if unavailable
  shareRo?: string[]; // extra read-only folders the sandboxed tool may see
  shareRw?: string[]; // extra writable folders the sandboxed tool may use (the working directory is always writable)
  allowArgs?: boolean; // `run <name> -- args` appends args after the stored ones (only for a pinned script, see scriptOf)
  scriptSha256?: string; // the script file's hash at approval; run refuses if the file has changed since
  pins?: Record<string, string>; // more files the tool loads (absolute path -> SHA-256); run refuses if any changed
}

// Interpreters run whatever code their arguments name, so for these the stored args must start with a script file.
const INTERPRETERS = /^(python[0-9.]*|node|nodejs|deno|bun|ruby|perl|php|bash|sh|zsh|dash|fish|pwsh|powershell|osascript|tsx)(\.exe)?$/i;
// Programs whose arguments name another program to run.
const LAUNCHERS = /^(env|xargs|sudo|doas|su|nohup|nice|time|timeout|caffeinate|exec|command|open|cmd|start|npx|uv|uvx|pipx|find|ssh)(\.exe)?$/i;
// Interpreter options allowed before the script path: none of them run code or take a value. Per family, because the
// same letter differs (bash -s reads commands from stdin; node/perl/ruby -e run code).
const SAFE_FLAGS: [RegExp, Set<string>][] = [
  [/^python/i, new Set(['-u', '-B', '-E', '-I', '-s', '-S', '-O', '-OO'])],
  [/^(pwsh|powershell)/i, new Set(['-NoProfile', '-NonInteractive', '-NoLogo', '-File'])],
];
const safeFlags = (command: string) => SAFE_FLAGS.find(([re]) => re.test(path.basename(command)))?.[1] ?? new Set<string>();
const scriptIndex = (command: string, args: string[]) => { const ok = safeFlags(command); return args.findIndex((a) => !ok.has(a)); };

/**
 * The script a tool runs, if its command is an interpreter: the first stored arg that isn't one of its SAFE_FLAGS.
 * Returns null for a non-interpreter command; throws if an interpreter is given code (-c, -m, ...) instead of a file.
 */
export function scriptOf(t: Pick<ToolDef, 'command' | 'args'>): string | null {
  if (!INTERPRETERS.test(path.basename(t.command))) return null;
  const i = scriptIndex(t.command, t.args);
  const s = i >= 0 ? t.args[i]! : undefined;
  if (!s || s.startsWith('-')) throw new StoreError(`"${path.basename(t.command)}" must be given a script file before any other arguments (options like ${s ?? '-c'} are not allowed).`);
  if (!path.isAbsolute(s)) throw new StoreError(`Script path "${s}" must be absolute.`);
  return s;
}

/**
 * Finds a command on PATH so a stored tool is pinned to one binary (blocks PATH-swap tricks later). Symlinks are kept,
 * not resolved, so a Homebrew upgrade (which moves the real file) doesn't break approved tools.
 */
export function findCommand(cmd: string, pathVar = process.env.PATH ?? '', platform = process.platform): string {
  if (cmd.includes('/') || cmd.includes('\\')) return path.resolve(cmd);
  const exts = platform === 'win32' ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';') : [''];
  for (const dir of pathVar.split(path.delimiter).filter(Boolean)) {
    for (const ext of exts) {
      const full = path.join(dir, cmd + (cmd.toLowerCase().endsWith(ext.toLowerCase()) ? '' : ext));
      try { if (statSync(full).isFile()) { accessSync(full, fsc.X_OK); return full; } } catch { /* next */ }
    }
  }
  throw new StoreError(`Command "${cmd}" was not found on PATH. Install it first, or give its full path.`);
}

export const fileSha256 = (file: string) => createHash('sha256').update(readFileSync(file)).digest('hex');

/**
 * Turns key references ("github", "jira:secret") into env bindings using each key's own variable name, so a tool
 * can be approved with just the keys it needs. Fails if a key isn't stored or has no variable name yet.
 */
export function bindingsForKeys(refs: string[], keys: Pick<SecureStore, 'list'>): Record<string, string> {
  const all = keys.list();
  const env: Record<string, string> = {};
  for (const ref of refs) {
    const { provider, label } = parseKeyRef(ref);
    const m = all.find((k) => k.provider === provider && k.label === label);
    if (!m) throw new StoreError(`No ${provider}:${label} key stored.`);
    if (!m.envName) throw new StoreError(`Key ${provider}:${label} has no variable name yet. Set one with: lllanyard env ${provider}${label === 'default' ? '' : ':' + label} VARIABLE_NAME`);
    if (env[m.envName]) throw new StoreError(`Two keys both use the variable ${m.envName}.`);
    env[m.envName] = label === 'default' ? provider : `${provider}:${label}`;
  }
  return env;
}

/**
 * Which of `names` a script uses: searches the script, then any script file in its folder that it (or a file found this
 * way) refers to in its code (not comments): a quoted path, a `source`/`.` line, or a Python import. A variable counts when its name appears as a whole word,
 * e.g. GITHUB_TOKEN in `$env:GITHUB_TOKEN`, `os.environ["GITHUB_TOKEN"]` or `'GITHUB_TOKEN'`.
 */
const SCRIPT_EXT = /\.(ps1|psm1|py|sh|bash|zsh|js|mjs|cjs|ts|rb|pl)$/i;
export function neededEnv(script: string, names: string[]): { needed: string[]; files: string[] } {
  const dir = path.dirname(script);
  let siblings: string[] = [];
  try { siblings = readdirSync(dir).filter((f) => SCRIPT_EXT.test(f)).filter((f) => { try { const st = statSync(path.join(dir, f)); return st.isFile() && st.size <= 2_000_000; } catch { return false; } }).slice(0, 500); }
  catch { /* unreadable folder: just the script */ }
  const read = (f: string) => { try { return readFileSync(f, 'utf8'); } catch { return ''; } };
  const esc = (t: string) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const word = (w: string) => new RegExp(`(?<![A-Za-z0-9_])${esc(w)}(?![A-Za-z0-9_])`);
  const seen = new Set<string>(), queue = [path.resolve(script)], needed = new Set<string>();
  while (queue.length && seen.size < 50) {
    const f = queue.shift()!;
    if (seen.has(f)) continue;
    seen.add(f);
    const text = read(f);
    for (const n of names) if (!needed.has(n) && word(n).test(text)) needed.add(n);
    const code = text.replace(/<#[\s\S]*?#>/g, '').replace(/(^|\s)#.*$/gm, '$1'); // drop PowerShell/shell/Python comments
    for (const sib of siblings) {
      const full = path.join(dir, sib);
      if (seen.has(full)) continue;
      const stem = sib.replace(/\.py$/, '');
      // A real reference: a quoted path ending in the file ('Common.ps1', "$DIR/common.sh"), a `source`/`.` line, or a
      // Python import. A name inside a sentence ("run Deploy-App.ps1 first") is not one.
      const refs = [`['"/\\\\]${esc(sib)}['"]`, `^\\s*(source|\\.)\\s+\\S*${esc(sib)}\\b`, ...(sib.endsWith('.py') ? [`^\\s*(from|import)\\s+${esc(stem)}\\b`] : [])];
      if (refs.some((r) => new RegExp(r, 'm').test(code))) queue.push(full);
    }
  }
  return { needed: names.filter((n) => needed.has(n)), files: [...seen] };
}

/** Every stored key that has a variable name, as env bindings: what `lllanyard exec` gives a command. */
export function bindingsForAllKeys(keys: Pick<SecureStore, 'list'>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const m of keys.list()) if (m.envName && !env[m.envName]) env[m.envName] = m.label === 'default' ? m.provider : `${m.provider}:${m.label}`;
  return env;
}

/** At approval: hashes extra files a tool depends on (e.g. a helper it dot-sources), resolved from cwd. */
export function pinFiles(files: string[], cwd = process.cwd()): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of files) {
    const abs = path.resolve(cwd, f);
    try { out[abs] = fileSha256(abs); } catch { throw new StoreError(`File to pin ${abs} was not found or can't be read.`); }
  }
  return out;
}

/** Files of a tool that have changed (or vanished) since approval: its script and any extra pins. */
export function changedPins(t: Pick<ToolDef, 'command' | 'args' | 'scriptSha256' | 'pins'>): string[] {
  const want: [string, string][] = Object.entries(t.pins ?? {});
  if (t.scriptSha256) want.unshift([scriptOf(t) ?? '(script)', t.scriptSha256]);
  return want.filter(([f, sha]) => { try { return fileSha256(f) !== sha; } catch { return true; } }).map(([f]) => f);
}

/** At approval: for an interpreter tool, makes the script path absolute and returns its hash to pin. Other tools pass through. */
export function pinScript(command: string, args: string[], cwd = process.cwd()): { args: string[]; scriptSha256?: string } {
  if (!INTERPRETERS.test(path.basename(command))) return { args };
  const i = scriptIndex(command, args);
  if (i < 0 || args[i]!.startsWith('-')) return { args };
  const abs = path.resolve(cwd, args[i]!);
  let sha: string;
  try { sha = fileSha256(abs); } catch { throw new StoreError(`Script ${abs} was not found or can't be read.`); }
  const out = [...args];
  out[i] = abs;
  return { args: out, scriptSha256: sha };
}

const ENV_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const BLOCKED_ENV = /^(LD_|DYLD_)/i;
const BLOCKED_ENV_NAMES = new Set(['PATH', 'PATHEXT', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH', 'PYTHONSTARTUP', 'BASH_ENV', 'ENV', 'IFS', 'SHELL', 'HOME', 'USERPROFILE']);

export function parseKeyRef(ref: string): { provider: string; label: string } {
  const [provider, label = 'default', ...extra] = ref.split(':');
  if (!provider || extra.length) throw new StoreError(`Bad key reference "${ref}" (use provider or provider:label).`);
  assertName('provider', provider);
  assertName('label', label);
  return { provider: provider.toLowerCase(), label: label.toLowerCase() };
}

export function assertEnvName(name: string) {
  if (!ENV_RE.test(name)) throw new StoreError(`Invalid environment variable name "${name}".`);
  if (BLOCKED_ENV.test(name) || BLOCKED_ENV_NAMES.has(name.toUpperCase()))
    throw new StoreError(`Refusing to inject a key into "${name}" (it can change how programs load code).`);
}

const HOST_RE = /^(\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
export function assertAllowedHost(h: string): string {
  const v = h.trim().toLowerCase();
  if (v.length > 253 || !HOST_RE.test(v)) throw new StoreError(`Invalid host "${h}" (use api.example.com or *.example.com; no IP addresses, ports or paths).`);
  return v;
}

export function validateTool(t: ToolDef): ToolDef {
  assertName('tool name', t.name);
  if (typeof t.command !== 'string' || !t.command || t.command.length > 400 || /[\0\r\n]/.test(t.command)) throw new StoreError('Invalid command.');
  if (!Array.isArray(t.args) || t.args.some((a) => typeof a !== 'string' || a.length > 1000 || a.includes('\0'))) throw new StoreError('Invalid command arguments.');
  const entries = Object.entries(t.env ?? {});
  if (!entries.length) throw new StoreError('A tool needs at least one key (--keys github,... or --env VAR=provider).');
  const env: Record<string, string> = {};
  for (const [k, ref] of entries) {
    assertEnvName(k);
    const r = parseKeyRef(ref);
    env[k] = r.label === 'default' ? r.provider : `${r.provider}:${r.label}`;
  }
  const out: ToolDef = { name: t.name.toLowerCase(), command: t.command, args: t.args, env, scrub: t.scrub !== false };
  if (t.allowHosts?.length) {
    if (t.allowHosts.length > 20) throw new StoreError('At most 20 allowed hosts per tool.');
    out.allowHosts = [...new Set(t.allowHosts.map(assertAllowedHost))];
  }
  if (t.passEnv?.length) {
    if (t.passEnv.length > 20) throw new StoreError('At most 20 pass-through variables per tool.');
    t.passEnv.forEach(assertEnvName);
    out.passEnv = [...new Set(t.passEnv)];
  }
  if (t.sandbox) out.sandbox = true;
  for (const key of ['shareRo', 'shareRw'] as const) {
    const v = t[key];
    if (!v?.length) continue;
    if (!t.sandbox) throw new StoreError('Shared folders only apply with --sandbox.');
    if (v.length > 5) throw new StoreError('At most 5 shared folders of each kind.');
    out[key] = [...new Set(v.map((p) => assertSafeMount(p, os.homedir(), 'shared folder')))];
  }
  if (t.killOnLeak) out.killOnLeak = true;
  if (t.inheritEnv) out.inheritEnv = true;
  // Extra args must reach a fixed program, never choose one: a bare interpreter + args = run any code with the keys.
  if (t.allowArgs) {
    if (LAUNCHERS.test(path.basename(out.command))) throw new StoreError(`--allow-args is not allowed for "${path.basename(out.command)}": its arguments choose which program runs.`);
    scriptOf(out);
    out.allowArgs = true;
  }
  if (t.pins !== undefined) {
    const e = Object.entries(t.pins);
    if (e.length > 10) throw new StoreError('At most 10 pinned files per tool.');
    for (const [f, sha] of e) if (!path.isAbsolute(f) || f.length > 400 || f.includes('\0') || !/^[0-9a-f]{64}$/.test(sha)) throw new StoreError('Invalid pinned file.');
    if (e.length) out.pins = { ...t.pins };
  }
  if (t.scriptSha256 !== undefined) {
    if (!scriptOf(out) || !/^[0-9a-f]{64}$/.test(t.scriptSha256)) throw new StoreError('Invalid script hash.');
    out.scriptSha256 = t.scriptSha256;
  }
  if (Buffer.byteLength(JSON.stringify(out)) > 2000) throw new StoreError('Tool definition too large for the OS keychain (limit ~2 KB).');
  return out;
}

const INDEX = '__tools__';

/**
 * Approved tools are stored in the keychain. `lllanyard run <name>` only ever executes the stored command with
 * the stored bindings, so editing an MCP config file can't turn a key into "run anything with this key".
 */
export class ToolStore {
  constructor(private backend: SecretBackend = defaultBackend()) {}

  private names(): string[] {
    const raw = this.backend.get(INDEX);
    if (!raw) return [];
    try { const v = JSON.parse(raw); if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v; } catch { /* */ }
    throw new StoreError('Tool index is corrupted; refusing to overwrite it.');
  }

  set(t: ToolDef): ToolDef {
    const v = validateTool(t);
    const names = this.names();
    this.backend.set(`tool:${v.name}`, JSON.stringify(v));
    if (!names.includes(v.name)) this.backend.set(INDEX, JSON.stringify([...names, v.name]));
    return v;
  }

  get(name: string): ToolDef | null {
    const raw = this.backend.get(`tool:${name.toLowerCase()}`);
    if (!raw) return null;
    try { return validateTool(JSON.parse(raw)); } catch { return null; }
  }

  list(): ToolDef[] {
    return this.names().map((n) => this.get(n)).filter((t): t is ToolDef => t !== null);
  }

  remove(name: string): boolean {
    const n = name.toLowerCase();
    const existed = this.backend.delete(`tool:${n}`);
    this.backend.set(INDEX, JSON.stringify(this.names().filter((x) => x !== n)));
    return existed;
  }
}
