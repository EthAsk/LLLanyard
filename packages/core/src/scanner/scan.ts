import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface Pattern { provider: string; importable: boolean; re: RegExp }

// `importable` = LLLanyard can proxy this provider today. Others are detected for hygiene only.
export const PATTERNS: Pattern[] = [
  { provider: 'anthropic', importable: true, re: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { provider: 'openai', importable: true, re: /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-(?!ant-)[A-Za-z0-9]{32,}/g },
  { provider: 'github', importable: true, re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { provider: 'google', importable: false, re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
];

export function mask(secret: string): string {
  return secret.length <= 16 ? '****' : `${secret.slice(0, 7)}…${secret.slice(-4)}`;
}

/** A detected key. The plaintext is held privately and is excluded from JSON/inspect/log output. */
export class Finding {
  readonly #secret: string;
  constructor(
    readonly file: string,
    readonly line: number,
    readonly provider: string,
    readonly importable: boolean,
    secret: string
  ) { this.#secret = secret; }
  get masked() { return mask(this.#secret); }
  reveal() { return this.#secret; }
  toJSON() { return { file: this.file, line: this.line, provider: this.provider, importable: this.importable, masked: this.masked }; }
  [Symbol.for('nodejs.util.inspect.custom')]() { return this.toJSON(); }
}

export function scanText(text: string) {
  const hits: { line: number; provider: string; importable: boolean; secret: string }[] = [];
  text.split(/\r?\n/).forEach((l, i) => {
    if (l.length > 100_000) return;
    for (const p of PATTERNS) for (const m of l.matchAll(p.re)) hits.push({ line: i + 1, provider: p.provider, importable: p.importable, secret: m[0] });
  });
  return hits;
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.venv', 'venv', '__pycache__', 'target', '.cache']);
const EXT = new Set(['.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.properties', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.env', '.py', '.js', '.mjs', '.cjs', '.ts', '.go']);
const KNOWN = new Set(['.zshrc', '.bashrc', '.bash_profile', '.profile', '.zprofile', '.envrc', 'config.fish']);
const isCandidate = (n: string) => n.startsWith('.env') || KNOWN.has(n) || EXT.has(path.extname(n).toLowerCase());

async function* walk(dir: string, depth: number, max: number): AsyncGenerator<string> {
  let entries;
  try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.isSymbolicLink()) continue; // never follow links out of the scanned tree
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (depth < max && !SKIP_DIRS.has(e.name)) yield* walk(p, depth + 1, max); }
    else if (e.isFile() && isCandidate(e.name)) yield p;
  }
}

export interface ScanOptions { roots: string[]; maxDepth?: number; maxFileBytes?: number }

export async function scan(opts: ScanOptions): Promise<Finding[]> {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const maxBytes = opts.maxFileBytes ?? 1_000_000;
  const home = path.resolve(os.homedir());

  const scanFile = async (file: string) => {
    if (seen.has(file)) return;
    seen.add(file);
    let st;
    try { st = await fs.lstat(file); } catch { return; }
    if (!st.isFile() || st.size > maxBytes) return;
    const buf = await fs.readFile(file);
    if (buf.subarray(0, 1024).includes(0)) return; // binary
    for (const h of scanText(buf.toString('utf8'))) out.push(new Finding(file, h.line, h.provider, h.importable, h.secret));
  };

  for (const raw of opts.roots) {
    const root = path.resolve(raw);
    if (root === home) throw new Error('Refusing to scan your whole home directory. Pass specific folders.');
    let st;
    try { st = await fs.lstat(root); } catch { continue; }
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) for await (const f of walk(root, 0, opts.maxDepth ?? 6)) await scanFile(f);
    else if (st.isFile()) await scanFile(root);
  }
  return out;
}

export function defaultRoots(cwd = process.cwd(), home = os.homedir()): string[] {
  const h = (...p: string[]) => path.join(home, ...p);
  return [
    cwd,
    h('.zshrc'), h('.zprofile'), h('.bashrc'), h('.bash_profile'), h('.profile'), h('.config', 'fish', 'config.fish'),
    h('.claude.json'), h('.claude', 'settings.json'), h('.cursor', 'mcp.json'),
    h('Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    h('.config', 'Claude', 'claude_desktop_config.json'),
    path.join(process.env.APPDATA ?? h('AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json'),
  ];
}

/**
 * Replace secrets in a file with a placeholder. Atomic (temp file + rename), keeps permissions,
 * and writes NO backup: a backup would just be another plaintext copy of the key.
 * Callers must have already stored the key safely before calling this.
 */
export async function redactFile(file: string, secrets: string[], placeholder = 'REMOVED_BY_LLLANYARD'): Promise<number> {
  const st = await fs.lstat(file);
  if (!st.isFile()) throw new Error('Refusing to edit a non-regular file');
  let text = await fs.readFile(file, 'utf8');
  let count = 0;
  for (const s of secrets) { const parts = text.split(s); count += parts.length - 1; text = parts.join(placeholder); }
  if (count === 0) return 0;
  const tmp = `${file}.lllanyard-${process.pid}.tmp`;
  try {
    await fs.writeFile(tmp, text, { mode: st.mode & 0o777, flag: 'wx' });
    await fs.rename(tmp, file);
  } catch (e) {
    await fs.rm(tmp, { force: true });
    throw e;
  }
  return count;
}
