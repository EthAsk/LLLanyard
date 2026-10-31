import { copyFileSync, existsSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveScriptDirs } from './script-file.js';
import { StoreError } from './storage/keyring-store.js';

/**
 * Connecting AI apps to LLLanyard (`lllanyard setup`, and the UI's "Connect AI apps").
 * - Claude Desktop: adds LLLanyard's MCP server to claude_desktop_config.json, so chats can run scripts with keys.
 * - Claude Code: adds a marked block to ~/.claude/CLAUDE.md telling it to use `lllanyard exec`, never .env files.
 * Both leave everything else in the file alone, back the file up first, and can be removed again.
 */
export const MCP_NAME = 'lllanyard';
const START = '<!-- lllanyard:start (added by `lllanyard setup claude-code`; remove with `lllanyard setup claude-code --remove`) -->';
const END = '<!-- lllanyard:end -->';
const BLOCK_RE = /<!-- lllanyard:start[^>]*-->[\s\S]*?<!-- lllanyard:end -->\n?/;

export interface Env { platform?: NodeJS.Platform; home?: string; env?: NodeJS.ProcessEnv }

export function claudeDesktopConfigPath(o: Env = {}): string {
  const platform = o.platform ?? process.platform, home = o.home ?? os.homedir(), env = o.env ?? process.env;
  const p = platform === 'win32' ? path.win32 : path.posix;
  if (platform === 'darwin') return p.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  if (platform === 'win32') return p.join(env.APPDATA ?? p.join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json');
  return p.join(env.XDG_CONFIG_HOME ?? p.join(home, '.config'), 'Claude', 'claude_desktop_config.json');
}

export function claudeCodeMemoryPath(o: Env = {}): string {
  const env = o.env ?? process.env;
  return path.join(env.CLAUDE_CONFIG_DIR ?? path.join(o.home ?? os.homedir(), '.claude'), 'CLAUDE.md');
}

/** How the app should start LLLanyard: absolute paths, because desktop apps start MCP servers with a minimal PATH. */
export interface Launch { node: string; cli: string; pathVar: string }

/**
 * The running Node, preferably by a path that survives upgrades: Homebrew runs node from a versioned Cellar folder, which
 * `brew upgrade` deletes, but /opt/homebrew/bin/node keeps pointing at the current one. Uses a PATH entry only if it is
 * the same Node.
 */
export function stableNodePath(execPath: string, pathVar: string, platform: NodeJS.Platform = process.platform): string {
  const real = (f: string) => { try { return realpathSync(f); } catch { return null; } };
  const target = real(execPath);
  for (const dir of pathVar.split(path.delimiter).filter(Boolean)) {
    const c = path.join(dir, platform === 'win32' ? 'node.exe' : 'node');
    if (c !== execPath && target && real(c) === target) return c;
  }
  return execPath;
}

export function mcpEntry(l: Launch, scriptDirs: string[]) {
  return {
    command: l.node,
    args: [l.cli, 'mcp', '--run', ...scriptDirs.flatMap((d) => ['--scripts-dir', d])],
    // The scripts' interpreters (pwsh, python3) are found on this PATH: the one LLLanyard was set up from.
    env: { PATH: l.pathVar },
  };
}

function readJson(file: string): Record<string, any> {
  if (!existsSync(file)) return {};
  const text = readFileSync(file, 'utf8');
  if (!text.trim()) return {};
  let v: unknown;
  try { v = JSON.parse(text); } catch { throw new StoreError(`${file} isn't valid JSON, so LLLanyard didn't change it. Fix or move it, then try again.`); }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new StoreError(`${file} isn't a settings object, so LLLanyard didn't change it.`);
  return v as Record<string, any>;
}

/** Writes via a temp file and rename, after copying the old file to <file>.lllanyard-backup. Returns the backup path. */
function writeWithBackup(file: string, text: string): string | undefined {
  mkdirSync(path.dirname(file), { recursive: true });
  let backup: string | undefined;
  if (existsSync(file)) { backup = `${file}.lllanyard-backup`; copyFileSync(file, backup); }
  const tmp = `${file}.lllanyard-tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  renameSync(tmp, file);
  return backup;
}

export interface DesktopStatus { file: string; connected: boolean; scriptDirs: string[]; problem?: string }

export function claudeDesktopStatus(o: Env = {}): DesktopStatus {
  const file = claudeDesktopConfigPath(o);
  let cfg: Record<string, any>;
  try { cfg = readJson(file); } catch (e) { return { file, connected: false, scriptDirs: [], problem: (e as Error).message }; }
  const e = cfg.mcpServers?.[MCP_NAME];
  if (!e) return { file, connected: false, scriptDirs: [] };
  const args: string[] = Array.isArray(e.args) ? e.args.map(String) : [];
  const scriptDirs = args.flatMap((a, i) => (args[i - 1] === '--scripts-dir' ? [a] : []));
  const missing = [e.command, args[0]].filter((f) => typeof f === 'string' && path.isAbsolute(f) && !existsSync(f));
  return { file, connected: true, scriptDirs, ...(missing.length ? { problem: `${missing.join(' and ')} no longer exist${missing.length > 1 ? '' : 's'}. Connect again to update it.` } : {}) };
}

export function connectClaudeDesktop(l: Launch, scriptDirs: string[], o: Env = {}): { file: string; backup?: string; scriptDirs: string[] } {
  const dirs = resolveScriptDirs(scriptDirs, o.home);
  const file = claudeDesktopConfigPath(o);
  const cfg = readJson(file);
  if (cfg.mcpServers !== undefined && (typeof cfg.mcpServers !== 'object' || Array.isArray(cfg.mcpServers))) throw new StoreError(`"mcpServers" in ${file} isn't an object, so LLLanyard didn't change it.`);
  cfg.mcpServers = { ...(cfg.mcpServers ?? {}), [MCP_NAME]: mcpEntry(l, dirs) };
  return { file, backup: writeWithBackup(file, JSON.stringify(cfg, null, 2) + '\n'), scriptDirs: dirs };
}

export function disconnectClaudeDesktop(o: Env = {}): { file: string; removed: boolean; backup?: string } {
  const file = claudeDesktopConfigPath(o);
  const cfg = readJson(file);
  if (!cfg.mcpServers?.[MCP_NAME]) return { file, removed: false };
  delete cfg.mcpServers[MCP_NAME];
  return { file, removed: true, backup: writeWithBackup(file, JSON.stringify(cfg, null, 2) + '\n') };
}

export function claudeCodeBlock(): string {
  return [
    START,
    '## API keys: use LLLanyard',
    '',
    'API keys live in LLLanyard (the OS keychain). Never read, print, copy or ask for key values, and never put them in files, commands or chat.',
    '',
    '- Run any script or command that needs keys through LLLanyard: `lllanyard exec <command> [args…]`, e.g. `lllanyard exec pwsh -File ./Deploy-App.ps1 -DryRun`. It passes only the keys the script uses, for that run only, and redacts them from the output.',
    '- For a program that isn\'t a script, name the keys: `lllanyard exec --keys github,sendgrid -- <command>`.',
    '- `lllanyard list` shows which keys exist and the variable names scripts get them as (values are masked).',
    '- Don\'t look in `.env` files or other files that hold secrets for keys. If a key is missing, ask the user to add it with `lllanyard add <provider>`.',
    '- MCP servers that need keys: approve them with `lllanyard tool add` and start them with `lllanyard run <name>`, never with keys in their config.',
    END,
  ].join('\n') + '\n';
}

export function claudeCodeStatus(o: Env = {}): { file: string; connected: boolean } {
  const file = claudeCodeMemoryPath(o);
  return { file, connected: existsSync(file) && BLOCK_RE.test(readFileSync(file, 'utf8')) };
}

/** Adds the block, or replaces an older version of it. Everything outside the markers is kept. */
export function connectClaudeCode(o: Env = {}): { file: string; backup?: string } {
  const file = claudeCodeMemoryPath(o);
  const old = existsSync(file) ? readFileSync(file, 'utf8') : '';
  const text = BLOCK_RE.test(old) ? old.replace(BLOCK_RE, claudeCodeBlock()) : (old && !old.endsWith('\n\n') ? old.replace(/\n?$/, '\n\n') : old) + claudeCodeBlock();
  return { file, backup: writeWithBackup(file, text) };
}

export function disconnectClaudeCode(o: Env = {}): { file: string; removed: boolean; backup?: string } {
  const file = claudeCodeMemoryPath(o);
  if (!existsSync(file)) return { file, removed: false };
  const old = readFileSync(file, 'utf8');
  if (!BLOCK_RE.test(old)) return { file, removed: false };
  const rest = old.replace(BLOCK_RE, '').replace(/\n+$/, '');
  return { file, removed: true, backup: writeWithBackup(file, rest ? rest + '\n' : '') };
}
