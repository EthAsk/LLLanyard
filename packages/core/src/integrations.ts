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
type Marks = { re: RegExp; start: (app: string) => string; end: string };
/** Markdown files (CLAUDE.md, AGENTS.md, copilot-instructions.md) mark our block with an HTML comment, TOML with a # comment. */
const MD: Marks = {
  re: /<!-- lllanyard:start[^>]*-->[\s\S]*?<!-- lllanyard:end -->\n?/,
  start: (app) => `<!-- lllanyard:start (added by \`lllanyard setup ${app}\`; remove with \`lllanyard setup ${app} --remove\`) -->`,
  end: '<!-- lllanyard:end -->',
};
const TOML: Marks = {
  re: /# lllanyard:start[^\n]*\n[\s\S]*?# lllanyard:end\n?/,
  start: (app) => `# lllanyard:start (added by \`lllanyard setup ${app}\`; remove with \`lllanyard setup ${app} --remove\`)`,
  end: '# lllanyard:end',
};

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

/** The instructions every agent gets: use lllanyard for keys and SSH, never look for secrets in files. */
export function instructionLines(): string[] {
  return [
    '## API keys: use LLLanyard',
    '',
    'API keys live in LLLanyard (the OS keychain). Never read, print, copy or ask for key values, and never put them in files, commands or chat.',
    '',
    '- Run any script or command that needs keys through LLLanyard: `lllanyard exec <command> [args…]`, e.g. `lllanyard exec pwsh -File ./Deploy-App.ps1 -DryRun`. It passes only the keys the script uses, for that run only, and redacts them from the output.',
    '- For a program that isn\'t a script, name the keys: `lllanyard exec --keys github,sendgrid -- <command>`.',
    '- `lllanyard list` shows which keys exist and the variable names scripts get them as (values are masked).',
    '- Don\'t look in `.env` files or other files that hold secrets for keys. If a key is missing, ask the user to add it with `lllanyard add <provider>`.',
    '- MCP servers that need keys: approve them with `lllanyard tool add` and start them with `lllanyard run <name>`, never with keys in their config.',
    '- SSH to a server: use `lllanyard ssh <name>` (or `lllanyard ssh with <name> -- scp …`) with a login the user stored (`lllanyard ssh list`). Never look in `~/.ssh`, ask for SSH keys or passwords, or write them to files. If a login is missing, ask the user to add it with `lllanyard ssh add`.',
  ];
}

function markedBlock(app: string, marks: Marks, body: string[]): string {
  return [marks.start(app), ...body, marks.end].join('\n') + '\n';
}

export function claudeCodeBlock(): string { return markedBlock('claude-code', MD, instructionLines()); }

function blockStatus(file: string, marks: Marks): boolean {
  return existsSync(file) && marks.re.test(readFileSync(file, 'utf8'));
}

/** Adds the block, or replaces an older version of it. Everything outside the markers is kept. */
function putBlock(file: string, marks: Marks, block: string): { file: string; backup?: string } {
  const old = existsSync(file) ? readFileSync(file, 'utf8') : '';
  const text = marks.re.test(old) ? old.replace(marks.re, block) : (old && !old.endsWith('\n\n') ? old.replace(/\n?$/, '\n\n') : old) + block;
  return { file, backup: writeWithBackup(file, text) };
}

function dropBlock(file: string, marks: Marks): { file: string; removed: boolean; backup?: string } {
  if (!existsSync(file)) return { file, removed: false };
  const old = readFileSync(file, 'utf8');
  if (!marks.re.test(old)) return { file, removed: false };
  const rest = old.replace(marks.re, '').replace(/\n+$/, '');
  return { file, removed: true, backup: writeWithBackup(file, rest ? rest + '\n' : '') };
}

export function claudeCodeStatus(o: Env = {}): { file: string; connected: boolean; hooks: boolean } {
  const file = claudeCodeMemoryPath(o);
  return { file, connected: blockStatus(file, MD), hooks: claudeHooksStatus(o) };
}
export function connectClaudeCode(o: Env = {}) { return putBlock(claudeCodeMemoryPath(o), MD, claudeCodeBlock()); }
export function disconnectClaudeCode(o: Env = {}) { return dropBlock(claudeCodeMemoryPath(o), MD); }

// ---------------------------------------------------------------------------------------------------------------------
// Claude Code hook: refuse tool calls that would read .env files or SSH keys (`setup claude-code --hooks`)
// ---------------------------------------------------------------------------------------------------------------------

export const claudeSettingsPath = (o: Env = {}) => path.join((o.env ?? process.env).CLAUDE_CONFIG_DIR ?? path.join(o.home ?? os.homedir(), '.claude'), 'settings.json');
const HOOK_MARK = ' hook claude-code';
const HOOK_MATCHER = 'Read|Edit|MultiEdit|Write|NotebookEdit|Grep|Bash';
const isOurHook = (h: any) => typeof h?.command === 'string' && h.command.endsWith(HOOK_MARK);

export function hookCommand(l: Launch): string { return `"${l.node}" "${l.cli}"${HOOK_MARK}`; }

export function claudeHooksStatus(o: Env = {}): boolean {
  try {
    const pre = readJson(claudeSettingsPath(o)).hooks?.PreToolUse;
    return Array.isArray(pre) && pre.some((g: any) => Array.isArray(g?.hooks) && g.hooks.some(isOurHook));
  } catch { return false; }
}

/** Adds (or refreshes) the PreToolUse hook in Claude Code's settings.json, leaving every other setting and hook alone. */
export function connectClaudeHooks(l: Launch, o: Env = {}): { file: string; backup?: string } {
  const file = claudeSettingsPath(o);
  const cfg = readJson(file);
  if (cfg.hooks !== undefined && (typeof cfg.hooks !== 'object' || Array.isArray(cfg.hooks))) throw new StoreError(`"hooks" in ${file} isn't an object, so LLLanyard didn't change it.`);
  if (cfg.hooks?.PreToolUse !== undefined && !Array.isArray(cfg.hooks.PreToolUse)) throw new StoreError(`"hooks.PreToolUse" in ${file} isn't a list, so LLLanyard didn't change it.`);
  const groups: any[] = (cfg.hooks?.PreToolUse ?? []).map((g: any) => (Array.isArray(g?.hooks) ? { ...g, hooks: g.hooks.filter((h: any) => !isOurHook(h)) } : g)).filter((g: any) => !Array.isArray(g?.hooks) || g.hooks.length);
  groups.push({ matcher: HOOK_MATCHER, hooks: [{ type: 'command', command: hookCommand(l) }] });
  cfg.hooks = { ...(cfg.hooks ?? {}), PreToolUse: groups };
  return { file, backup: writeWithBackup(file, JSON.stringify(cfg, null, 2) + '\n') };
}

export function disconnectClaudeHooks(o: Env = {}): { file: string; removed: boolean; backup?: string } {
  const file = claudeSettingsPath(o);
  if (!existsSync(file) || !claudeHooksStatus(o)) return { file, removed: false };
  const cfg = readJson(file);
  const groups = (cfg.hooks.PreToolUse as any[]).map((g) => (Array.isArray(g?.hooks) ? { ...g, hooks: g.hooks.filter((h: any) => !isOurHook(h)) } : g)).filter((g) => !Array.isArray(g?.hooks) || g.hooks.length);
  if (groups.length) cfg.hooks.PreToolUse = groups; else delete cfg.hooks.PreToolUse;
  if (!Object.keys(cfg.hooks).length) delete cfg.hooks;
  return { file, removed: true, backup: writeWithBackup(file, JSON.stringify(cfg, null, 2) + '\n') };
}

// ---------------------------------------------------------------------------------------------------------------------
// OpenAI Codex (CLI and IDE extension; the ChatGPT apps cannot start a local MCP server)
// ---------------------------------------------------------------------------------------------------------------------

export function codexHome(o: Env = {}): string {
  return (o.env ?? process.env).CODEX_HOME ?? path.join(o.home ?? os.homedir(), '.codex');
}
export const codexAgentsPath = (o: Env = {}) => path.join(codexHome(o), 'AGENTS.md');
export const codexConfigPath = (o: Env = {}) => path.join(codexHome(o), 'config.toml');

const tomlStr = (v: string) => JSON.stringify(v); // a JSON string is a valid TOML basic string

export function codexMcpBlock(l: Launch): string {
  const e = mcpEntry(l, []);
  return markedBlock('codex', TOML, [
    `[mcp_servers.${MCP_NAME}]`,
    `command = ${tomlStr(e.command)}`,
    `args = [${e.args.map(tomlStr).join(', ')}]`,
    `env = { PATH = ${tomlStr(e.env.PATH)} }`,
  ]);
}

export function codexStatus(o: Env = {}): { file: string; connected: boolean; mcp: boolean; instructions: boolean } {
  const instructions = blockStatus(codexAgentsPath(o), MD), mcp = blockStatus(codexConfigPath(o), TOML);
  return { file: codexHome(o), connected: instructions || mcp, mcp, instructions };
}

export function connectCodex(l: Launch, o: Env = {}): { files: string[]; backups: string[] } {
  const cfg = codexConfigPath(o);
  const old = existsSync(cfg) ? readFileSync(cfg, 'utf8') : '';
  // A table of our name that we didn't write would make the file invalid TOML (a duplicate table): leave it to the user.
  if (!TOML.re.test(old) && new RegExp(`^\\s*\\[mcp_servers\\.${MCP_NAME}[\\].]`, 'm').test(old))
    throw new StoreError(`${cfg} already has an [mcp_servers.${MCP_NAME}] entry that LLLanyard didn't add, so it didn't change it. Remove that entry, then try again.`);
  const a = putBlock(codexAgentsPath(o), MD, markedBlock('codex', MD, instructionLines()));
  const c = putBlock(cfg, TOML, codexMcpBlock(l));
  return { files: [a.file, c.file], backups: [a.backup, c.backup].filter((x): x is string => Boolean(x)) };
}

export function disconnectCodex(o: Env = {}): { removed: boolean; files: string[] } {
  const a = dropBlock(codexAgentsPath(o), MD), c = dropBlock(codexConfigPath(o), TOML);
  return { removed: a.removed || c.removed, files: [a.file, c.file] };
}

// ---------------------------------------------------------------------------------------------------------------------
// GitHub Copilot: Copilot CLI (your user folder) and VS Code / the Copilot coding agent (a project folder)
// ---------------------------------------------------------------------------------------------------------------------

export function copilotHome(o: Env = {}): string {
  return (o.env ?? process.env).COPILOT_HOME ?? path.join(o.home ?? os.homedir(), '.copilot');
}
export const copilotCliInstructionsPath = (o: Env = {}) => path.join(copilotHome(o), 'copilot-instructions.md');
export const copilotCliMcpPath = (o: Env = {}) => path.join(copilotHome(o), 'mcp-config.json');
export const projectInstructionsPath = (dir: string) => path.join(dir, '.github', 'copilot-instructions.md');
export const projectMcpPath = (dir: string) => path.join(dir, '.vscode', 'mcp.json');

/** In a project the file may be committed and shared, so it names `lllanyard` (found on PATH) rather than this machine's paths. */
export function projectMcpEntry() { return { type: 'stdio', command: 'lllanyard', args: ['mcp', '--run'] }; }

export function copilotStatus(dir?: string, o: Env = {}): { cli: boolean; project?: boolean; files: string[] } {
  const mcp = (() => { try { return Boolean(readJson(copilotCliMcpPath(o)).mcpServers?.[MCP_NAME]); } catch { return false; } })();
  const cli = blockStatus(copilotCliInstructionsPath(o), MD) || mcp;
  const project = dir ? blockStatus(projectInstructionsPath(dir), MD) : undefined;
  return { cli, ...(project === undefined ? {} : { project }), files: [copilotCliInstructionsPath(o), copilotCliMcpPath(o), ...(dir ? [projectInstructionsPath(dir)] : [])] };
}

/** Copilot CLI, for you on this computer: its personal instructions file plus its MCP server list. */
export function connectCopilotCli(l: Launch, o: Env = {}): { files: string[]; backups: string[] } {
  const mcpFile = copilotCliMcpPath(o);
  const cfg = readJson(mcpFile);
  if (cfg.mcpServers !== undefined && (typeof cfg.mcpServers !== 'object' || Array.isArray(cfg.mcpServers))) throw new StoreError(`"mcpServers" in ${mcpFile} isn't an object, so LLLanyard didn't change it.`);
  const i = putBlock(copilotCliInstructionsPath(o), MD, markedBlock('copilot', MD, instructionLines()));
  cfg.mcpServers = { ...(cfg.mcpServers ?? {}), [MCP_NAME]: { type: 'local', ...mcpEntry(l, []), tools: ['*'] } };
  const m = writeWithBackup(mcpFile, JSON.stringify(cfg, null, 2) + '\n');
  return { files: [i.file, mcpFile], backups: [i.backup, m].filter((x): x is string => Boolean(x)) };
}

export function disconnectCopilotCli(o: Env = {}): { removed: boolean; files: string[] } {
  const i = dropBlock(copilotCliInstructionsPath(o), MD);
  const mcpFile = copilotCliMcpPath(o);
  const cfg = readJson(mcpFile);
  let removedMcp = false;
  if (cfg.mcpServers?.[MCP_NAME]) { delete cfg.mcpServers[MCP_NAME]; writeWithBackup(mcpFile, JSON.stringify(cfg, null, 2) + '\n'); removedMcp = true; }
  return { removed: i.removed || removedMcp, files: [i.file, mcpFile] };
}

/** VS Code Copilot Chat and the Copilot coding agent, for one project: .github/copilot-instructions.md and .vscode/mcp.json. */
export function connectCopilotProject(dir: string): { files: string[]; backups: string[] } {
  const mcpFile = projectMcpPath(dir);
  const cfg = readJson(mcpFile);
  if (cfg.servers !== undefined && (typeof cfg.servers !== 'object' || Array.isArray(cfg.servers))) throw new StoreError(`"servers" in ${mcpFile} isn't an object, so LLLanyard didn't change it.`);
  const i = putBlock(projectInstructionsPath(dir), MD, markedBlock('copilot', MD, instructionLines()));
  cfg.servers = { ...(cfg.servers ?? {}), [MCP_NAME]: projectMcpEntry() };
  const m = writeWithBackup(mcpFile, JSON.stringify(cfg, null, 2) + '\n');
  return { files: [i.file, mcpFile], backups: [i.backup, m].filter((x): x is string => Boolean(x)) };
}

export function disconnectCopilotProject(dir: string): { removed: boolean; files: string[] } {
  const i = dropBlock(projectInstructionsPath(dir), MD);
  const mcpFile = projectMcpPath(dir);
  const cfg = readJson(mcpFile);
  let removedMcp = false;
  if (cfg.servers?.[MCP_NAME]) { delete cfg.servers[MCP_NAME]; writeWithBackup(mcpFile, JSON.stringify(cfg, null, 2) + '\n'); removedMcp = true; }
  return { removed: i.removed || removedMcp, files: [i.file, mcpFile] };
}

// ---------------------------------------------------------------------------------------------------------------------
// Tools that keep an `mcpServers` JSON file (and sometimes a user instructions file): Gemini CLI, Windsurf, Cursor
// ---------------------------------------------------------------------------------------------------------------------

export interface JsonTarget {
  id: string;
  name: string;
  folder: (o: Env) => string; // the tool's own folder: its presence means the tool is installed
  mcpFile: (o: Env) => string;
  instructionsFile?: (o: Env) => string; // where the tool reads the user's own instructions, if it has such a file
}
const homeOf = (o: Env) => o.home ?? os.homedir();

export const JSON_TARGETS: JsonTarget[] = [
  { id: 'gemini', name: 'Gemini CLI', folder: (o) => path.join(homeOf(o), '.gemini'), mcpFile: (o) => path.join(homeOf(o), '.gemini', 'settings.json'), instructionsFile: (o) => path.join(homeOf(o), '.gemini', 'GEMINI.md') },
  { id: 'windsurf', name: 'Windsurf', folder: (o) => path.join(homeOf(o), '.codeium', 'windsurf'), mcpFile: (o) => path.join(homeOf(o), '.codeium', 'windsurf', 'mcp_config.json'), instructionsFile: (o) => path.join(homeOf(o), '.codeium', 'windsurf', 'memories', 'global_rules.md') },
  { id: 'cursor', name: 'Cursor', folder: (o) => path.join(homeOf(o), '.cursor'), mcpFile: (o) => path.join(homeOf(o), '.cursor', 'mcp.json') }, // global rules are set in Cursor's settings, not a file
];

export function jsonTargetStatus(t: JsonTarget, o: Env = {}): { connected: boolean; mcp: boolean; instructions: boolean } {
  const mcp = (() => { try { return Boolean(readJson(t.mcpFile(o)).mcpServers?.[MCP_NAME]); } catch { return false; } })();
  const instructions = t.instructionsFile ? blockStatus(t.instructionsFile(o), MD) : false;
  return { connected: mcp || instructions, mcp, instructions };
}

export function connectJsonTarget(t: JsonTarget, l: Launch, o: Env = {}): { files: string[]; backups: string[] } {
  const file = t.mcpFile(o);
  const cfg = readJson(file);
  if (cfg.mcpServers !== undefined && (typeof cfg.mcpServers !== 'object' || Array.isArray(cfg.mcpServers))) throw new StoreError(`"mcpServers" in ${file} isn't an object, so LLLanyard didn't change it.`);
  const files: string[] = [], backups: string[] = [];
  if (t.instructionsFile) { const i = putBlock(t.instructionsFile(o), MD, markedBlock(t.id, MD, instructionLines())); files.push(i.file); if (i.backup) backups.push(i.backup); }
  cfg.mcpServers = { ...(cfg.mcpServers ?? {}), [MCP_NAME]: mcpEntry(l, []) };
  const b = writeWithBackup(file, JSON.stringify(cfg, null, 2) + '\n');
  files.push(file); if (b) backups.push(b);
  return { files, backups };
}

export function disconnectJsonTarget(t: JsonTarget, o: Env = {}): { removed: boolean; files: string[] } {
  const i = t.instructionsFile ? dropBlock(t.instructionsFile(o), MD) : { file: '', removed: false };
  const file = t.mcpFile(o);
  const cfg = readJson(file);
  let mcp = false;
  if (cfg.mcpServers?.[MCP_NAME]) { delete cfg.mcpServers[MCP_NAME]; writeWithBackup(file, JSON.stringify(cfg, null, 2) + '\n'); mcp = true; }
  return { removed: i.removed || mcp, files: [i.file, file].filter(Boolean) };
}

// ---------------------------------------------------------------------------------------------------------------------
// Any other agent: an instructions file it reads (AGENTS.md is read by most), plus the MCP snippet to paste
// ---------------------------------------------------------------------------------------------------------------------

export const connectAgentFile = (file: string) => putBlock(file, MD, markedBlock('agent', MD, instructionLines()));
export const disconnectAgentFile = (file: string) => dropBlock(file, MD);
export const agentFileConnected = (file: string) => blockStatus(file, MD);
/** The standard `mcpServers` entry most MCP clients accept. */
export const genericMcpSnippet = () => JSON.stringify({ mcpServers: { [MCP_NAME]: { command: 'lllanyard', args: ['mcp', '--run'] } } }, null, 2);
