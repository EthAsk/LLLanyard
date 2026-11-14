import { existsSync } from 'node:fs';
import path from 'node:path';
import {
  claudeCodeMemoryPath, claudeCodeStatus, codexHome, codexStatus, connectClaudeCode, connectCodex, connectCopilotCli, connectJsonTarget,
  copilotCliInstructionsPath, copilotCliMcpPath, copilotStatus, disconnectClaudeCode, disconnectClaudeHooks, disconnectCodex, disconnectCopilotCli, disconnectJsonTarget, jsonTargetStatus, JSON_TARGETS,
  type Env, type Launch,
} from './integrations.js';

/**
 * The AI tools `lllanyard setup <id>` can connect, in one list so the command line, the app and `audit` agree.
 * (Claude Desktop is handled separately: it has to be closed while its settings are changed.)
 */
export interface AppInfo {
  id: string;
  name: string;
  /** What connecting does, in a sentence. */
  summary: string;
  installed: (o?: Env) => boolean;
  status: (o?: Env) => { connected: boolean; detail?: string };
  connect: (l: Launch, o?: Env) => { files: string[]; backups: string[]; note?: string };
  disconnect: (o?: Env) => { removed: boolean; files: string[] };
}

const dirExists = (d: string) => { try { return existsSync(d); } catch { return false; } };

/** Whether a command is on PATH. A tool's folder alone isn't proof: other programs (VS Code's Copilot extension) create ~/.copilot too. */
export function onPath(cmd: string, env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): boolean {
  const exts = platform === 'win32' ? ['.exe', '.cmd', '.bat', ''] : [''];
  return (env.PATH ?? '').split(path.delimiter).filter(Boolean).some((d) => exts.some((x) => dirExists(path.join(d, cmd + x))));
}
const files = (r: { file: string; backup?: string }) => ({ files: [r.file], backups: r.backup ? [r.backup] : [] });

export const APPS: AppInfo[] = [
  {
    id: 'claude-code', name: 'Claude Code',
    summary: 'Adds instructions to ~/.claude/CLAUDE.md so Claude Code uses lllanyard exec and lllanyard ssh. Add --hooks to make it refuse to read .env files and SSH keys.',
    installed: (o) => dirExists(path.dirname(claudeCodeMemoryPath(o))),
    status: (o) => { const s = claudeCodeStatus(o); return { connected: s.connected, detail: s.hooks ? 'hook on' : undefined }; },
    connect: (_l, o) => files(connectClaudeCode(o)),
    disconnect: (o) => { const a = disconnectClaudeCode(o), h = disconnectClaudeHooks(o); return { removed: a.removed || h.removed, files: [a.file, h.file] }; },
  },
  {
    id: 'codex', name: 'OpenAI Codex',
    summary: 'Adds instructions to ~/.codex/AGENTS.md and the LLLanyard MCP server to ~/.codex/config.toml (CLI and IDE extension).',
    installed: (o) => dirExists(codexHome(o)) || onPath('codex', o?.env),
    status: (o) => ({ connected: codexStatus(o).connected }),
    connect: (l, o) => connectCodex(l, o),
    disconnect: (o) => disconnectCodex(o),
  },
  {
    id: 'copilot', name: 'GitHub Copilot CLI',
    summary: 'Adds instructions and the LLLanyard MCP server to ~/.copilot. For VS Code Copilot Chat, use --project <folder>.',
    installed: (o) => onPath('copilot', o?.env) || dirExists(copilotCliMcpPath(o)) || dirExists(copilotCliInstructionsPath(o)),
    status: (o) => ({ connected: copilotStatus(undefined, o).cli }),
    connect: (l, o) => connectCopilotCli(l, o),
    disconnect: (o) => disconnectCopilotCli(o),
  },
  ...JSON_TARGETS.map((t): AppInfo => ({
    id: t.id, name: t.name,
    summary: t.instructionsFile
      ? `Adds instructions to ${path.basename(t.instructionsFile({ home: '~' }))} and the LLLanyard MCP server to ${path.basename(t.mcpFile({ home: '~' }))}.`
      : `Adds the LLLanyard MCP server to ${path.basename(t.mcpFile({ home: '~' }))}. Its global rules are set in its settings, so add the instructions there: run lllanyard setup agent and paste the section it adds.`,
    installed: (o) => dirExists(t.folder(o ?? {})) || (t.id === 'gemini' && onPath('gemini', o?.env)),
    status: (o) => ({ connected: jsonTargetStatus(t, o).connected }),
    connect: (l, o) => ({ ...connectJsonTarget(t, l, o), ...(t.instructionsFile ? {} : { note: `${t.name} has no instructions file: its global rules are in its settings. Run lllanyard setup agent and paste the section into its rules so it knows to use lllanyard.` }) }),
    disconnect: (o) => disconnectJsonTarget(t, o),
  })),
];

export const findApp = (id: string) => APPS.find((a) => a.id === id);
