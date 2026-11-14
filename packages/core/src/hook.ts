import os from 'node:os';
import path from 'node:path';

/**
 * The check behind `lllanyard setup claude-code --hooks`. Claude Code runs it before a tool call (`lllanyard hook
 * claude-code`, with the call as JSON on stdin) and it can refuse the call, so an agent that ignores the instructions
 * in CLAUDE.md still can't read .env files or SSH keys.
 *
 * This is a safety net for an agent that is careless or has been tricked, not a sandbox: it looks at the paths a tool
 * call names, so a command that builds a path at run time (`cat $(printf '.e%s' nv)`) gets past it. For a hard
 * boundary use `lllanyard tool add --sandbox`.
 */
export interface HookInput { tool_name?: unknown; tool_input?: unknown; cwd?: unknown }
export interface HookEnv { home?: string; cwd?: string }

const SAFE_ENV_SUFFIX = /\.(example|sample|template|dist|defaults?)$/i;
const SSH_PUBLIC = /^(known_hosts.*|config|authorized_keys.*|.*\.pub)$/;
const PRIVATE_KEY_NAME = /^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$/;

const WHY_ENV = 'This file holds secrets. Don\'t read it: run the command through `lllanyard exec <command>` (it passes only the keys the script uses), see `lllanyard list` for what exists, and ask the user to add a missing key with `lllanyard add <provider>`.';
const WHY_SSH = 'SSH keys are kept in LLLanyard, not read from disk. Use `lllanyard ssh <name>` or `lllanyard ssh with <name> -- scp …` (see `lllanyard ssh list`), and ask the user to add a missing login with `lllanyard ssh add`.';
const WHY_CRED = 'This file holds credentials. Don\'t read it: run the command through `lllanyard exec`, and ask the user to add a missing key with `lllanyard add <provider>`.';

/** Why a path must not be read or changed by an agent, or null if it is fine. */
export function protectedReason(file: string, home: string): string | null {
  const p = path.resolve(file);
  const base = path.basename(p);
  const rel = (dir: string): string | null => {
    const r = path.relative(path.join(home, dir), p);
    return r === '' ? '' : !r.startsWith('..') && !path.isAbsolute(r) ? r : null;
  };
  if (/^\.env(\..+)?$/.test(base) && !SAFE_ENV_SUFFIX.test(base)) return WHY_ENV;
  if (PRIVATE_KEY_NAME.test(base)) return WHY_SSH;
  const ssh = rel('.ssh');
  if (ssh !== null && !SSH_PUBLIC.test(path.basename(ssh))) return WHY_SSH;
  for (const f of ['.aws/credentials', '.netrc', '.git-credentials', '.npmrc', '.pypirc', '.docker/config.json', '.kube/config', '.config/gh/hosts.yml', '.lllanyard/vault.enc'])
    if (rel(f) === '') return WHY_CRED;
  for (const d of ['.gnupg', '.aws/sso', '.aws/cli/cache'])
    if (rel(d) !== null) return WHY_CRED;
  return null;
}

const expand = (t: string, home: string, cwd: string): string => {
  const x = t.replace(/^(~|\$HOME|\$\{HOME\})(?=\/|\\|$)/, home);
  return path.isAbsolute(x) ? x : path.resolve(cwd, x);
};

/** The words of a shell command that could be file paths. */
export function commandPaths(command: string): string[] {
  return command.split(/[\s"'`;|&<>()=,{}]+/).filter((t) => t && (t.includes('/') || t.includes('.') || t.startsWith('~') || t.startsWith('$HOME')));
}

/** A reason to refuse this tool call, or null to let it through. Anything it can't make sense of is let through. */
export function checkToolCall(input: HookInput, env: HookEnv = {}): string | null {
  const home = env.home ?? os.homedir();
  const cwd = typeof input.cwd === 'string' && input.cwd ? input.cwd : env.cwd ?? process.cwd();
  const tool = typeof input.tool_name === 'string' ? input.tool_name : '';
  const ti = input.tool_input && typeof input.tool_input === 'object' ? (input.tool_input as Record<string, unknown>) : {};
  const str = (k: string) => (typeof ti[k] === 'string' ? (ti[k] as string) : undefined);
  const hit = (f: string | undefined) => (f ? protectedReason(expand(f, home, cwd), home) : null);

  switch (tool) {
    case 'Read': case 'Edit': case 'Write': case 'MultiEdit': return hit(str('file_path'));
    case 'NotebookEdit': return hit(str('notebook_path'));
    case 'Grep': return hit(str('path')) ?? (str('glob') && /(^|\/)\.env(\.|$|\*)/.test(str('glob')!) ? WHY_ENV : null);
    case 'Bash': {
      const cmd = str('command');
      if (!cmd || /^\s*lllanyard\s/.test(cmd)) return null; // lllanyard itself is the way to use secrets
      for (const t of commandPaths(cmd)) { const r = hit(t); if (r) return r; }
      return null;
    }
    default: return null;
  }
}

/** What Claude Code reads back from the hook on stdout to refuse a call. */
export function denyResponse(reason: string): string {
  return JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `Blocked by LLLanyard. ${reason}` } });
}
