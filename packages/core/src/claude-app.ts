import { execFile, spawnSync } from 'node:child_process';
import { StoreError } from './storage/keyring-store.js';

/**
 * Claude Desktop rewrites claude_desktop_config.json from memory when it quits, so a change written while it is open is
 * lost. Changes are therefore only made while it is closed: on macOS we can quit it, write,
 * and reopen it; elsewhere the user quits it first.
 */
const MAC_ID = 'com.anthropic.claudefordesktop';
const MAC_EXE = '/Claude.app/Contents/MacOS/Claude';

export interface AppSys {
  platform: NodeJS.Platform;
  list: () => string[] | null; // running process names/paths, or null if we can't tell
  run: (cmd: string, args: string[]) => Promise<number>;
  sleep: (ms: number) => Promise<void>;
}

export function defaultAppSys(platform = process.platform): AppSys {
  return {
    platform,
    list: () => {
      const r = platform === 'win32'
        ? spawnSync('tasklist', ['/FO', 'CSV', '/NH'], { encoding: 'utf8', timeout: 10_000, windowsHide: true })
        : spawnSync('ps', platform === 'darwin' ? ['-axo', 'comm='] : ['-eo', 'comm='], { encoding: 'utf8', timeout: 10_000 });
      return r.status === 0 ? r.stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean) : null;
    },
    run: (cmd, args) => new Promise((resolve) => { execFile(cmd, args, { timeout: 60_000 }, (e) => resolve(e ? (typeof e.code === 'number' ? e.code : 1) : 0)); }),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  };
}

/** Whether Claude Desktop is open. Unknown (no process list) counts as closed. */
export function claudeDesktopRunning(sys: AppSys = defaultAppSys()): boolean {
  const procs = sys.list();
  if (!procs) return false;
  if (sys.platform === 'darwin') return procs.some((p) => p.endsWith(MAC_EXE));
  if (sys.platform === 'win32') return procs.some((p) => /^"claude\.exe"/i.test(p));
  return procs.includes('claude-desktop'); // not "claude": that is Claude Code
}

export const canRestartClaudeDesktop = (platform = process.platform) => platform === 'darwin';

/**
 * Runs `change` with Claude Desktop closed. If it's open: with `restart` (macOS only) it is quit first and reopened
 * afterwards, even if the change fails; otherwise nothing is changed and the error says what to do.
 */
export async function withClaudeDesktopClosed<T>(change: () => T, opts: { restart: boolean; sys?: AppSys }): Promise<{ result: T; restarted: boolean }> {
  const sys = opts.sys ?? defaultAppSys();
  if (!claudeDesktopRunning(sys)) return { result: change(), restarted: false };
  if (!canRestartClaudeDesktop(sys.platform)) throw new StoreError('Claude Desktop is open. Quit it completely (including from the system tray), then try again: it rewrites its settings when it quits, which would undo this change.');
  if (!opts.restart) throw new StoreError('Claude Desktop is open, and it rewrites its settings when it quits, which would undo this change. Run again with --restart to quit it, make the change and reopen it, or quit it yourself first.');
  await sys.run('osascript', ['-e', `tell application id "${MAC_ID}" to quit`]);
  for (let i = 0; i < 60 && claudeDesktopRunning(sys); i++) await sys.sleep(500);
  if (claudeDesktopRunning(sys)) throw new StoreError('Claude Desktop didn\'t quit (it may be asking you something). Quit it, then try again. Nothing was changed.');
  try {
    return { result: change(), restarted: true };
  } finally {
    await sys.run('open', ['-b', MAC_ID]);
  }
}
