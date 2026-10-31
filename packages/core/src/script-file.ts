import { spawn } from 'node:child_process';
import { realpathSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { StoreError } from './storage/keyring-store.js';
import { fileSha256, findCommand, neededEnv } from './tools.js';

/**
 * Running a script file that wasn't approved in advance (`lllanyard mcp --run --scripts-dir DIR`). The agent names a file
 * inside one of the user's script folders; the user confirms each run in a dialog LLLanyard shows, so the agent can't
 * approve it itself. The script and the helpers it loads are hashed before the dialog and checked again at launch.
 */
export interface ScriptPlan {
  script: string; // real path
  command: string;
  args: string[];
  env: Record<string, string>; // ENV_VAR -> key reference, only the keys the script uses
  scriptSha256: string;
  pins: Record<string, string>; // helper files it loads -> SHA-256
  helpers: string[];
  modifiedRecently: string[]; // the script or helpers, changed in the last day
}

// Extension -> interpreter and the options that go before the script.
const RUNNERS: Record<string, { cmd: string[]; pre: string[] }> = {
  '.ps1': { cmd: ['pwsh', 'powershell'], pre: ['-NoProfile', '-NonInteractive', '-File'] },
  '.py': { cmd: ['python3', 'python'], pre: [] },
  '.sh': { cmd: ['bash'], pre: [] },
  '.bash': { cmd: ['bash'], pre: [] },
  '.zsh': { cmd: ['zsh'], pre: [] },
  '.js': { cmd: ['node'], pre: [] },
  '.mjs': { cmd: ['node'], pre: [] },
};
const DAY = 24 * 3600_000;
const inside = (dir: string, p: string) => { const r = path.relative(dir, p); return r !== '' && !r.startsWith('..') && !path.isAbsolute(r); };

/** The script folders, resolved. Refuses the home directory and the filesystem root: they would allow almost anything. */
export function resolveScriptDirs(dirs: string[], home = os.homedir()): string[] {
  return dirs.map((d) => {
    let real: string;
    try { real = realpathSync(path.resolve(d)); } catch { throw new StoreError(`Script folder ${d} was not found.`); }
    if (!statSync(real).isDirectory()) throw new StoreError(`${d} is not a folder.`);
    if (real === path.parse(real).root || real === realpathSync(home)) throw new StoreError(`${real} is too broad to be a script folder. Name a specific folder of scripts.`);
    return real;
  });
}

export function planScriptRun(
  file: string, extra: string[], dirs: string[], bindings: Record<string, string>,
  opts: { pathVar?: string; now?: number } = {},
): ScriptPlan {
  if (!path.isAbsolute(file)) throw new StoreError('Give the script\'s full path.');
  let script: string;
  try { script = realpathSync(file); } catch { throw new StoreError(`Script ${file} was not found.`); }
  // Checked on the real path, so a symlink in a script folder can't point outside it.
  if (!dirs.some((d) => inside(d, script))) throw new StoreError(`${file} is not inside the script folders (${dirs.join(', ')}).`);
  const st = statSync(script);
  if (!st.isFile() || st.size > 2_000_000) throw new StoreError(`${file} is not a script file.`);
  const runner = RUNNERS[path.extname(script).toLowerCase()];
  if (!runner) throw new StoreError(`Can't run ${path.basename(script)}: supported scripts are ${Object.keys(RUNNERS).join(' ')}.`);
  if (extra.length > 100 || extra.some((a) => a.length > 1000 || a.includes('\0'))) throw new StoreError('Too many or too long arguments.');

  let command: string | undefined;
  for (const c of runner.cmd) { try { command = findCommand(c, opts.pathVar); break; } catch { /* try the next */ } }
  if (!command) throw new StoreError(`${runner.cmd.join(' or ')} is not installed (needed for ${path.basename(script)}).`);

  const { needed, files } = neededEnv(script, Object.keys(bindings));
  const helpers = files.filter((f) => f !== script);
  const now = opts.now ?? Date.now();
  return {
    script, command, args: [...runner.pre, script, ...extra],
    env: Object.fromEntries(needed.map((n) => [n, bindings[n]!])),
    scriptSha256: fileSha256(script),
    pins: Object.fromEntries(helpers.map((f) => [f, fileSha256(f)])),
    helpers,
    modifiedRecently: files.filter((f) => { try { return now - statSync(f).mtimeMs < DAY; } catch { return true; } }),
  };
}

/** The text of the confirmation dialog. */
export function describePlan(p: ScriptPlan, extra: string[], requester = 'Claude'): string {
  const lines = [
    `${requester} wants to run a script with your API keys.`, '',
    `Script: ${p.script}`,
    `Arguments: ${extra.length ? extra.join(' ') : '(none)'}`,
    `Keys: ${Object.keys(p.env).join(', ') || '(none)'}`,
  ];
  if (p.helpers.length) lines.push(`Also loads: ${p.helpers.map((f) => path.basename(f)).join(', ')}`);
  if (p.modifiedRecently.length) lines.push('', `WARNING: changed in the last 24 hours: ${p.modifiedRecently.map((f) => path.basename(f)).join(', ')}. Check it before running, in case an AI wrote or edited it.`);
  return lines.join('\n');
}

/**
 * Asks the user in a native dialog. Resolves true only for an explicit "Run"; Deny, closing it, the 2-minute timeout or
 * no way to show a dialog all mean no. The text is passed as data (argv or environment), never spliced into code.
 */
export function confirmDialog(message: string, opts: { platform?: NodeJS.Platform; spawnFn?: typeof spawn; timeoutSec?: number } = {}): Promise<boolean> {
  const platform = opts.platform ?? process.platform;
  const t = opts.timeoutSec ?? 120;
  let cmd: string, args: string[], yes: (out: string, code: number | null) => boolean;
  const env = { ...process.env, LLY_MSG: message };
  if (platform === 'darwin') {
    cmd = '/usr/bin/osascript';
    args = ['-e', 'on run argv', '-e', `display dialog (item 1 of argv) with title "LLLanyard" buttons {"Deny", "Run"} default button "Deny" cancel button "Deny" with icon caution giving up after ${t}`, '-e', 'end run', '--', message];
    yes = (out, code) => code === 0 && /button returned:Run\b/.test(out) && !/gave up:true/.test(out);
  } else if (platform === 'win32') {
    cmd = 'powershell.exe';
    const ps = 'Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.Form -Property @{TopMost=$true}; ' +
      "$r = [System.Windows.Forms.MessageBox]::Show($f, $env:LLY_MSG, 'LLLanyard', 'YesNo', 'Warning', 'Button2'); if ($r -eq 'Yes') { 'RUN' }";
    args = ['-NoProfile', '-NonInteractive', '-Command', ps];
    yes = (out, code) => code === 0 && out.trim() === 'RUN';
  } else {
    cmd = 'zenity';
    args = ['--question', '--no-markup', '--title=LLLanyard', `--text=${message}`, '--ok-label=Run', '--cancel-label=Deny', '--default-cancel', `--timeout=${t}`];
    yes = (_out, code) => code === 0;
  }
  return new Promise((resolve) => {
    let out = '';
    let child;
    try { child = (opts.spawnFn ?? spawn)(cmd, args, { env, stdio: ['ignore', 'pipe', 'ignore'] }); } catch { resolve(false); return; }
    const timer = setTimeout(() => child.kill(), (t + 10) * 1000);
    child.stdout?.on('data', (d) => { out += String(d); });
    child.once('error', () => { clearTimeout(timer); resolve(false); });
    child.once('close', (code) => { clearTimeout(timer); resolve(yes(out, code)); });
  });
}
