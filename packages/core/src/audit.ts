import { openSync, readdirSync, readSync, closeSync, readFileSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { keyIsEncrypted } from './ssh.js';

/**
 * `lllanyard audit`: what an AI agent running as you could still get at, and how to close each gap. It reports where
 * things are and masked values, never a secret.
 */
export type Severity = 'high' | 'medium' | 'info';
export interface AuditFinding { severity: Severity; title: string; details?: string[]; fix?: string }

export interface AuditInput {
  home: string;
  /** Plaintext keys found by `scan` (masked). */
  plaintext: { provider: string; masked: string; file: string; line: number }[];
  /** Private keys sitting on disk. */
  diskKeys: { file: string; encrypted: boolean }[];
  /** Stored keys whose rotation is overdue or due soon. */
  rotation: { name: string; state: 'ok' | 'due-soon' | 'overdue'; dueInDays: number }[];
  /** SSH logins whose expiry has passed. */
  expiredLogins: string[];
  /** Key-shaped strings found in test files: usually fixtures, so they are mentioned but not counted as problems. */
  inTests?: number;
  /** Other Claude Code folders (for people who keep separate profiles), each with its own settings. */
  claudeProfiles?: { dir: string; connected: boolean; hooks: boolean }[];
  apps: { id: string; name: string; installed: boolean; connected: boolean; hooks?: boolean }[];
}

/** A path with the home folder shown as ~, whichever separator the path uses (Windows accepts both). */
const tilde = (f: string, home: string) => (f === home || f.startsWith(home + '/') || f.startsWith(home + '\\') ? '~' + f.slice(home.length) : f);

export function buildAudit(i: AuditInput): AuditFinding[] {
  const out: AuditFinding[] = [];
  if (i.plaintext.length) {
    const shown = i.plaintext.slice(0, 8).map((f) => `${f.provider.padEnd(10)} ${f.masked.padEnd(16)} ${tilde(f.file, i.home)}:${f.line}`);
    if (i.plaintext.length > 8) shown.push(`…and ${i.plaintext.length - 8} more`);
    out.push({ severity: 'high', title: `${i.plaintext.length} plaintext key${i.plaintext.length === 1 ? '' : 's'} in files an AI agent can read`, details: shown, fix: 'lllanyard scan --import --apply --redact   (moves supported keys into the keychain and blanks them in the file)' });
  }
  if (i.inTests) out.push({ severity: 'info', title: `${i.inTests} key-shaped string${i.inTests === 1 ? '' : 's'} in test files (usually fixtures, not counted above)`, fix: 'lllanyard scan <folder>   to list them' });
  for (const k of i.diskKeys)
    out.push({
      severity: k.encrypted ? 'medium' : 'high',
      title: `SSH private key on disk${k.encrypted ? ' (passphrase protected)' : ' with no passphrase'}: ${tilde(k.file, i.home)}`,
      details: [k.encrypted ? 'An agent running as you can copy this file; only its passphrase protects it.' : 'An agent running as you can read this file and use the server.'],
      fix: `lllanyard ssh add <name> --host user@host --key-file ${tilde(k.file, i.home)}   then check it works and delete the file`,
    });
  const bad = i.rotation.filter((r) => r.state === 'overdue');
  if (bad.length) out.push({ severity: 'medium', title: `${bad.length} key${bad.length === 1 ? ' is' : 's are'} overdue for rotation`, details: bad.map((r) => `${r.name} (${-r.dueInDays} days late)`), fix: 'lllanyard rotate <provider>' });
  const soon = i.rotation.filter((r) => r.state === 'due-soon');
  if (soon.length) out.push({ severity: 'info', title: `${soon.length} key${soon.length === 1 ? '' : 's'} due for rotation soon`, details: soon.map((r) => `${r.name} (in ${r.dueInDays} days)`) });
  if (i.expiredLogins.length) out.push({ severity: 'info', title: `${i.expiredLogins.length} SSH login${i.expiredLogins.length === 1 ? ' has' : 's have'} expired`, details: i.expiredLogins, fix: 'lllanyard ssh policy <name> --expires 30d   (or lllanyard ssh remove <name>)' });
  for (const c of i.claudeProfiles ?? []) {
    const d = tilde(c.dir, i.home);
    if (!c.connected) out.push({ severity: 'medium', title: `Claude Code profile ${d} is not set up to use LLLanyard`, details: ['This profile has its own settings, so setup for your main profile doesn\'t cover it.'], fix: `lllanyard setup claude-code --hooks --config-dir ${d}` });
    else if (!c.hooks) out.push({ severity: 'medium', title: `Claude Code profile ${d} is asked to avoid secrets, but nothing stops it`, fix: `lllanyard setup claude-code --hooks --config-dir ${d}` });
  }
  for (const a of i.apps) {
    if (a.installed && !a.connected) out.push({ severity: 'medium', title: `${a.name} is installed but not set up to use LLLanyard`, details: ['Nothing tells it to use lllanyard exec or lllanyard ssh, so it will look for keys in files.'], fix: `lllanyard setup ${a.id}` });
    if (a.id === 'claude-code' && a.connected && !a.hooks) out.push({ severity: 'medium', title: 'Claude Code is asked to avoid .env files and SSH keys, but nothing stops it', details: ['The instructions are a request. A hook makes Claude Code refuse the call.'], fix: 'lllanyard setup claude-code --hooks' });
  }
  return out;
}

export interface Tally { high: number; medium: number; info: number }
export const tally = (f: AuditFinding[]): Tally => ({ high: f.filter((x) => x.severity === 'high').length, medium: f.filter((x) => x.severity === 'medium').length, info: f.filter((x) => x.severity === 'info').length });

const SSH_SKIP = /^(known_hosts.*|config|authorized_keys.*|.*\.pub|environment|rc)$/;

/** Private keys in ~/.ssh: any file that starts like one. Reads the first bytes only, and the whole file to see whether it has a passphrase. */
export function findDiskSshKeys(home = os.homedir()): { file: string; encrypted: boolean }[] {
  const dir = path.join(home, '.ssh');
  let names: string[];
  try { names = readdirSync(dir); } catch { return []; }
  const found: { file: string; encrypted: boolean }[] = [];
  for (const n of names) {
    if (SSH_SKIP.test(n)) continue;
    const f = path.join(dir, n);
    try {
      if (!statSync(f).isFile()) continue;
      const fd = openSync(f, 'r');
      const buf = Buffer.alloc(64);
      const len = readSync(fd, buf, 0, 64, 0);
      closeSync(fd);
      if (!/^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(buf.subarray(0, len).toString('latin1'))) continue;
      const text = statSync(f).size <= 50_000 ? readFileSync(f, 'latin1') : '';
      found.push({ file: f, encrypted: text ? keyIsEncrypted(text) : false });
    } catch { /* unreadable: not ours to report */ }
  }
  return found.sort((a, b) => a.file.localeCompare(b.file));
}

/** Test files, where a key-shaped string is nearly always a fixture. */
export const isTestFile = (f: string) => /(^|[\\/])(tests?|__tests__|fixtures?|spec)[\\/]|\.(test|spec)\.[A-Za-z]+$/.test(f);

/** Other Claude Code folders next to ~/.claude (~/.claude-work, ~/.claude-client...), skipping the one in use. */
export function findClaudeProfiles(home: string, active: string): string[] {
  try {
    return readdirSync(home).filter((n) => /^\.claude[-_.].+/.test(n)).map((n) => path.join(home, n)).filter((d) => path.resolve(d) !== path.resolve(active) && (() => { try { return statSync(d).isDirectory(); } catch { return false; } })()).sort();
  } catch { return []; }
}

export function renderAudit(findings: AuditFinding[]): string {
  if (!findings.length) return 'Nothing to fix: no plaintext keys or private keys on disk, and the AI tools found here use LLLanyard.';
  const label = { high: 'HIGH  ', medium: 'MEDIUM', info: 'INFO  ' } as const;
  const lines: string[] = [];
  for (const f of findings) {
    lines.push(`${label[f.severity]} ${f.title}`);
    for (const d of f.details ?? []) lines.push(`         ${d}`);
    if (f.fix) lines.push(`       fix: ${f.fix}`);
    lines.push('');
  }
  const t = tally(findings);
  lines.push(`${t.high} high, ${t.medium} medium, ${t.info} for information.`);
  return lines.join('\n');
}

