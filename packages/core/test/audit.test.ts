import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildAudit, findDiskSshKeys, generateKey, renderAudit, tally, type AuditInput } from '../src/index.js';

const base: AuditInput = { home: '/Users/me', plaintext: [], diskKeys: [], rotation: [], expiredLogins: [], apps: [] };

test('audit: a clean machine reports nothing', () => {
  assert.deepEqual(buildAudit(base), []);
  assert.match(renderAudit([]), /Nothing to fix/);
});

test('audit: plaintext keys are high, masked, capped, and come with the fix', () => {
  const plaintext = Array.from({ length: 10 }, (_, n) => ({ provider: 'openai', masked: 'sk-…abcd', file: '/Users/me/.zshrc', line: n + 1 }));
  const [f] = buildAudit({ ...base, plaintext });
  assert.equal(f!.severity, 'high');
  assert.match(f!.title, /^10 plaintext keys/);
  assert.equal(f!.details!.length, 9); // 8 shown + "and 2 more"
  assert.match(f!.details!.at(-1)!, /and 2 more/);
  assert.match(f!.details![0]!, /~\/\.zshrc:1/);
  assert.match(f!.fix!, /scan --import --apply --redact/);
});

test('audit: an SSH key with no passphrase is high, one with a passphrase is medium', () => {
  const f = buildAudit({ ...base, diskKeys: [{ file: '/Users/me/.ssh/a', encrypted: false }, { file: '/Users/me/.ssh/b', encrypted: true }] });
  assert.deepEqual(f.map((x) => x.severity), ['high', 'medium']);
  assert.match(f[0]!.title, /with no passphrase: ~\/\.ssh\/a/);
  assert.match(f[1]!.title, /passphrase protected/);
});

test('audit: tools that are installed but not connected, and Claude Code without its hook', () => {
  const f = buildAudit({ ...base, apps: [
    { id: 'codex', name: 'OpenAI Codex', installed: true, connected: false },
    { id: 'gemini', name: 'Gemini CLI', installed: false, connected: false }, // not installed: nothing to say
    { id: 'claude-code', name: 'Claude Code', installed: true, connected: true, hooks: false },
    { id: 'cursor', name: 'Cursor', installed: true, connected: true },
  ] });
  assert.equal(f.length, 2);
  assert.equal(f[0]!.fix, 'lllanyard setup codex');
  assert.equal(f[1]!.fix, 'lllanyard setup claude-code --hooks');
  assert.equal(buildAudit({ ...base, apps: [{ id: 'claude-code', name: 'Claude Code', installed: true, connected: true, hooks: true }] }).length, 0);
});

test('audit: rotation and expired logins', () => {
  const f = buildAudit({ ...base, rotation: [{ name: 'openai/default', state: 'overdue', dueInDays: -12 }, { name: 'github/x', state: 'due-soon', dueInDays: 5 }, { name: 'a/b', state: 'ok', dueInDays: 80 }], expiredLogins: ['prod'] });
  assert.deepEqual(f.map((x) => x.severity), ['medium', 'info', 'info']);
  assert.deepEqual(f[0]!.details, ['openai/default (12 days late)']);
  assert.deepEqual(tally(f), { high: 0, medium: 1, info: 2 });
  assert.match(renderAudit(f), /0 high, 1 medium, 2 for information\./);
});

test('audit: finds private keys in ~/.ssh and ignores public keys, known_hosts and config', () => {
  const home = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'lly-audit-')));
  try {
    const dir = path.join(home, '.ssh');
    mkdirSync(dir);
    const { privateKey, publicKey } = generateKey('t');
    writeFileSync(path.join(dir, 'id_ed25519'), privateKey, { mode: 0o600 });
    writeFileSync(path.join(dir, 'id_ed25519.pub'), publicKey);
    writeFileSync(path.join(dir, 'known_hosts'), 'host ssh-ed25519 AAAA\n');
    writeFileSync(path.join(dir, 'config'), 'Host x\n');
    writeFileSync(path.join(dir, 'notes.txt'), 'not a key\n');
    mkdirSync(path.join(dir, 'sub'));
    chmodSync(dir, 0o700);
    assert.deepEqual(findDiskSshKeys(home), [{ file: path.join(dir, 'id_ed25519'), encrypted: false }]);
    assert.deepEqual(findDiskSshKeys(path.join(home, 'nope')), []);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

import { findClaudeProfiles, isTestFile } from '../src/index.js';

test('audit: key-shaped strings in test files are mentioned, not counted as problems', () => {
  const f = buildAudit({ ...base, inTests: 3 });
  assert.equal(f.length, 1);
  assert.equal(f[0]!.severity, 'info');
  assert.match(f[0]!.title, /^3 key-shaped strings in test files/);
  assert.equal(isTestFile('/p/packages/core/test/mcp.test.ts'), true);
  assert.equal(isTestFile('/p/src/__tests__/a.ts'), true);
  assert.equal(isTestFile('/p/src/login.spec.js'), true);
  assert.equal(isTestFile('C:\\p\\tests\\a.ts'), true);
  assert.equal(isTestFile('/p/src/latest.ts'), false);
  assert.equal(isTestFile('/p/.env'), false);
  assert.equal(isTestFile('/Users/me/.zshrc'), false);
});

test('audit: other Claude Code profiles are reported when not set up, and when they have no hook', () => {
  const f = buildAudit({ ...base, claudeProfiles: [{ dir: '/Users/me/.claude-work', connected: false, hooks: false }, { dir: '/Users/me/.claude-b', connected: true, hooks: false }, { dir: '/Users/me/.claude-c', connected: true, hooks: true }] });
  assert.equal(f.length, 2);
  assert.match(f[0]!.title, /profile ~\/\.claude-work is not set up/);
  assert.equal(f[0]!.fix, 'lllanyard setup claude-code --hooks --config-dir ~/.claude-work');
  assert.match(f[1]!.fix!, /--config-dir ~\/\.claude-b$/);
  assert.match(f[1]!.title, /profile ~\/\.claude-b is asked to avoid secrets/);
});

test('audit: finds extra Claude Code folders next to the active one, ignoring files and the active folder', () => {
  const home = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'lly-prof-')));
  try {
    for (const d of ['.claude', '.claude-work', '.claude_client', '.config']) mkdirSync(path.join(home, d));
    writeFileSync(path.join(home, '.claude.json'), '{}');
    writeFileSync(path.join(home, '.claude-notes'), 'a file, not a profile');
    assert.deepEqual(findClaudeProfiles(home, path.join(home, '.claude')), [path.join(home, '.claude-work'), path.join(home, '.claude_client')]);
    assert.deepEqual(findClaudeProfiles(home, path.join(home, '.claude-work')).map((x) => path.basename(x)), ['.claude_client']);
    assert.deepEqual(findClaudeProfiles(path.join(home, 'nope'), '/x'), []);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('audit: a Windows home folder is shown as ~ too, whichever separator the path uses', () => {
  const f = buildAudit({ ...base, home: 'C:\\Users\\me', plaintext: [{ provider: 'openai', masked: 'sk-…abcd', file: 'C:\\Users\\me\\.zshrc', line: 2 }, { provider: 'openai', masked: 'sk-…abcd', file: 'C:\\Users\\me/proj/.env', line: 3 }] });
  assert.match(f[0]!.details![0]!, /~\\\.zshrc:2/);
  assert.match(f[0]!.details![1]!, /~\/proj\/\.env:3/);
});
