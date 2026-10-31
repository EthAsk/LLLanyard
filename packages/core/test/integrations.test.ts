import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, symlinkSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  claudeCodeBlock, claudeCodeMemoryPath, claudeCodeStatus, claudeDesktopConfigPath, claudeDesktopStatus, connectClaudeCode,
  connectClaudeDesktop, disconnectClaudeCode, disconnectClaudeDesktop, stableNodePath,
} from '../src/index.js';

function home() {
  const h = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'lly-int-')));
  const scripts = path.join(h, 'Scripts');
  mkdirSync(scripts);
  writeFileSync(path.join(h, 'node'), ''); writeFileSync(path.join(h, 'cli.js'), '');
  const o = { platform: 'darwin' as const, home: h, env: {} };
  return { h, scripts, o, launch: { node: path.join(h, 'node'), cli: path.join(h, 'cli.js'), pathVar: '/usr/local/bin:/usr/bin' }, done: () => rmSync(h, { recursive: true, force: true }) };
}

test('config paths per OS', () => {
  assert.equal(claudeDesktopConfigPath({ platform: 'darwin', home: '/Users/a' }), '/Users/a/Library/Application Support/Claude/claude_desktop_config.json');
  assert.equal(claudeDesktopConfigPath({ platform: 'win32', home: 'C:\\Users\\a', env: { APPDATA: 'C:\\Users\\a\\AppData\\Roaming' } }), 'C:\\Users\\a\\AppData\\Roaming\\Claude\\claude_desktop_config.json');
  assert.equal(claudeDesktopConfigPath({ platform: 'linux', home: '/home/a', env: {} }), '/home/a/.config/Claude/claude_desktop_config.json');
  assert.equal(claudeCodeMemoryPath({ home: '/h', env: { CLAUDE_CONFIG_DIR: '/cfg' } }), path.join('/cfg', 'CLAUDE.md'));
});

test('Claude Desktop: connect keeps other settings, backs up, updates in place, disconnects', () => {
  const t = home();
  try {
    const file = claudeDesktopConfigPath(t.o);
    assert.equal(claudeDesktopStatus(t.o).connected, false);
    mkdirSync(path.dirname(file), { recursive: true });
    const before = { theme: 'dark', mcpServers: { other: { command: 'x' } } };
    writeFileSync(file, JSON.stringify(before));
    const r = connectClaudeDesktop(t.launch, [t.scripts], t.o);
    assert.equal(r.backup, `${file}.lllanyard-backup`);
    assert.deepEqual(JSON.parse(readFileSync(r.backup!, 'utf8')), before);
    const cfg = JSON.parse(readFileSync(file, 'utf8'));
    assert.equal(cfg.theme, 'dark');
    assert.deepEqual(cfg.mcpServers.other, { command: 'x' });
    assert.deepEqual(cfg.mcpServers.lllanyard, { command: t.launch.node, args: [t.launch.cli, 'mcp', '--run', '--scripts-dir', t.scripts], env: { PATH: t.launch.pathVar } });
    assert.deepEqual(claudeDesktopStatus(t.o), { file, connected: true, scriptDirs: [t.scripts] });
    connectClaudeDesktop(t.launch, [], t.o);
    assert.deepEqual(claudeDesktopStatus(t.o).scriptDirs, []);
    rmSync(t.launch.cli);
    assert.match(claudeDesktopStatus(t.o).problem!, /no longer exists/);
    assert.equal(disconnectClaudeDesktop(t.o).removed, true);
    assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), before);
    assert.equal(disconnectClaudeDesktop(t.o).removed, false);
  } finally { t.done(); }
});

test('Claude Desktop: creates a missing config; refuses broken JSON and bad folders without writing', () => {
  const t = home();
  try {
    const file = claudeDesktopConfigPath(t.o);
    connectClaudeDesktop(t.launch, [], t.o);
    assert.ok(JSON.parse(readFileSync(file, 'utf8')).mcpServers.lllanyard);
    writeFileSync(file, '{ not json');
    assert.throws(() => connectClaudeDesktop(t.launch, [], t.o), /isn't valid JSON/);
    assert.equal(readFileSync(file, 'utf8'), '{ not json');
    assert.match(claudeDesktopStatus(t.o).problem!, /valid JSON/);
    writeFileSync(file, '{}');
    assert.throws(() => connectClaudeDesktop(t.launch, [t.h], t.o), /too broad/);
    assert.throws(() => connectClaudeDesktop(t.launch, [path.join(t.h, 'nope')], t.o), /not found/);
    assert.equal(readFileSync(file, 'utf8'), '{}');
  } finally { t.done(); }
});

test('Claude Code: adds a marked block once, keeps the rest, removes cleanly', () => {
  const t = home();
  try {
    const file = claudeCodeMemoryPath(t.o);
    connectClaudeCode(t.o);
    assert.equal(readFileSync(file, 'utf8'), claudeCodeBlock());
    writeFileSync(file, '# Mine\n\nKeep this.\n');
    connectClaudeCode(t.o);
    connectClaudeCode(t.o);
    const text = readFileSync(file, 'utf8');
    assert.equal(text, '# Mine\n\nKeep this.\n\n' + claudeCodeBlock());
    assert.equal(claudeCodeStatus(t.o).connected, true);
    assert.equal(disconnectClaudeCode(t.o).removed, true);
    assert.equal(readFileSync(file, 'utf8'), '# Mine\n\nKeep this.\n');
    assert.equal(claudeCodeStatus(t.o).connected, false);
    assert.ok(existsSync(`${file}.lllanyard-backup`));
  } finally { t.done(); }
});

test('node path: a stable link to the same node is preferred over a versioned one', { skip: process.platform === 'win32' }, () => {
  const t = home();
  try {
    const cellar = path.join(t.h, 'Cellar', 'node', '26.1', 'bin'), bin = path.join(t.h, 'bin'), other = path.join(t.h, 'other');
    for (const d of [cellar, bin, other]) mkdirSync(d, { recursive: true });
    writeFileSync(path.join(cellar, 'node'), '');
    writeFileSync(path.join(other, 'node'), '');
    symlinkSync(path.join(cellar, 'node'), path.join(bin, 'node'));
    const exec = path.join(cellar, 'node');
    assert.equal(stableNodePath(exec, [other, bin].join(path.delimiter)), path.join(bin, 'node'));
    assert.equal(stableNodePath(exec, other), exec);
  } finally { t.done(); }
});
