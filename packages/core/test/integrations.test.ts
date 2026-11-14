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

import {
  agentFileConnected, codexAgentsPath, codexConfigPath, codexStatus, connectAgentFile, connectCodex, connectCopilotCli, connectCopilotProject,
  copilotCliInstructionsPath, copilotCliMcpPath, copilotStatus, disconnectAgentFile, disconnectCodex, disconnectCopilotCli, disconnectCopilotProject,
  genericMcpSnippet, projectInstructionsPath, projectMcpPath,
} from '../src/index.js';

test('Codex: adds instructions and an MCP table, keeps the rest, updates in place, removes cleanly', () => {
  const t = home();
  try {
    const cfg = codexConfigPath(t.o), md = codexAgentsPath(t.o);
    mkdirSync(path.dirname(cfg), { recursive: true });
    writeFileSync(cfg, 'model = "gpt-5"\n\n[mcp_servers.other]\ncommand = "x"\n');
    writeFileSync(md, '# My rules\n');
    assert.equal(codexStatus(t.o).connected, false);
    connectCodex(t.launch, t.o);
    const toml = readFileSync(cfg, 'utf8');
    assert.match(toml, /^model = "gpt-5"/);
    assert.match(toml, /\[mcp_servers\.other\]/);
    assert.match(toml, /\[mcp_servers\.lllanyard\]\ncommand = ".*node"\nargs = \[".*cli\.js", "mcp", "--run"\]\nenv = \{ PATH = "\/usr\/local\/bin:\/usr\/bin" \}/);
    assert.match(readFileSync(md, 'utf8'), /^# My rules\n\n<!-- lllanyard:start/);
    assert.deepEqual(codexStatus(t.o), { file: path.dirname(cfg), connected: true, mcp: true, instructions: true });
    connectCodex(t.launch, t.o); // again: replaced, not duplicated
    assert.equal(readFileSync(cfg, 'utf8').match(/\[mcp_servers\.lllanyard\]/g)!.length, 1);
    assert.equal(readFileSync(md, 'utf8').match(/lllanyard:start/g)!.length, 1);
    assert.equal(disconnectCodex(t.o).removed, true);
    assert.equal(readFileSync(cfg, 'utf8'), 'model = "gpt-5"\n\n[mcp_servers.other]\ncommand = "x"\n');
    assert.equal(readFileSync(md, 'utf8'), '# My rules\n');
    assert.equal(disconnectCodex(t.o).removed, false);
  } finally { t.done(); }
});

test('Codex: refuses to add a second table when the user already has one of that name', () => {
  const t = home();
  try {
    const cfg = codexConfigPath(t.o);
    mkdirSync(path.dirname(cfg), { recursive: true });
    const mine = '[mcp_servers.lllanyard]\ncommand = "mine"\n';
    writeFileSync(cfg, mine);
    assert.throws(() => connectCodex(t.launch, t.o), /already has an \[mcp_servers\.lllanyard\] entry/);
    assert.equal(readFileSync(cfg, 'utf8'), mine);
    assert.equal(existsSync(codexAgentsPath(t.o)), false); // nothing half-done
  } finally { t.done(); }
});

test('Codex: a Windows path is written as a valid TOML string', () => {
  const t = home();
  try {
    connectCodex({ node: 'C:\\Program Files\\nodejs\\node.exe', cli: 'C:\\x\\cli.js', pathVar: 'C:\\a;C:\\b' }, t.o);
    assert.match(readFileSync(codexConfigPath(t.o), 'utf8'), /command = "C:\\\\Program Files\\\\nodejs\\\\node\.exe"/);
  } finally { t.done(); }
});

test('Copilot CLI: instructions and mcp-config.json, other servers kept, removable', () => {
  const t = home();
  try {
    const mcp = copilotCliMcpPath(t.o);
    mkdirSync(path.dirname(mcp), { recursive: true });
    writeFileSync(mcp, JSON.stringify({ mcpServers: { other: { command: 'x' } } }));
    assert.equal(copilotStatus(undefined, t.o).cli, false);
    connectCopilotCli(t.launch, t.o);
    const cfg = JSON.parse(readFileSync(mcp, 'utf8'));
    assert.deepEqual(cfg.mcpServers.other, { command: 'x' });
    assert.deepEqual(cfg.mcpServers.lllanyard, { type: 'local', command: t.launch.node, args: [t.launch.cli, 'mcp', '--run'], env: { PATH: t.launch.pathVar }, tools: ['*'] });
    assert.match(readFileSync(copilotCliInstructionsPath(t.o), 'utf8'), /lllanyard exec/);
    assert.equal(copilotStatus(undefined, t.o).cli, true);
    assert.equal(disconnectCopilotCli(t.o).removed, true);
    assert.deepEqual(JSON.parse(readFileSync(mcp, 'utf8')), { mcpServers: { other: { command: 'x' } } });
    assert.equal(readFileSync(copilotCliInstructionsPath(t.o), 'utf8'), '');
    assert.equal(disconnectCopilotCli(t.o).removed, false);
  } finally { t.done(); }
});

test('Copilot project: shareable files with no machine paths; removable', () => {
  const t = home();
  try {
    const proj = path.join(t.h, 'proj');
    mkdirSync(path.join(proj, '.vscode'), { recursive: true });
    writeFileSync(projectMcpPath(proj), JSON.stringify({ servers: { other: { command: 'x' } } }));
    connectCopilotProject(proj);
    const cfg = JSON.parse(readFileSync(projectMcpPath(proj), 'utf8'));
    assert.deepEqual(cfg.servers.lllanyard, { type: 'stdio', command: 'lllanyard', args: ['mcp', '--run'] });
    assert.deepEqual(cfg.servers.other, { command: 'x' });
    assert.ok(!readFileSync(projectInstructionsPath(proj), 'utf8').includes(t.h));
    assert.equal(copilotStatus(proj, t.o).project, true);
    assert.equal(disconnectCopilotProject(proj).removed, true);
    assert.deepEqual(JSON.parse(readFileSync(projectMcpPath(proj), 'utf8')), { servers: { other: { command: 'x' } } });
  } finally { t.done(); }
});

test('Copilot: bad JSON or a non-object server list is refused without writing anything', () => {
  const t = home();
  try {
    const mcp = copilotCliMcpPath(t.o);
    mkdirSync(path.dirname(mcp), { recursive: true });
    writeFileSync(mcp, '{ not json');
    assert.throws(() => connectCopilotCli(t.launch, t.o), /isn't valid JSON/);
    assert.equal(existsSync(copilotCliInstructionsPath(t.o)), false);
    writeFileSync(mcp, JSON.stringify({ mcpServers: [] }));
    assert.throws(() => connectCopilotCli(t.launch, t.o), /isn't an object/);
    assert.equal(existsSync(copilotCliInstructionsPath(t.o)), false);
  } finally { t.done(); }
});

test('generic agent: instructions go into any file, and the MCP snippet is plain JSON', () => {
  const t = home();
  try {
    const f = path.join(t.h, 'AGENTS.md');
    writeFileSync(f, '# Project\n');
    assert.equal(agentFileConnected(f), false);
    connectAgentFile(f);
    assert.equal(agentFileConnected(f), true);
    assert.match(readFileSync(f, 'utf8'), /^# Project\n\n<!-- lllanyard:start/);
    assert.equal(disconnectAgentFile(f).removed, true);
    assert.equal(readFileSync(f, 'utf8'), '# Project\n');
    assert.deepEqual(JSON.parse(genericMcpSnippet()), { mcpServers: { lllanyard: { command: 'lllanyard', args: ['mcp', '--run'] } } });
  } finally { t.done(); }
});

import { claudeHooksStatus, claudeSettingsPath, connectClaudeHooks, disconnectClaudeHooks, hookCommand } from '../src/index.js';

test('Claude Code hook: added beside the user\'s own hooks and settings, refreshed in place, removed cleanly', () => {
  const t = home();
  try {
    const file = claudeSettingsPath(t.o);
    mkdirSync(path.dirname(file), { recursive: true });
    const mine = { model: 'opus', hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'my-linter' }] }], PostToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'fmt' }] }] } };
    writeFileSync(file, JSON.stringify(mine));
    assert.equal(claudeHooksStatus(t.o), false);
    assert.equal(claudeCodeStatus(t.o).hooks, false);
    connectClaudeHooks(t.launch, t.o);
    let cfg = JSON.parse(readFileSync(file, 'utf8'));
    assert.equal(cfg.model, 'opus');
    assert.deepEqual(cfg.hooks.PostToolUse, mine.hooks.PostToolUse);
    assert.equal(cfg.hooks.PreToolUse.length, 2);
    assert.deepEqual(cfg.hooks.PreToolUse[0], mine.hooks.PreToolUse[0]);
    assert.deepEqual(cfg.hooks.PreToolUse[1].hooks, [{ type: 'command', command: hookCommand(t.launch) }]);
    assert.match(cfg.hooks.PreToolUse[1].matcher, /Read.*Bash/);
    assert.equal(claudeHooksStatus(t.o), true);
    connectClaudeHooks({ ...t.launch, cli: '/new/cli.js' }, t.o); // run again after moving LLLanyard: replaced, not duplicated
    cfg = JSON.parse(readFileSync(file, 'utf8'));
    assert.equal(cfg.hooks.PreToolUse.length, 2);
    assert.match(cfg.hooks.PreToolUse[1].hooks[0].command, /\/new\/cli\.js" hook claude-code$/);
    assert.equal(disconnectClaudeHooks(t.o).removed, true);
    assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), mine);
    assert.equal(disconnectClaudeHooks(t.o).removed, false);
  } finally { t.done(); }
});

test('Claude Code hook: starts from no settings file, and removing leaves no empty hooks object', () => {
  const t = home();
  try {
    connectClaudeHooks(t.launch, t.o);
    assert.equal(disconnectClaudeHooks(t.o).removed, true);
    assert.deepEqual(JSON.parse(readFileSync(claudeSettingsPath(t.o), 'utf8')), {});
  } finally { t.done(); }
});

test('Claude Code hook: bad settings are refused without writing; the command quotes paths with spaces', () => {
  const t = home();
  try {
    const file = claudeSettingsPath(t.o);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, '{ nope');
    assert.throws(() => connectClaudeHooks(t.launch, t.o), /isn't valid JSON/);
    writeFileSync(file, JSON.stringify({ hooks: [] }));
    assert.throws(() => connectClaudeHooks(t.launch, t.o), /isn't an object/);
    writeFileSync(file, JSON.stringify({ hooks: { PreToolUse: {} } }));
    assert.throws(() => connectClaudeHooks(t.launch, t.o), /isn't a list/);
    assert.equal(hookCommand({ node: '/opt/n/node', cli: '/My Files/LLLanyard/cli.js', pathVar: '' }), '"/opt/n/node" "/My Files/LLLanyard/cli.js" hook claude-code');
  } finally { t.done(); }
});
