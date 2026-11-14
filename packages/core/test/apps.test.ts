import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { APPS, findApp, JSON_TARGETS } from '../src/index.js';

function home() {
  const h = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'lly-apps-')));
  return { h, o: { platform: 'darwin' as const, home: h, env: {} }, launch: { node: '/n/node', cli: '/c/cli.js', pathVar: '/usr/bin' }, done: () => rmSync(h, { recursive: true, force: true }) };
}

test('apps: the registry lists each tool once, with a summary', () => {
  const ids = APPS.map((a) => a.id);
  assert.deepEqual(ids, ['claude-code', 'codex', 'copilot', 'gemini', 'windsurf', 'cursor']);
  assert.equal(new Set(ids).size, ids.length);
  for (const a of APPS) assert.ok(a.summary.length > 20 && a.name);
  assert.equal(findApp('nope'), undefined);
});

test('apps: Gemini CLI and Windsurf get instructions and the MCP server; Cursor gets the MCP server and a note', () => {
  for (const id of ['gemini', 'windsurf', 'cursor']) {
    const t = home();
    try {
      const app = findApp(id)!, target = JSON_TARGETS.find((x) => x.id === id)!;
      assert.equal(app.installed(t.o), false);
      mkdirSync(path.dirname(target.mcpFile(t.o)), { recursive: true });
      assert.equal(app.installed(t.o), true);
      const mine = { theme: 'dark', mcpServers: { other: { command: 'x' } } };
      writeFileSync(target.mcpFile(t.o), JSON.stringify(mine));
      assert.equal(app.status(t.o).connected, false);
      const r = app.connect(t.launch, t.o);
      const cfg = JSON.parse(readFileSync(target.mcpFile(t.o), 'utf8'));
      assert.equal(cfg.theme, 'dark');
      assert.deepEqual(cfg.mcpServers.other, { command: 'x' });
      assert.deepEqual(cfg.mcpServers.lllanyard, { command: '/n/node', args: ['/c/cli.js', 'mcp', '--run'], env: { PATH: '/usr/bin' } });
      assert.equal(r.files.length, target.instructionsFile ? 2 : 1);
      if (target.instructionsFile) assert.match(readFileSync(target.instructionsFile(t.o), 'utf8'), /lllanyard exec/);
      else assert.match(r.note!, /global rules are in its settings/);
      assert.equal(app.status(t.o).connected, true);
      app.connect(t.launch, t.o); // again: nothing duplicated
      if (target.instructionsFile) assert.equal(readFileSync(target.instructionsFile(t.o), 'utf8').match(/lllanyard:start/g)!.length, 1);
      assert.equal(app.disconnect(t.o).removed, true);
      assert.deepEqual(JSON.parse(readFileSync(target.mcpFile(t.o), 'utf8')), mine);
      assert.equal(app.status(t.o).connected, false);
      assert.equal(app.disconnect(t.o).removed, false);
    } finally { t.done(); }
  }
});

test('apps: a settings file that is not valid JSON is refused and nothing else is written', () => {
  const t = home();
  try {
    const target = JSON_TARGETS.find((x) => x.id === 'gemini')!;
    mkdirSync(path.dirname(target.mcpFile(t.o)), { recursive: true });
    writeFileSync(target.mcpFile(t.o), '{ nope');
    assert.throws(() => findApp('gemini')!.connect(t.launch, t.o), /isn't valid JSON/);
    assert.equal(existsSync(target.instructionsFile!(t.o)), false);
  } finally { t.done(); }
});

test('apps: Claude Code and Codex go through the same registry', () => {
  const t = home();
  try {
    for (const id of ['claude-code', 'codex', 'copilot']) {
      const a = findApp(id)!;
      assert.equal(a.status(t.o).connected, false, id);
      a.connect(t.launch, t.o);
      assert.equal(a.status(t.o).connected, true, id);
      assert.equal(a.disconnect(t.o).removed, true, id);
      assert.equal(a.status(t.o).connected, false, id);
    }
  } finally { t.done(); }
});

import { onPath } from '../src/index.js';

test('apps: Copilot CLI counts as installed only if its command is on PATH or it has been set up, not just because ~/.copilot exists', () => {
  const t = home();
  try {
    mkdirSync(path.join(t.h, '.copilot', 'logs'), { recursive: true }); // what VS Code's Copilot extension leaves behind
    const copilot = findApp('copilot')!;
    assert.equal(copilot.installed(t.o), false);
    const bin = path.join(t.h, 'bin');
    mkdirSync(bin);
    writeFileSync(path.join(bin, 'copilot'), '#!/bin/sh\n', { mode: 0o755 });
    assert.equal(copilot.installed({ ...t.o, env: { PATH: bin } }), true);
    assert.equal(onPath('copilot', { PATH: bin }), true);
    assert.equal(onPath('nothing-here', { PATH: bin }), false);
    assert.equal(onPath('copilot', {}), false);
    copilot.connect(t.launch, t.o);
    assert.equal(copilot.installed(t.o), true); // set up once, so it's there
  } finally { t.done(); }
});

test('apps: Codex and Gemini are detected by their folder or their command', () => {
  const t = home();
  try {
    assert.equal(findApp('codex')!.installed(t.o), false);
    mkdirSync(path.join(t.h, '.codex'));
    assert.equal(findApp('codex')!.installed(t.o), true);
    const bin = path.join(t.h, 'bin');
    mkdirSync(bin);
    writeFileSync(path.join(bin, 'gemini'), '', { mode: 0o755 });
    assert.equal(findApp('gemini')!.installed({ ...t.o, env: { PATH: bin } }), true);
    assert.equal(findApp('gemini')!.installed(t.o), false);
  } finally { t.done(); }
});
