import test from 'node:test';
import assert from 'node:assert/strict';
import { claudeDesktopRunning, withClaudeDesktopClosed, type AppSys } from '../src/index.js';

const MAC = '/Applications/Claude.app/Contents/MacOS/Claude';
function fakeMac(open: boolean, opts: { quits?: boolean } = {}) {
  const calls: string[] = [];
  let running = open;
  const sys: AppSys = {
    platform: 'darwin',
    list: () => (running ? ['/sbin/launchd', MAC] : ['/sbin/launchd']),
    run: async (cmd, args) => { calls.push(`${cmd} ${args.join(' ')}`); if (cmd === 'osascript' && opts.quits !== false) running = false; if (cmd === 'open') running = true; return 0; },
    sleep: async () => {},
  };
  return { sys, calls, isOpen: () => running };
}

test('running: by app path on macOS, Claude.exe on Windows, never Claude Code', () => {
  assert.equal(claudeDesktopRunning(fakeMac(true).sys), true);
  assert.equal(claudeDesktopRunning({ ...fakeMac(false).sys, list: () => ['/usr/local/bin/claude'] }), false);
  const win = (l: string[]) => claudeDesktopRunning({ ...fakeMac(false).sys, platform: 'win32', list: () => l });
  assert.equal(win(['"Claude.exe","1234","Console","1","100 K"']), true);
  assert.equal(win(['"node.exe","1"']), false);
  const linux = (l: string[]) => claudeDesktopRunning({ ...fakeMac(false).sys, platform: 'linux', list: () => l });
  assert.equal(linux(['claude']), false);
  assert.equal(linux(['claude-desktop']), true);
  assert.equal(claudeDesktopRunning({ ...fakeMac(true).sys, list: () => null }), false);
});

test('closed: the change just happens', async () => {
  const f = fakeMac(false);
  assert.deepEqual(await withClaudeDesktopClosed(() => 'done', { restart: false, sys: f.sys }), { result: 'done', restarted: false });
  assert.deepEqual(f.calls, []);
});

test('open without restart: refused, nothing changed', async () => {
  const f = fakeMac(true);
  let changed = false;
  await assert.rejects(withClaudeDesktopClosed(() => { changed = true; }, { restart: false, sys: f.sys }), /--restart/);
  assert.equal(changed, false);
  await assert.rejects(withClaudeDesktopClosed(() => { changed = true; }, { restart: true, sys: { ...f.sys, platform: 'win32', list: () => ['"Claude.exe"'] } }), /system tray/);
  assert.equal(changed, false);
});

test('open with restart: quit, change while closed, reopen (even if the change fails)', async () => {
  const f = fakeMac(true);
  let openDuringChange: boolean | undefined;
  const r = await withClaudeDesktopClosed(() => { openDuringChange = f.isOpen(); return 1; }, { restart: true, sys: f.sys });
  assert.deepEqual(r, { result: 1, restarted: true });
  assert.equal(openDuringChange, false);
  assert.deepEqual(f.calls.map((c) => c.split(' ')[0]), ['osascript', 'open']);
  const g = fakeMac(true);
  await assert.rejects(withClaudeDesktopClosed(() => { throw new Error('bad config'); }, { restart: true, sys: g.sys }), /bad config/);
  assert.equal(g.isOpen(), true);
});

test('if it will not quit, nothing is changed and it is not reopened', async () => {
  const f = fakeMac(true, { quits: false });
  let changed = false;
  await assert.rejects(withClaudeDesktopClosed(() => { changed = true; }, { restart: true, sys: f.sys }), /didn't quit/);
  assert.equal(changed, false);
  assert.ok(!f.calls.some((c) => c.startsWith('open')));
});
