import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, existsSync, writeFileSync, readFileSync, realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sandboxCommand, sandboxSelfTest, resolveCommand } from '../src/index.js';

// Runs a real sandbox. Skipped where none is available (CI installs bubblewrap on Linux; macOS has sandbox-exec).
const st = sandboxSelfTest();
const skip = !st.ok && `no working sandbox here: ${st.reason}`;

function inSandbox(script: string, cwd: string, home: string, tmp: string) {
  const sh = resolveCommand('sh');
  const { command, args } = sandboxCommand({ kind: st.kind!, command: sh, args: ['-c', script], cwd, home, ro: [], rw: [], network: null, tty: false, tmp });
  return spawnSync(command, args, { encoding: 'utf8', cwd, env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home }, timeout: 30_000 });
}

test('real sandbox: project is writable, home credentials are invisible, outside writes fail, no network', { skip }, () => {
  const home = mkdtempSync(path.join(os.homedir() === '/' ? os.tmpdir() : os.homedir(), '.lly-sbx-home-'));
  const proj = path.join(home, 'proj');
  spawnSync('mkdir', ['-p', proj, path.join(home, '.ssh')]);
  writeFileSync(path.join(home, '.ssh', 'id_test'), 'PRIVATE-KEY-CANARY');
  writeFileSync(path.join(home, 'notes.txt'), 'HOME-CANARY');
  const outside = path.join(os.tmpdir(), `lly-outside-${process.pid}`);
  const tmp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'lly-sbx-tmp-')));
  // Network probe with a system interpreter (the CI's node lives where the sandbox can't see it).
  const py = ['/usr/bin/python3', '/usr/local/bin/python3'].find((p) => existsSync(p));
  const probe = py
    ? `"${py}" -c "import socket;print('PROBE_RAN');socket.create_connection(('1.1.1.1',443),2);print('NET_OPEN')" 2>/dev/null`
    : `"${process.execPath}" -e "console.log('PROBE_RAN');const s=require('net').connect({host:'1.1.1.1',port:443,timeout:2000});s.on('connect',()=>{console.log('NET_OPEN');process.exit(0)});s.on('error',()=>process.exit(0));s.on('timeout',()=>process.exit(0))"`;

  const r = inSandbox([
    'echo ok > ./inside.txt && echo WROTE_PROJECT',
    `cat "${home}/.ssh/id_test" 2>/dev/null && echo LEAK_SSH`,
    `cat "${home}/notes.txt" 2>/dev/null && echo LEAK_HOME`,
    `echo x > "${outside}" 2>/dev/null`, // Linux: lands in the sandbox's private /tmp; checked on the host below
    `echo x > "${tmp}/own.txt" && echo WROTE_TMP`,
    probe,
  ].join('; '), proj, home, tmp);

  const out = `${r.stdout}\n${r.stderr}`;
  assert.match(out, /WROTE_PROJECT/, out);
  assert.equal(readFileSync(path.join(proj, 'inside.txt'), 'utf8').trim(), 'ok');
  assert.match(out, /PROBE_RAN/, `network probe did not run:\n${out}`);
  if (st.kind === 'seatbelt') assert.match(out, /WROTE_TMP/, out);
  for (const bad of ['LEAK_SSH', 'LEAK_HOME', 'NET_OPEN', 'PRIVATE-KEY-CANARY', 'HOME-CANARY']) assert.ok(!out.includes(bad), `${bad} should not happen:\n${out}`);
  assert.equal(existsSync(outside), false);
});
