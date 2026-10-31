import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import { spawn } from 'node:child_process';
import { loadPty, runTool } from '../src/run.js';

// Runs a real program in a real pseudo-terminal (ConPTY on Windows). On CI this must work on every OS we ship for.
const pty = loadPty();
test('real pseudo-terminal: tool sees a terminal, gets keystrokes and its key, output is scrubbed', { skip: !pty && !process.env.CI && 'node-pty not available here', timeout: 30000 }, async () => {
  assert.ok(pty, 'node-pty failed to load on CI');
  const stdin = new PassThrough() as any;
  let out = '';
  const stdout = new Writable({ write(c, _e, cb) { out += c; cb(); } });
  const script = "process.stdin.once('data',d=>{console.log('got:'+String(d).trim()+' key:'+process.env.K+' tty:'+process.stdout.isTTY);setTimeout(()=>process.exit(6),200)})";
  const p = runTool({ command: process.execPath, args: ['-e', script], env: { K: 'github' }, scrub: true, inheritEnv: true },
    { store: { get: () => 'ghp_realptysecret98765' }, stdout, stdin, tty: true });
  setTimeout(() => stdin.write('hello\r'), 1500);
  assert.equal(await p, 6);
  const plain = out.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '');
  assert.match(plain, /got:hello key:\[REDACTED\] tty:true/);
  assert.ok(!out.includes('ghp_realptysecret98765'));
});

test('fallback without node-pty: the system `script` command gives the tool a terminal', { skip: process.platform === 'win32' && 'no script command on Windows', timeout: 30000 }, async () => {
  let out = '';
  const stdout = new Writable({ write(c, _e, cb) { out += c; cb(); } });
  const code = await runTool({ command: process.execPath, args: ['-e', "console.log('tty:'+process.stdout.isTTY+' key:'+process.env.K);process.exit(7)"], env: { K: 'github' }, scrub: true, inheritEnv: true },
    { store: { get: () => 'ghp_scriptsecret98765' }, stdout, tty: true, loadPty: () => null,
      // The test runner's stdin is a socket, which `script` rejects; real runs only get here with a terminal on stdin.
      spawn: ((cmd: string, args: string[], o: any) => spawn(cmd, args, { ...o, stdio: ['ignore', ...o.stdio.slice(1)] })) as any });
  assert.equal(code, 7);
  assert.match(out, /tty:true key:\[REDACTED\]/);
});
