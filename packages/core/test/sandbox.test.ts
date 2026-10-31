import test from 'node:test';
import { EventEmitter } from 'node:events';
import assert from 'node:assert/strict';
import { bwrapArgs, seatbeltProfile, assertSafeMount, sandboxSelfTest, runTool, validateTool, type SandboxSpec } from '../src/index.js';
import { MemoryBackend } from '../src/storage/index.js';

const HOME = '/home/alice';
const base = (over: Partial<SandboxSpec> = {}): SandboxSpec => ({
  kind: 'bwrap', command: '/usr/bin/git', args: ['status'], cwd: '/home/alice/proj', home: HOME, ro: [], rw: [], network: null, tty: false,
  nodePath: '/opt/node/bin/node', bridgePath: '/opt/lly/dist/sandbox-bridge.js',
  fsLayout: (p) => (['/bin', '/sbin', '/lib', '/lib64'].includes(p) ? 'symlink' : p === '/usr' ? 'dir' : 'missing'), ...over,
});
const idx = (a: string[], ...seq: string[]) => a.findIndex((_, i) => seq.every((s, j) => a[i + j] === s));

test('bwrap: isolates everything, hides home, binds only the project', () => {
  const a = bwrapArgs(base());
  for (const f of ['--unshare-all', '--die-with-parent', '--new-session']) assert.ok(a.includes(f), f);
  assert.ok(!a.includes('--share-net'));
  assert.ok(idx(a, '--tmpfs', HOME) >= 0);
  assert.ok(idx(a, '--bind', '/home/alice/proj', '/home/alice/proj') > idx(a, '--tmpfs', HOME), 'project is mounted after the empty home');
  assert.ok(idx(a, '--symlink', 'usr/bin', '/bin') >= 0);
  assert.ok(!a.some((x) => x === '/run' || x === '/var/run' || x === '/root'), 'no keyring/docker sockets');
  assert.equal(a.join(' ').includes('--ro-bind / /'), false);
  assert.deepEqual(a.slice(-3), ['--', '/usr/bin/git', 'status'].slice(0, 3));
});

test('bwrap: no bridge without network; bridge + private socket dir with network', () => {
  assert.ok(!bwrapArgs(base()).includes('/opt/lly/dist/sandbox-bridge.js'));
  const a = bwrapArgs(base({ network: { socketPath: '/tmp/lly-abc/egress.sock', port: 31337 } }));
  assert.ok(idx(a, '--bind', '/tmp/lly-abc', '/tmp/lly-abc') >= 0);
  assert.ok(idx(a, '/opt/node/bin/node', '/opt/lly/dist/sandbox-bridge.js', '/tmp/lly-abc/egress.sock', '31337', '--', '/usr/bin/git') >= 0);
});

test('bwrap: TTY runs do not use --new-session; secrets never appear in argv', () => {
  assert.ok(!bwrapArgs(base({ tty: true })).includes('--new-session'));
  assert.ok(bwrapArgs(base()).includes('--unsetenv'));
});

test('mount safety: home, credentials dirs and system paths are refused', () => {
  for (const p of ['/home/alice', '/home', '/', '/etc', '/run', '/home/alice/.ssh', '/home/alice/.aws/creds', '/home/alice/.config/gcloud', 'relative/x', '/tmp/a"b', '/tmp/a\nb'])
    assert.throws(() => assertSafeMount(p, HOME), undefined, p);
  assert.throws(() => assertSafeMount('/', HOME));
  assert.equal(assertSafeMount('/home/alice/proj/', HOME), '/home/alice/proj');
  assert.throws(() => bwrapArgs(base({ cwd: HOME })), /whole home/);
  assert.throws(() => bwrapArgs(base({ ro: ['/home/alice/.ssh'] })), /credentials/);
  assert.throws(() => bwrapArgs(base({ rw: ['/home/alice/.gnupg'] })), /credentials/);
});

test('seatbelt: denies network except the proxy port, denies home reads, escapes paths', () => {
  const p = seatbeltProfile(base({ kind: 'seatbelt', cwd: '/Users/bob/proj', home: '/Users/bob', network: { socketPath: '', port: 4242 }, tmp: '/private/var/folders/x/T/lllanyard-run-1' }));
  assert.match(p, /\(deny network\*\)/);
  assert.match(p, /remote ip "localhost:4242"/);
  assert.match(p, /\(deny file-read\* \(subpath "\/Users\/bob"\)\)/);
  assert.match(p, /\(allow file-write\* \(subpath "\/Users\/bob\/proj"\)\)/);
  assert.match(p, /com\.apple\.SecurityServer/);
  assert.ok(p.indexOf('(deny file-read* (subpath "/Users/bob"))') < p.indexOf('(allow file-read* (subpath "/Users/bob/proj"))'), 'later allow overrides earlier deny');
  assert.match(p, /\(allow file-write\* \(subpath "\/private\/var\/folders\/x\/T\/lllanyard-run-1"\)\)/);
  assert.doesNotMatch(p, /subpath "\/private\/(tmp|var\/folders)"/, 'shared temp folders are not writable');
  assert.doesNotMatch(seatbeltProfile(base({ kind: 'seatbelt', cwd: '/Users/bob/proj', home: '/Users/bob', tmp: '/private/tmp/r' })), /remote ip/);
  assert.throws(() => seatbeltProfile(base({ kind: 'seatbelt', cwd: '/Users/bob/proj', home: '/Users/bob' })), /private temp/);
  assert.throws(() => seatbeltProfile(base({ kind: 'seatbelt', cwd: '/Users/bob/p")(allow default', home: '/Users/bob', tmp: '/private/tmp/r' })));
});

test('self-test: reports missing sandbox and Windows honestly', () => {
  const r = sandboxSelfTest('win32');
  assert.equal(r.ok, false); assert.match(r.reason!, /Windows/);
  const missing = sandboxSelfTest('linux', (() => ({ error: Object.assign(new Error('x'), { code: 'ENOENT' }), status: null })) as any);
  assert.equal(missing.ok, false); assert.match(missing.reason!, /apt install bubblewrap/);
  const userns = sandboxSelfTest('linux', (() => ({ status: 1, stderr: 'bwrap: No permissions to create new namespace' })) as any);
  assert.match(userns.reason!, /AppArmor/);
  assert.equal(sandboxSelfTest('linux', (() => ({ status: 0 })) as any).ok, true);
});

test('runTool: sandboxed tool FAILS CLOSED when no sandbox works (never runs unprotected)', async () => {
  let spawned = false;
  const store = new MemoryBackend() as any;
  const fake = { get: () => 'sk-test-key-123456' };
  await assert.rejects(
    runTool({ command: 'git', args: [], env: { K: 'github' }, scrub: true, sandbox: true }, {
      store: fake, env: { PATH: '/usr/bin' }, spawn: (() => { spawned = true; throw new Error('should not spawn'); }) as any,
      selfTest: () => ({ ok: false, kind: 'bwrap', reason: 'bubblewrap is not installed.' }),
    }), /NOT started/);
  assert.equal(spawned, false); void store;
});

test('runTool: sandboxed + allowHosts without an egress proxy refuses', async () => {
  await assert.rejects(
    runTool({ command: 'sh', args: [], env: { K: 'github' }, scrub: true, sandbox: true, allowHosts: ['api.github.com'] }, {
      store: { get: () => 'sk-test-key-123456' }, env: { PATH: '/usr/bin:/bin' }, spawn: (() => { throw new Error('no'); }) as any,
      selfTest: () => ({ ok: true, kind: 'bwrap' }), platform: 'linux',
    }), /egress proxy/);
});

test('runTool: sandbox wraps the command, keeps secrets out of argv, drops keyring env', { skip: process.platform === 'win32' && 'needs a POSIX shell to resolve' }, async () => {
  let call: any;
  const spawn = ((cmd: string, args: string[], o: any) => {
    call = { cmd, args, env: o.env };
    const c = new EventEmitter(); c.stdout = null; c.stderr = null;
    setImmediate(() => c.emit('close', 0, null)); return c;
  }) as any;
  const code = await runTool({ command: 'sh', args: ['-c', 'true'], env: { K: 'github' }, scrub: false, sandbox: true }, {
    store: { get: () => 'ghp_SECRETSECRETSECRET123' }, spawn, platform: 'linux', home: '/home/alice', cwd: '/home/alice/proj',
    env: { PATH: '/usr/bin:/bin', XDG_RUNTIME_DIR: '/run/user/1000', DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/1000/bus' },
    selfTest: () => ({ ok: true, kind: 'bwrap' }),
  });
  assert.equal(code, 0);
  assert.equal(call.cmd, 'bwrap');
  assert.ok(!JSON.stringify(call.args).includes('SECRET'));
  assert.equal(call.env.K, 'ghp_SECRETSECRETSECRET123');
  assert.equal(call.env.XDG_RUNTIME_DIR, undefined);
  assert.equal(call.env.DBUS_SESSION_BUS_ADDRESS, undefined);
});

test('validateTool: sandbox shares are validated', () => {
  const t = { name: 't', command: 'x', args: [], env: { K: 'github' }, scrub: true };
  assert.throws(() => validateTool({ ...t, shareRw: ['/tmp/x'] }), /--sandbox/);
  assert.throws(() => validateTool({ ...t, sandbox: true, shareRo: ['/root'] }));
  assert.deepEqual(validateTool({ ...t, sandbox: true, shareRo: ['/opt/tools/'] }).shareRo, ['/opt/tools']);
});
