import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  createBackup, createMcpHandler, describeSshRun, summarize, generateKey, keyIsEncrypted, MemoryBackend, normaliseKey, openSshSession, readBackup, restoreBackup, sshArgs, SshStore, StoreError, validateSsh, KeyringStore,
} from '../src/index.js';

const haveSsh = spawnSync('ssh-keygen', ['-V'], { encoding: 'utf8' }).error === undefined && spawnSync('ssh-agent', ['-k'], { encoding: 'utf8' }).error === undefined;
const base = { name: 'prod', host: 'prod.example.com', user: 'deploy', port: 22 };

test('ssh: store round trip keeps the secret out of list()', { skip: !haveSsh }, () => {
  const { privateKey, publicKey } = generateKey('t');
  const s = new SshStore(new MemoryBackend());
  const m = s.set({ ...base, auth: 'key', secret: privateKey, publicKey });
  assert.ok(!JSON.stringify(s.list()).includes('PRIVATE KEY'));
  assert.equal(m.name, 'prod');
  assert.equal(s.get('PROD')?.secret, privateKey);
  assert.ok(s.get('prod')?.publicKey?.startsWith('ssh-ed25519 '));
  assert.equal(s.remove('prod'), true);
  assert.deepEqual(s.list(), []);
});

test('ssh: password logins, limits and reserved names', () => {
  const s = new SshStore(new MemoryBackend());
  s.set({ ...base, auth: 'password', secret: 'hunter2 with spaces' });
  assert.equal(s.get('prod')?.secret, 'hunter2 with spaces');
  assert.throws(() => s.set({ ...base, name: 'two', auth: 'password', secret: 'x' }, { maxTotal: 2, otherCount: 1 }), StoreError);
  assert.throws(() => s.set({ ...base, name: 'list', auth: 'password', secret: 'x' }), /command/);
  s.set({ ...base, auth: 'password', secret: 'changed' }, { maxTotal: 1 }); // replacing doesn't count against the limit
});

test('ssh: hosts and users can never be read as ssh options', () => {
  for (const host of ['-oProxyCommand=evil', 'a b', 'a;b', '']) assert.throws(() => validateSsh({ ...base, host, auth: 'password', secret: 'x' }), StoreError);
  for (const user of ['-oProxyCommand=x', 'a b', '']) assert.throws(() => validateSsh({ ...base, user, auth: 'password', secret: 'x' }), StoreError);
  assert.throws(() => validateSsh({ ...base, port: 0, auth: 'password', secret: 'x' }), StoreError);
});

test('ssh: key text is checked and tidied; encrypted keys are recognised', { skip: !haveSsh }, () => {
  assert.throws(() => normaliseKey('not a key'), StoreError);
  const { privateKey } = generateKey('t');
  assert.equal(normaliseKey('  ' + privateKey.replace(/\n/g, '\r\n') + '\n\n'), privateKey);
  assert.equal(keyIsEncrypted(privateKey), false);
});

test('ssh: an encrypted OpenSSH key is detected', { skip: !haveSsh }, () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-test-'));
  try {
    spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', 'secret-pass', '-f', path.join(dir, 'k')]);
    assert.equal(keyIsEncrypted(readFileSync(path.join(dir, 'k'), 'utf8')), true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('ssh: backup and restore carry SSH logins and count towards the limit', () => {
  const b = new MemoryBackend();
  new SshStore(b).set({ ...base, auth: 'password', secret: 'pw-12345' });
  new KeyringStore(b).set('github', 'ghp_' + 'B'.repeat(36));
  const { text, items } = createBackup('correct horse battery', b);
  assert.equal(items.length, 2);
  assert.ok(!text.includes('pw-12345') && !text.includes('prod.example.com'));
  const fresh = new MemoryBackend();
  const r = restoreBackup(readBackup(text, 'correct horse battery'), fresh);
  assert.deepEqual(r.invalid, []);
  assert.equal(new SshStore(fresh).get('prod')?.secret, 'pw-12345');
  assert.throws(() => restoreBackup(readBackup(text, 'correct horse battery'), new MemoryBackend(), { maxKeys: 1 }), /allows 1/);
});

test('ssh: args use the private agent, never the user\'s own, and a dedicated known_hosts', { skip: !haveSsh || process.platform === 'win32' }, async () => {
  const { privateKey } = generateKey('t');
  const e = { ...base, auth: 'key' as const, secret: privateKey, createdAt: '' };
  const session = await openSshSession([e], { base: { PATH: process.env.PATH!, HOME: process.env.HOME!, SSH_AUTH_SOCK: '/their/own/agent', SECRET_X: 'nope' } });
  try {
    assert.ok(session.env.SSH_AUTH_SOCK && existsSync(session.env.SSH_AUTH_SOCK) && session.env.SSH_AUTH_SOCK !== '/their/own/agent');
    assert.equal(session.env.SECRET_X, undefined);
    const listed = spawnSync('ssh-add', ['-l'], { env: session.env, encoding: 'utf8' });
    assert.equal(listed.status, 0);
    assert.match(listed.stdout, /ED25519/);
    const args = sshArgs(e, session, ['uptime']);
    assert.ok(args.includes(`IdentityAgent=${session.env.SSH_AUTH_SOCK}`));
    assert.equal(args.at(-2), 'deploy@prod.example.com');
    assert.equal(args.at(-1), 'uptime');
    assert.ok(args.some((a) => a.startsWith('UserKnownHostsFile=') && a.endsWith('ssh_known_hosts')));
  } finally { session.close(); }
  assert.equal(existsSync(session.env.SSH_AUTH_SOCK!), false, 'the agent and its socket are gone after the session');
});

test('ssh: sessions refuse to mix a password with other logins', async () => {
  const pw = { ...base, auth: 'password' as const, secret: 'x', createdAt: '' };
  await assert.rejects(openSshSession([pw, { ...pw, name: 'b' }]), /Only one password/);
});

// ---- long keys (RSA) --------------------------------------------------------------------------------------------

/** A keychain that refuses entries over Windows' size limit, so a key that isn't split would fail here. */
class SmallEntries extends MemoryBackend {
  set(a: string, v: string) { if (v.length > 1000) throw new Error('entry too large'); super.set(a, v); }
}

test('ssh: an RSA 4096 key is split across keychain entries and comes back whole', { skip: !haveSsh }, () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-test-'));
  let rsa: string;
  try {
    spawnSync('ssh-keygen', ['-q', '-t', 'rsa', '-b', '4096', '-m', 'PEM', '-N', '', '-f', path.join(dir, 'k')]);
    rsa = normaliseKey(readFileSync(path.join(dir, 'k'), 'utf8'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
  assert.ok(rsa.length > 3000);
  const b = new SmallEntries();
  const s = new SshStore(b);
  s.set({ ...base, auth: 'key', secret: rsa });
  assert.equal(s.get('prod')?.secret, rsa);
  assert.deepEqual(s.list().map((m) => m.name), ['prod']);

  // backup / restore carry it whole, into a store with the same limit
  const { text } = createBackup('correct horse battery', b);
  const fresh = new SmallEntries();
  assert.deepEqual(restoreBackup(readBackup(text, 'correct horse battery'), fresh).invalid, []);
  assert.equal(new SshStore(fresh).get('prod')?.secret, rsa);

  // replacing it with a short login leaves no stale pieces behind; removing it clears everything
  s.set({ ...base, auth: 'password', secret: 'short-pass' });
  assert.equal(s.get('prod')?.secret, 'short-pass');
  assert.equal(b.get('ssh:prod#1'), null);
  s.set({ ...base, auth: 'key', secret: rsa });
  assert.equal(s.remove('prod'), true);
  assert.equal(b.get('ssh:prod#1'), null);
  assert.equal(s.get('prod'), null);
});

test('ssh: a half-written long login reads as missing, never as a broken key', () => {
  const b = new MemoryBackend();
  b.set('__ssh__', JSON.stringify(['prod']));
  b.set('ssh:prod', '#3');
  b.set('ssh:prod#1', '{"name":'); // chunks 2 and 3 never arrived
  assert.equal(new SshStore(b).get('prod'), null);
  assert.deepEqual(new SshStore(b).list(), []);
});

// ---- MCP --------------------------------------------------------------------------------------------------------

function mcpWith(run: (name: string, command: string) => Promise<any>) {
  return createMcpHandler({
    listKeys: () => [], providerIds: () => [], usage: (since) => summarize([], since), proxyBase: 'http://127.0.0.1:3000',
    runner: { list: () => [], run: async () => ({ exitCode: 0, output: '', truncated: false, timedOut: false }),
      ssh: { list: () => [{ name: 'prod', target: 'deploy@prod.example.com', auth: 'key' }], run } },
  });
}
const rpc = (h: ReturnType<typeof mcpWith>, method: string, params?: any) => h({ jsonrpc: '2.0', id: 1, method, params }) as any;

test('mcp: ssh tools appear only with the runner, list_ssh shows no secrets, ssh_run needs a known login', async () => {
  const calls: string[] = [];
  const h = mcpWith(async (n, c) => { calls.push(`${n}:${c}`); return { exitCode: 0, output: 'up 3 days', truncated: false, timedOut: false }; });
  const names = rpc(h, 'tools/list').result.tools.map((t: any) => t.name);
  assert.ok(names.includes('list_ssh') && names.includes('ssh_run'));
  assert.equal(rpc(h, 'tools/list').result.tools.find((t: any) => t.name === 'ssh_run').annotations.destructiveHint, true);
  const listed = rpc(h, 'tools/call', { name: 'list_ssh', arguments: {} }).result.content[0].text;
  assert.match(listed, /deploy@prod\.example\.com/);
  const ok = await rpc(h, 'tools/call', { name: 'ssh_run', arguments: { name: 'PROD', command: 'uptime' } });
  assert.match(ok.result.content[0].text, /Exit code 0[\s\S]*up 3 days/);
  assert.deepEqual(calls, ['prod:uptime']);
  for (const args of [{ name: 'nope', command: 'ls' }, { name: 'prod', command: '' }, { name: 'prod', command: 'x'.repeat(1501) }]) {
    assert.equal((await rpc(h, 'tools/call', { name: 'ssh_run', arguments: args })).result.isError, true);
  }
  assert.equal(calls.length, 1, 'refused requests never reach the runner');

  const plain = createMcpHandler({ listKeys: () => [], providerIds: () => [], usage: (since) => summarize([], since), proxyBase: 'x' });
  assert.ok(!(plain({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) as any).result.tools.some((t: any) => t.name.includes('ssh')));
});

test('mcp: a denied dialog is reported as not run', async () => {
  const h = mcpWith(async () => null);
  const r = await rpc(h, 'tools/call', { name: 'ssh_run', arguments: { name: 'prod', command: 'reboot' } });
  assert.match(r.result.content[0].text, /^Not run: the user clicked Deny/);
});

test('ssh: the confirmation dialog shows the login and the exact command', () => {
  const t = describeSshRun({ name: 'prod', user: 'deploy', host: 'prod.example.com', port: 2222 }, 'sudo systemctl restart app');
  assert.match(t, /prod \(deploy@prod\.example\.com:2222\)/);
  assert.match(t, /Command: sudo systemctl restart app/);
});
