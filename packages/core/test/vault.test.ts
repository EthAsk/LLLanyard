import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { FileBackend, KeyringStore, AgentStore, vaultPassphrase } from '../src/index.js';

const tmp = () => path.join(mkdtempSync(path.join(os.tmpdir(), 'lly-vault-')), 'sub', 'vault.enc');
const PASS = 'correct horse battery staple';

test('vault: round trip, persists across instances, private file, no plaintext on disk', () => {
  const f = tmp();
  const a = new FileBackend(f, () => PASS);
  a.set('key:openai:default', 'sk-SUPERSECRET-0123456789');
  a.set('other', 'v2');
  if (process.platform !== 'win32') {
    assert.equal(statSync(f).mode & 0o077, 0);
    assert.equal(statSync(path.dirname(f)).mode & 0o077, 0);
  }
  const raw = readFileSync(f, 'utf8');
  assert.ok(!raw.includes('SUPERSECRET') && !raw.includes('openai'));
  const b = new FileBackend(f, () => PASS);
  assert.equal(b.get('key:openai:default'), 'sk-SUPERSECRET-0123456789');
  assert.equal(b.get('missing'), null);
  assert.equal(b.delete('other'), true);
  assert.equal(b.delete('other'), false);
  assert.equal(new FileBackend(f, () => PASS).get('other'), null);
});

test('vault: wrong passphrase and tampering are detected, never silently accepted', () => {
  const f = tmp();
  new FileBackend(f, () => PASS).set('a', 'secret-value-1');
  assert.throws(() => new FileBackend(f, () => 'wrong passphrase here').get('a'), /wrong passphrase|modified/);
  const h = JSON.parse(readFileSync(f, 'utf8'));
  const ct = Buffer.from(h.ct, 'base64'); ct[0] ^= 1; h.ct = ct.toString('base64');
  writeFileSync(f, JSON.stringify(h));
  assert.throws(() => new FileBackend(f, () => PASS).get('a'), /wrong passphrase|modified/);
});

test('vault: needs a passphrase, enforces a minimum on creation, refuses hostile KDF settings', () => {
  assert.throws(() => new FileBackend(tmp(), () => undefined).set('a', 'b'), /passphrase/);
  assert.throws(() => new FileBackend(tmp(), () => 'short').set('a', 'b'), /at least 12/);
  const f = tmp();
  new FileBackend(f, () => PASS).set('a', 'secret-value-1');
  const h = JSON.parse(readFileSync(f, 'utf8')); h.kdf.n = 1 << 30; writeFileSync(f, JSON.stringify(h));
  assert.throws(() => new FileBackend(f, () => PASS).get('a'), /out of range/);
});

test('vault: passphrase file must be private; env and file sources work', { skip: process.platform === 'win32' && 'POSIX permissions' }, () => {
  const d = mkdtempSync(path.join(os.tmpdir(), 'lly-pp-'));
  const pf = path.join(d, 'pass'); writeFileSync(pf, PASS + '\n', { mode: 0o644 }); chmodSync(pf, 0o644);
  assert.throws(() => vaultPassphrase({ LLLANYARD_VAULT_PASSPHRASE_FILE: pf }), /chmod 600/);
  chmodSync(pf, 0o600);
  assert.equal(vaultPassphrase({ LLLANYARD_VAULT_PASSPHRASE_FILE: pf }), PASS);
  assert.equal(vaultPassphrase({ LLLANYARD_VAULT_PASSPHRASE: 'x'.repeat(12) }), 'x'.repeat(12));
});

test('vault: works as the backend for the real stores', () => {
  const f = tmp();
  const be = new FileBackend(f, () => PASS);
  const keys = new KeyringStore(be);
  keys.set('openai', 'sk-test-abcdefghijklmnop');
  const agents = new AgentStore(be);
  const tok = agents.create('bot');
  assert.equal(new KeyringStore(new FileBackend(f, () => PASS)).get('openai', 'default'), 'sk-test-abcdefghijklmnop');
  assert.equal(new AgentStore(new FileBackend(f, () => PASS)).verifier()(tok)?.name, 'bot');
});

test('vault: concurrent writers from separate processes lose no updates', { skip: process.platform === 'win32' && 'uses npx' }, () => {
  const f = tmp();
  new FileBackend(f, () => PASS).set('seed', 'value-value-1');
  const script = `
    import { FileBackend } from ${JSON.stringify(path.resolve(import.meta.dirname, '../src/index.ts'))};
    const b = new FileBackend(process.argv[2], () => ${JSON.stringify(PASS)});
    for (let i = 0; i < 4; i++) b.set(process.argv[3] + i, 'v' + i);`;
  const sf = path.join(path.dirname(f), 'w.mts'); writeFileSync(sf, script);
  const run = (tag: string) => new Promise<void>((res, rej) => {
    import('node:child_process').then(({ spawn }) => { const c = spawn('npx', ['tsx', sf, f, tag], { stdio: 'inherit' }); c.on('close', (x) => (x === 0 ? res() : rej(new Error('writer failed ' + x)))); });
  });
  return Promise.all([run('a'), run('b'), run('c')]).then(() => {
    const r = new FileBackend(f, () => PASS);
    for (const t of ['a', 'b', 'c']) for (let i = 0; i < 4; i++) assert.equal(r.get(t + i), 'v' + i);
    assert.equal(r.get('seed'), 'value-value-1');
    assert.ok(!existsSync(f + '.lock'));
  });
});
