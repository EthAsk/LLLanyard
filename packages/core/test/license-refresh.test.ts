import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, randomUUID } from 'node:crypto';
import { LicenseStore, refreshDue, refreshLicense } from '../src/license.js';
import type { SecretBackend } from '../src/storage/backend.js';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pub = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const mk = (exp: number, sub?: string) => {
  const body = 'lly1.' + Buffer.from(JSON.stringify({ v: 1, id: randomUUID(), tier: 'pro', seats: 2, iat: 1, exp, ...(sub ? { sub } : {}) })).toString('base64url');
  return `${body}.${sign(null, Buffer.from(body), privateKey).toString('base64url')}`;
};
const mem = (): SecretBackend => { const m = new Map<string, string>(); return { get: (k) => m.get(k) ?? null, set: (k, v) => { m.set(k, v); }, delete: (k) => { m.delete(k); }, list: () => [...m.keys()] } as unknown as SecretBackend; };
const now = Math.floor(Date.now() / 1000);

test('refresh stores the renewed key from the server', async () => {
  const store = new LicenseStore(mem(), pub);
  const old = mk(now + 3 * 86400, 'lic_7');
  store.activate(old);
  const renewed = mk(now + 40 * 86400, 'lic_7');
  let sent: unknown;
  const fake = (async (_url: string, init: RequestInit) => { sent = JSON.parse(String(init.body)); return new Response(JSON.stringify({ licence: renewed }), { status: 200 }); }) as typeof fetch;
  const r = await refreshLicense(store, fake);
  assert.equal(r.kind, 'renewed');
  assert.deepEqual(sent, { licence: old });
  assert.equal(store.token(), renewed);
});

test('refresh reports a withdrawn license and keeps the old key', async () => {
  const store = new LicenseStore(mem(), pub);
  const old = mk(now + 3 * 86400, 'lic_7');
  store.activate(old);
  const fake = (async () => new Response(JSON.stringify({ message: 'This licence has been withdrawn.' }), { status: 410 })) as unknown as typeof fetch;
  const r = await refreshLicense(store, fake);
  assert.deepEqual(r, { kind: 'failed', message: 'This licence has been withdrawn.' });
  assert.equal(store.token(), old);
});

test('refresh never calls out for licenses not sold through the server', async () => {
  const store = new LicenseStore(mem(), pub);
  store.activate(mk(now + 86400));
  const fake = (async () => { throw new Error('should not be called'); }) as unknown as typeof fetch;
  assert.equal((await refreshLicense(store, fake)).kind, 'none');
  assert.equal((await refreshLicense(new LicenseStore(mem(), pub), fake)).kind, 'none');
});

test('start-up checks only in the last week of a paid license', () => {
  const store = new LicenseStore(mem(), pub);
  assert.equal(refreshDue(store), false);
  store.activate(mk(now + 30 * 86400, 'lic_1'));
  assert.equal(refreshDue(store), false);
  store.activate(mk(now + 2 * 86400, 'lic_1'));
  assert.equal(refreshDue(store), true);
  process.env.LLLANYARD_NO_LICENSE_REFRESH = '1';
  try { assert.equal(refreshDue(store), false); } finally { delete process.env.LLLANYARD_NO_LICENSE_REFRESH; }
});
