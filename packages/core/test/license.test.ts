import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { LicenseStore, verifyLicense, TIER_LIMITS, KeyringStore, MemoryBackend } from '../src/index.js';

const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-lic-'));
const tool = path.resolve(import.meta.dirname, '../../../tools/issue-license.mjs');
execFileSync(process.execPath, [tool, 'gen-keys', dir]);
const PUB = readFileSync(path.join(dir, 'license-public.pem'), 'utf8');
const issue = (...a: string[]) => execFileSync(process.execPath, [tool, 'issue', '--key', path.join(dir, 'license-private.pem'), ...a], { encoding: 'utf8' }).trim();

test('valid license verifies offline; tampering, wrong key and expiry are rejected', () => {
  const t = issue('--tier', 'pro', '--days', '30', '--sub', 'order-1');
  const v = verifyLicense(t, PUB);
  assert.ok(v.ok && v.payload.tier === 'pro' && v.payload.sub === 'order-1');
  const [h, p, s] = t.split('.');
  const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p!, 'base64url').toString()), tier: 'team' })).toString('base64url');
  assert.equal(verifyLicense(`${h}.${forged}.${s}`, PUB).ok, false);
  const dir2 = mkdtempSync(path.join(os.tmpdir(), 'lly-lic2-'));
  execFileSync(process.execPath, [tool, 'gen-keys', dir2]);
  assert.equal(verifyLicense(t, readFileSync(path.join(dir2, 'license-public.pem'), 'utf8')).ok, false);
  const late = verifyLicense(t, PUB, Date.now() + 31 * 86400_000);
  assert.ok(!late.ok && /expired/.test(late.reason));
  assert.equal(verifyLicense('garbage', PUB).ok, false);
  assert.equal(verifyLicense(t, '').ok, false, 'no configured public key = nothing validates');
});

test('LicenseStore: free by default, pro lifts the key cap, expiry falls back to free without breaking existing keys', () => {
  const backend = new MemoryBackend();
  const ls = new LicenseStore(backend, PUB);
  assert.equal(ls.status().tier, 'free');
  assert.throws(() => ls.activate('nope'));
  ls.activate(issue('--tier', 'pro', '--days', '10'));
  assert.equal(ls.limits().maxKeys, TIER_LIMITS.pro.maxKeys);
  const store = new KeyringStore(backend, { maxKeys: ls.limits().maxKeys });
  for (let i = 0; i < 7; i++) store.set('openai', `sk-${'a'.repeat(20)}${i}`, { label: `k${i}` });
  const later = Date.now() + 11 * 86400_000;
  assert.equal(ls.status(later).tier, 'free');
  assert.match(ls.status(later).problem!, /expired/);
  assert.equal(store.list().length, 7, 'existing keys keep working');
  ls.remove();
  assert.equal(ls.status().tier, 'free');
});

test('agent allowance: 5 on free, 10 per Pro user, unlimited on Team', () => {
  const backend = new MemoryBackend();
  const ls = new LicenseStore(backend, PUB);
  assert.equal(ls.maxAgents(), 5);
  ls.activate(issue('--tier', 'pro', '--days', '10', '--seats', '1'));
  assert.equal(ls.maxAgents(), 10);
  ls.activate(issue('--tier', 'pro', '--days', '10', '--seats', '4'));
  assert.equal(ls.maxAgents(), 40);
  ls.activate(issue('--tier', 'team', '--days', '10', '--seats', '3'));
  assert.equal(ls.maxAgents(), Number.POSITIVE_INFINITY);
  ls.remove();
  assert.equal(ls.maxAgents(), 5, 'a lapsed licence drops back to free');
});
