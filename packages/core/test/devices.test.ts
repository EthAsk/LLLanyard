import test from 'node:test';
import assert from 'node:assert/strict';
import { DEVICE_LIMITS, DeviceStore, MemoryBackend, RemoteStore, machineId, rawMachineId } from '../src/index.js';

const M1 = machineId('machine-one'), M2 = machineId('machine-two');

test('machine IDs are hashed, stable and differ per machine', () => {
  assert.match(M1, /^[0-9a-f]{64}$/);
  assert.equal(machineId(' MACHINE-ONE '), M1);
  assert.notEqual(M1, M2);
  if (process.platform === 'darwin' || process.platform === 'linux') assert.ok(rawMachineId().length > 8);
});

test('Pro pairs up to 3 devices; codes are single use and count while waiting', () => {
  const s = new DeviceStore(new MemoryBackend());
  const limit = DEVICE_LIMITS.pro;
  const a = s.invite('laptop', limit);
  assert.match(a.code, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  const p = s.pair(a.code.toLowerCase().replace('-', ' '), M1);
  assert.equal(p.name, 'laptop');
  assert.match(p.token, /^lly_dev_/);
  assert.throws(() => s.pair(a.code, M2), /wrong or has expired/, 'single use');
  s.invite('desktop', limit);
  s.invite('tablet', limit);
  assert.throws(() => s.invite('phone', limit), /allows 3 devices/);
  assert.doesNotThrow(() => s.invite('tablet', limit), 'a new code for the same name replaces the old one');
  assert.equal(s.remove('tablet'), true);
  assert.doesNotThrow(() => s.invite('phone', limit));
  assert.throws(() => new DeviceStore(new MemoryBackend()).invite('x', DEVICE_LIMITS.free), /needs Pro/);
});

test('a device token works only with the machine it was paired on', () => {
  const s = new DeviceStore(new MemoryBackend());
  const { token } = s.pair(s.invite('laptop', 3).code, M1);
  const v = s.verifier(3);
  assert.deepEqual(v(token, M1), { name: 'device:laptop', client: 'default', device: true, keys: true });
  const ro = s.pair(s.invite('tablet', 3, { noKeys: true }).code, M2);
  assert.equal((s.verifier(3)(ro.token, M2) as { keys: boolean }).keys, false);
  assert.equal(s.list().find((d) => d.name === 'tablet')?.keys, false);
  assert.equal(v(token, M2), 'wrong-machine');
  assert.equal(v(token, undefined), 'wrong-machine');
  assert.equal(v('lly_dev_nope', M1), null);
  assert.equal(v('lly_agent_token', M1), null);
  s.remove('laptop');
  assert.equal(s.verifier(3)(token, M1), null, 'removed devices stop working');
});

test('one machine, one device; re-pairing a name replaces it', () => {
  const s = new DeviceStore(new MemoryBackend());
  const first = s.pair(s.invite('laptop', 3).code, M1);
  assert.throws(() => s.pair(s.invite('other', 3).code, M1), /already paired as "laptop"/);
  const again = s.pair(s.invite('laptop', 3).code, M2);
  const v = s.verifier(3);
  assert.equal(v(first.token, M1), null);
  assert.equal((v(again.token, M2) as { name: string }).name, 'device:laptop');
});

test('codes run out after 10 minutes', () => {
  let t = Date.parse('2026-11-01T10:00:00Z');
  const s = new DeviceStore(new MemoryBackend(), () => t);
  const { code } = s.invite('laptop', 3);
  t += 11 * 60_000;
  assert.throws(() => s.pair(code, M1), /expired/);
  assert.equal(s.used(), 0);
});

test('over the limit (e.g. Team to Pro), only the first devices paired keep working', () => {
  let t = Date.parse('2026-11-01T10:00:00Z');
  const s = new DeviceStore(new MemoryBackend(), () => t);
  const toks = ['a', 'b', 'c', 'd'].map((n) => { t += 1000; return s.pair(s.invite(n, Infinity).code, machineId(n)).token; });
  const v = s.verifier(3);
  assert.equal(v(toks[0]!, machineId('a')) !== null, true);
  assert.equal(v(toks[3]!, machineId('d')), null);
});

test('the device side keeps its link and a fixed relay token', () => {
  const r = new RemoteStore(new MemoryBackend());
  assert.throws(() => r.set({ url: 'https://x', token: 'lly_abc', name: 'laptop' }), /device token/);
  r.set({ url: 'https://main.example:3443', token: 'lly_dev_aaaaaaaaaaaaaaaaaaaa', name: 'laptop' });
  const t = r.relayToken();
  assert.match(t, /^lly_local_/);
  assert.equal(r.relayToken(), t);
  assert.equal(r.get()?.name, 'laptop');
  assert.equal(r.remove(), true);
});
