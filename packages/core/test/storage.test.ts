import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentStore, KeyringStore, MemoryBackend, StoreError } from '../src/index.js';

const KEY = 'sk-ant-' + 'A'.repeat(40);
const dump = (b: MemoryBackend) => JSON.stringify([...(b as any).m.entries()]);

test('store: set/get/list/remove round trip; list never exposes secrets', () => {
  const s = new KeyringStore(new MemoryBackend());
  const m = s.set('anthropic', KEY);
  assert.equal(m.id, 'anthropic:default');
  assert.equal(s.get('anthropic'), KEY);
  assert.equal(JSON.stringify(s.list()).includes(KEY), false);
  assert.equal(s.remove('anthropic'), true);
  assert.equal(s.get('anthropic'), null);
  assert.deepEqual(s.list(), []);
});

test('store: index and metadata entries never contain the secret', () => {
  const b = new MemoryBackend();
  new KeyringStore(b).set('openai', 'sk-' + 'b'.repeat(40));
  const entries = [...(b as any).m.entries()] as [string, string][];
  for (const [k, v] of entries) if (!k.startsWith('key:')) assert.equal(v.includes('bbbbbbbb'), false, k);
});

test('store: free tier caps at 10 keys but allows overwriting', () => {
  const s = new KeyringStore(new MemoryBackend());
  for (let i = 0; i < 10; i++) s.set('openai', 'sk-' + String(i).repeat(30), { label: `c${i}` });
  assert.throws(() => s.set('openai', 'sk-' + 'x'.repeat(30), { label: 'c10' }), StoreError);
  assert.doesNotThrow(() => s.set('openai', 'sk-' + 'y'.repeat(30), { label: 'c0' }));
});

test('store: rejects bad names and malformed secrets', () => {
  const s = new KeyringStore(new MemoryBackend());
  assert.throws(() => s.set('a:b', KEY), StoreError);
  assert.throws(() => s.set('openai', 'has space in it'), StoreError);
  assert.throws(() => s.set('openai', 'sk-abc\nsk-def'), StoreError);
  assert.throws(() => s.set('openai', KEY, { rotateAfterDays: 0 }), StoreError);
});

test('store: rotating keeps the interval and resets the clock', async () => {
  const s = new KeyringStore(new MemoryBackend());
  const a = s.set('openai', 'sk-' + 'a'.repeat(30), { rotateAfterDays: 30 });
  await new Promise((r) => setTimeout(r, 5));
  const b = s.set('openai', 'sk-' + 'b'.repeat(30));
  assert.equal(b.rotateAfterDays, 30);
  assert.ok(b.createdAt > a.createdAt);
});

test('store: refuses to overwrite a corrupted index', () => {
  const b = new MemoryBackend();
  b.set('__index__', '{not json');
  assert.throws(() => new KeyringStore(b).set('openai', KEY), StoreError);
});

test('agents: token verifies, wrong token fails, token is never stored, revoke works', () => {
  const b = new MemoryBackend();
  const a = new AgentStore(b);
  const token = a.create('claude-code', 'acme');
  assert.match(token, /^lly_[A-Za-z0-9_-]{43}$/);
  assert.equal(dump(b).includes(token), false);
  assert.deepEqual(a.verifier()(token), { name: 'claude-code', client: 'acme' });
  assert.equal(a.verifier()(token + 'x'), null);
  assert.equal(a.verifier()('lly_nope'), null);
  assert.equal(a.revoke('claude-code'), true);
  assert.equal(a.verifier()(token), null);
});
