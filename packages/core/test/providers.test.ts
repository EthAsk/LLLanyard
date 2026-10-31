import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryBackend, ProviderStore, StoreError, allProviders, validateProvider, BUILTIN_PROVIDERS } from '../src/index.js';

const ok = { id: 'acme', upstream: 'https://api.acme.dev/v2/', auth: { type: 'bearer' as const } };

test('providers: valid config is normalised (trailing slash removed, id lowercased)', () => {
  const v = validateProvider({ ...ok, id: 'ACME' });
  assert.equal(v.id, 'acme');
  assert.equal(v.upstream, 'https://api.acme.dev/v2');
});

test('providers: rejects http, credentials, query strings, IPs, localhost and bad ids', () => {
  const bad: any[] = [
    { ...ok, upstream: 'http://api.acme.dev' },
    { ...ok, upstream: 'https://user:pw@api.acme.dev' },
    { ...ok, upstream: 'https://api.acme.dev/?k=1' },
    { ...ok, upstream: 'https://169.254.169.254' },
    { ...ok, upstream: 'https://[::1]' },
    { ...ok, upstream: 'https://localhost' },
    { ...ok, upstream: 'not a url' },
    { ...ok, id: 'a/b' },
  ];
  for (const b of bad) assert.throws(() => validateProvider(b), StoreError, JSON.stringify(b));
});

test('providers: loopback needs allowLocal, and allowLocal is refused for public hosts', () => {
  const local = { id: 'ollama', upstream: 'http://localhost:11434', auth: { type: 'bearer' as const } };
  assert.throws(() => validateProvider(local), StoreError);
  assert.equal(validateProvider({ ...local, allowLocal: true }).allowLocal, true);
  assert.throws(() => validateProvider({ ...ok, allowLocal: true }), StoreError);
});

test('providers: custom header auth is validated; dangerous headers refused', () => {
  assert.deepEqual(validateProvider({ ...ok, auth: { type: 'header', name: 'X-Api-Key', prefix: 'Token ' } }).auth, { type: 'header', name: 'X-Api-Key', prefix: 'Token ' });
  for (const name of ['Host', 'Cookie', 'Content-Length', 'bad name', 'x\r\ny'])
    assert.throws(() => validateProvider({ ...ok, auth: { type: 'header', name } }), StoreError, name);
  assert.throws(() => validateProvider({ ...ok, auth: { type: 'header', name: 'X-Key', prefix: 'a\r\nb' } }), StoreError);
});

test('providers: built-ins cannot be redefined, and always win in the merged map', () => {
  assert.throws(() => validateProvider({ ...ok, id: 'openai' }), StoreError);
  const s = new ProviderStore(new MemoryBackend());
  s.set(ok);
  const all = allProviders(s);
  assert.equal(all['acme']!.upstream, 'https://api.acme.dev/v2');
  for (const b of BUILTIN_PROVIDERS) assert.deepEqual(all[b.id], b);
  assert.equal(all['constructor'], undefined);
});

test('providers: store round trip and removal; tampered entries are ignored, never used', () => {
  const b = new MemoryBackend();
  const s = new ProviderStore(b);
  s.set(ok);
  assert.equal(s.list().length, 1);
  b.set('provider:acme', JSON.stringify({ ...ok, upstream: 'http://169.254.169.254' }));
  assert.equal(s.get('acme'), null);
  assert.equal(s.remove('acme'), true);
  assert.deepEqual(s.list(), []);
});
