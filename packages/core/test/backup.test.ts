import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AgentStore, collectItems, createBackup, describeItem, KeyringStore, MemoryBackend, ProviderStore, readBackup, restoreBackup, StoreError, TeamStore, ToolStore,
} from '../src/index.js';

const PASS = 'correct horse battery staple';
const KEY = 'sk-ant-' + 'A'.repeat(40);
const GH = 'ghp_' + 'B'.repeat(36);

function populated() {
  const b = new MemoryBackend();
  new KeyringStore(b).set('anthropic', KEY, { rotateAfterDays: 30 });
  new KeyringStore(b).set('github', GH, { label: 'work' });
  new ProviderStore(b).set({ id: 'acme', upstream: 'https://api.example.com', auth: { type: 'header', name: 'X-API-KEY' } });
  new ToolStore(b).set({ name: 'gh', command: '/usr/bin/gh', args: ['api'], env: { GH_TOKEN: 'github:work' }, scrub: true });
  const token = new AgentStore(b).create('claude-code', 'default', ['anthropic']);
  return { b, token };
}

test('backup: round trip restores keys, metadata, providers, tools and agents into an empty store', () => {
  const { b, token } = populated();
  const { text, items } = createBackup(PASS, b);
  assert.equal(items.length, 5);
  assert.ok(!text.includes(KEY) && !text.includes('anthropic') && !text.includes('acme'), 'backup file must not contain plaintext');

  const fresh = new MemoryBackend();
  const r = restoreBackup(readBackup(text, PASS), fresh);
  assert.equal(r.added.length, 5);
  assert.deepEqual(r.invalid, []);
  const keys = new KeyringStore(fresh);
  assert.equal(keys.get('anthropic'), KEY);
  assert.equal(keys.get('github', 'work'), GH);
  assert.deepEqual(keys.list(), new KeyringStore(b).list(), 'metadata (createdAt, rotation) is preserved');
  assert.equal(new ProviderStore(fresh).get('acme')?.auth.type, 'header');
  assert.deepEqual(new ToolStore(fresh).get('gh')?.env, { GH_TOKEN: 'github:work' });
  assert.equal(new AgentStore(fresh).verifier()(token)?.name, 'claude-code', 'existing agent tokens keep working');
});

test('backup: wrong passphrase, tampering and non-backup files are rejected', () => {
  const { b } = populated();
  const { text } = createBackup(PASS, b);
  assert.throws(() => readBackup(text, 'wrong passphrase here'), /wrong passphrase|modified/);
  const h = JSON.parse(text);
  const ct = Buffer.from(h.ct, 'base64'); ct[3] ^= 1; h.ct = ct.toString('base64');
  assert.throws(() => readBackup(JSON.stringify(h), PASS), /wrong passphrase|modified/);
  assert.throws(() => readBackup('{"v":1,"kdf":{}}', PASS), /Not a LLLanyard backup/);
  assert.throws(() => readBackup('not json', PASS), /Not a LLLanyard backup/);
  assert.throws(() => createBackup('short', b), /at least 12/);
});

test('restore: merges by default, keeps existing items, --overwrite replaces them, never deletes', () => {
  const { b } = populated();
  const payload = readBackup(createBackup(PASS, b).text, PASS);

  const target = new MemoryBackend();
  const keys = new KeyringStore(target);
  const other = 'sk-ant-' + 'C'.repeat(40);
  keys.set('anthropic', other);
  keys.set('openai', 'sk-' + 'D'.repeat(40));

  const r1 = restoreBackup(payload, target);
  assert.deepEqual(r1.kept.map((i) => i.id), ['anthropic:default']);
  assert.equal(keys.get('anthropic'), other, 'existing key kept');
  assert.equal(keys.get('github', 'work'), GH, 'missing key added');
  assert.ok(keys.get('openai'), 'items not in the backup are untouched');

  const r2 = restoreBackup(payload, target, { overwrite: true });
  assert.ok(r2.replaced.some((i) => i.id === 'anthropic:default'));
  assert.equal(keys.get('anthropic'), KEY);
  assert.equal(keys.list().length, 3, 'index has no duplicates');
});

test('restore: dry run writes nothing', () => {
  const { b } = populated();
  const target = new MemoryBackend();
  const r = restoreBackup(readBackup(createBackup(PASS, b).text, PASS), target, { dryRun: true });
  assert.equal(r.added.length, 5);
  assert.deepEqual(collectItems(target), []);
});

test('restore: key limit is checked before anything is written', () => {
  const { b } = populated();
  const payload = readBackup(createBackup(PASS, b).text, PASS);
  const target = new MemoryBackend();
  const keys = new KeyringStore(target);
  for (let i = 0; i < 4; i++) keys.set('openai', 'sk-' + String(i).repeat(30), { label: `c${i}` });
  assert.throws(() => restoreBackup(payload, target, { maxKeys: 5 }), StoreError);
  assert.equal(keys.list().length, 4);
  assert.equal(new ProviderStore(target).list().length, 0, 'nothing partially restored');
});

test('restore: invalid or unknown items are skipped and reported, valid ones still restored', () => {
  const { b } = populated();
  const payload = readBackup(createBackup(PASS, b).text, PASS);
  payload.items.push(
    { kind: 'key', id: 'evil:default', records: { 'key:evil:default': 'has spaces in it', 'meta:evil:default': '{}' } },
    { kind: 'provider', id: 'bad', records: { 'provider:bad': JSON.stringify({ id: 'bad', upstream: 'http://169.254.169.254', auth: { type: 'bearer' } }) } },
    { kind: 'key', id: 'x:default', records: { 'key:x:default': KEY, 'meta:x:default': '{}', __index__: '[]' } },
    { kind: 'nope' as any, id: 'n', records: {} },
  );
  const target = new MemoryBackend();
  const r = restoreBackup(payload, target);
  assert.equal(r.invalid.length, 4);
  assert.equal(r.added.length, 5);
  assert.equal(target.get('provider:bad'), null);
  assert.equal(target.get('key:evil:default'), null);
});

test('backup: a team member gets their team server link back', () => {
  const { b } = populated();
  new TeamStore(b).set({ url: 'https://keys.example.com:3443', token: 'lly_' + 'T'.repeat(43) });
  const { text, items } = createBackup(PASS, b);
  assert.equal(items.length, 6);
  assert.ok(items.some((i) => describeItem(i) === 'team server link'));
  assert.ok(!text.includes('keys.example.com'), 'the link is encrypted like everything else');

  const fresh = new MemoryBackend();
  restoreBackup(readBackup(text, PASS), fresh);
  assert.deepEqual(new TeamStore(fresh).get(), new TeamStore(b).get());

  // An edited link is refused, not restored.
  const bad = readBackup(text, PASS);
  const team = bad.items.find((i) => i.kind === 'team')!;
  team.records['__team__'] = JSON.stringify({ url: 'http://evil.example', token: 'lly_' + 'T'.repeat(43) });
  const r = restoreBackup(bad, new MemoryBackend());
  assert.deepEqual(r.invalid.map((i) => i.reason), ['team link is not valid']);
});
