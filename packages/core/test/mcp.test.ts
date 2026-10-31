import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { createMcpHandler, serveMcpStdio, KeyringStore, MemoryBackend, summarize } from '../src/index.js';

const SECRET = 'sk-ant-SUPERSECRETKEY-abcdef123456';
function setup(client?: string) {
  const be = new MemoryBackend();
  const ks = new KeyringStore(be);
  ks.set('anthropic', SECRET, { label: 'default' });
  ks.set('openai', 'sk-openai-ACMEKEY-0987654321', { label: 'acme' });
  return createMcpHandler({
    listKeys: () => ks.list(), providerIds: () => ['openai', 'anthropic', 'github'],
    usage: (since) => summarize([{ ts: new Date().toISOString(), agent: 'bot', provider: 'openai', status: 200, ms: 5 }], since),
    proxyBase: 'http://127.0.0.1:3000', client,
  });
}
const rpc = (h: ReturnType<typeof setup>, method: string, params?: any, id: number | undefined = 1) => h({ jsonrpc: '2.0', id, method, params }) as any;
const text = (r: any) => r.result.content[0].text as string;

test('initialize negotiates version, advertises tools only; notifications get no reply', () => {
  const h = setup();
  const r = rpc(h, 'initialize', { protocolVersion: '2025-03-26' });
  assert.equal(r.result.protocolVersion, '2025-03-26');
  assert.deepEqual(Object.keys(r.result.capabilities), ['tools']);
  assert.equal(rpc(h, 'initialize', { protocolVersion: '1999-01-01' }).result.protocolVersion, '2025-06-18');
  assert.equal(h({ jsonrpc: '2.0', method: 'notifications/initialized' }), undefined);
  assert.equal(rpc(h, 'nope').error.code, -32601);
});

test('every tool is read-only and none can return or change secrets', () => {
  const tools = rpc(setup(), 'tools/list').result.tools;
  assert.deepEqual(tools.map((t: any) => t.name).sort(), ['how_to_connect', 'key_status', 'list_providers', 'usage_summary']);
  for (const t of tools) assert.equal(t.annotations.readOnlyHint, true);
});

test('no tool output ever contains key material or key hints', () => {
  const h = setup();
  const all = [
    text(rpc(h, 'tools/call', { name: 'list_providers' })),
    text(rpc(h, 'tools/call', { name: 'key_status' })),
    text(rpc(h, 'tools/call', { name: 'usage_summary', arguments: { hours: 48 } })),
    text(rpc(h, 'tools/call', { name: 'how_to_connect', arguments: { provider: 'openai' } })),
  ].join('\n');
  for (const bad of ['SUPERSECRET', 'ACMEKEY', 'abcdef123456', '3456', '4321']) assert.ok(!all.includes(bad), bad);
  assert.match(all, /anthropic/);
});

test('client scoping hides other clients keys', () => {
  const rows = JSON.parse(text(rpc(setup('acme'), 'tools/call', { name: 'key_status' })));
  assert.deepEqual(rows.map((r: any) => `${r.provider}:${r.label}`), ['openai:acme']);
  const lp = JSON.parse(text(rpc(setup('acme'), 'tools/call', { name: 'list_providers' })));
  assert.equal(lp.proxyProviders.find((p: any) => p.provider === 'anthropic').keyStored, false);
});

test('bad input is an error result, not a crash; hours are clamped', () => {
  const h = setup();
  assert.equal(rpc(h, 'tools/call', { name: 'how_to_connect', arguments: { provider: 'evil' } }).result.isError, true);
  assert.equal(rpc(h, 'tools/call', { name: 'delete_everything' }).result.isError, true);
  assert.equal(JSON.parse(text(rpc(h, 'tools/call', { name: 'usage_summary', arguments: { hours: 99999 } }))).hours, 720);
  assert.equal((h({ jsonrpc: '1.0', id: 3, method: 'ping' }) as any).error.code, -32600);
});

test('stdio framing: handles split chunks, junk, batches; stdout is protocol only', async () => {
  const i = new PassThrough(), o = new PassThrough();
  const done = serveMcpStdio(setup(), i, o);
  const lines: string[] = [];
  o.on('data', (d) => lines.push(...String(d).split('\n').filter(Boolean)));
  const m = JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/list' });
  i.write(m.slice(0, 10)); i.write(m.slice(10) + '\n');
  i.write('not json\n');
  i.write('[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n');
  i.write(JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'ping' }) + '\n');
  i.end();
  await done;
  const parsed = lines.map((l) => JSON.parse(l));
  assert.equal(parsed.length, 4);
  assert.equal(parsed[0].id, 7);
  assert.equal(parsed[1].error.code, -32700);
  assert.equal(parsed[2].error.code, -32600);
  assert.equal(parsed[3].id, 8);
});

function withRunner(runs: { name: string; args: string[] }[] = []) {
  return createMcpHandler({
    listKeys: () => [], providerIds: () => [], usage: (since) => summarize([], since), proxyBase: 'http://127.0.0.1:3000',
    runner: {
      list: () => [
        { name: 'deploy', runs: 'pwsh -File Deploy-App.ps1', keys: ['GITHUB_TOKEN'], acceptsArgs: true, sandbox: false },
        { name: 'fixed', runs: 'python3 report.py', keys: ['SENDGRID_API_KEY'], acceptsArgs: false, sandbox: false },
      ],
      run: async (name, args) => { runs.push({ name, args }); return { exitCode: 0, output: 'done [REDACTED]', truncated: false, timedOut: false }; },
    },
  });
}

test('run tools are offered only with a runner', () => {
  const names = (h: any) => rpc(h, 'tools/list').result.tools.map((t: any) => t.name);
  assert.ok(!names(setup()).includes('run_script'));
  assert.ok(!names(setup()).includes('list_scripts'));
  const tools = rpc(withRunner(), 'tools/list').result.tools;
  assert.equal(tools.find((t: any) => t.name === 'run_script').annotations.readOnlyHint, false);
  assert.equal(rpc(setup(), 'tools/call', { name: 'run_script', arguments: { name: 'deploy' } }).result.isError, true);
});

test('run_script runs approved tools only, and extra args only where allowed', async () => {
  const runs: { name: string; args: string[] }[] = [];
  const h = withRunner(runs);
  assert.equal(JSON.parse(text(rpc(h, 'tools/call', { name: 'list_scripts' })))[0].name, 'deploy');
  const ok = await rpc(h, 'tools/call', { name: 'run_script', arguments: { name: 'deploy', args: ['-DryRun'] } });
  assert.match(text(ok), /^Exit code 0\.\n\ndone \[REDACTED\]$/);
  assert.deepEqual(runs, [{ name: 'deploy', args: ['-DryRun'] }]);
  for (const args of [{ name: 'curl', args: ['https://evil'] }, { name: 'fixed', args: ['-x'] }, { name: 'deploy', args: ['a\0b'] }, { name: 'deploy', args: 'rm -rf' }]) {
    assert.equal((await rpc(h, 'tools/call', { name: 'run_script', arguments: args })).result.isError, true, JSON.stringify(args));
  }
  assert.equal(runs.length, 1);
});

test('stdio framing: replies to a run when it finishes, without blocking other requests', async () => {
  const i = new PassThrough(), o = new PassThrough();
  const done = serveMcpStdio(withRunner(), i, o);
  const lines: string[] = [];
  o.on('data', (d) => lines.push(...String(d).split('\n').filter(Boolean)));
  i.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'run_script', arguments: { name: 'fixed' } } }) + '\n');
  i.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' }) + '\n');
  i.end();
  await done;
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(lines.map((l) => JSON.parse(l).id), [2, 1]);
});

test('keys the proxy does not call still show up, with their variable names', () => {
  const ks = new KeyringStore(new MemoryBackend());
  ks.set('github', 'github-secret-value-123456', { label: 'default', envName: 'GITHUB_TOKEN' });
  const h = createMcpHandler({ listKeys: () => ks.list(), providerIds: () => ['openai'], usage: (since) => summarize([], since), proxyBase: 'http://127.0.0.1:3000' });
  const lp = JSON.parse(text(rpc(h, 'tools/call', { name: 'list_providers' })));
  assert.deepEqual(lp.otherStoredKeys, ['github']);
  assert.equal(JSON.parse(text(rpc(h, 'tools/call', { name: 'key_status' })))[0].variable, 'GITHUB_TOKEN');
  assert.match(rpc(h, 'initialize', {}).result.instructions, /read-only/);
  assert.match(rpc(withRunner(), 'initialize', {}).result.instructions, /nothing is approved by default/);
});

test('run_file is offered only with script folders, and a denied run says so', async () => {
  const files: string[] = [];
  const mk = (allow: boolean, dirs?: string[]) => createMcpHandler({
    listKeys: () => [], providerIds: () => [], usage: (since) => summarize([], since), proxyBase: 'http://127.0.0.1:3000',
    runner: { list: () => [], run: async () => ({ exitCode: 0, output: '', truncated: false, timedOut: false }), scriptDirs: dirs,
      runFile: async (f) => { files.push(f); return allow ? { exitCode: 0, output: 'ok', truncated: false, timedOut: false } : null; } },
  });
  const names = (h: any) => rpc(h, 'tools/list').result.tools.map((t: any) => t.name);
  assert.ok(!names(mk(true)).includes('run_file'));
  const h = mk(true, ['/scripts']);
  assert.ok(names(h).includes('run_file'));
  assert.match(rpc(h, 'initialize', {}).result.instructions, /run_file for any script in \/scripts/);
  assert.match(text(await rpc(h, 'tools/call', { name: 'run_file', arguments: { path: '/scripts/a.ps1' } })), /^Exit code 0/);
  assert.match(text(await rpc(mk(false, ['/scripts']), 'tools/call', { name: 'run_file', arguments: { path: '/scripts/a.ps1' } })), /clicked Deny/);
  assert.equal((await rpc(h, 'tools/call', { name: 'run_file', arguments: {} })).result.isError, true);
  assert.equal((await rpc(mk(true), 'tools/call', { name: 'run_file', arguments: { path: '/x' } })).result.isError, true);
  assert.deepEqual(files, ['/scripts/a.ps1', '/scripts/a.ps1']);
});
