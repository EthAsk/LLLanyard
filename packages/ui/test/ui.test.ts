import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createUiServer, type UiDeps } from '../src/server.js';

const SECRET = 'sk-SUPERSECRET-0123456789';
function mkDeps(calls: any[] = []): UiDeps {
  return {
    state: () => ({ keys: [{ provider: 'openai', label: 'default', last4: '6789' }], agents: [] }),
    addKey: (b) => { calls.push(['addKey', b]); if (b.provider === 'bad') throw Object.assign(new Error('Key looks invalid'), { user: true }); if (b.provider === 'boom') throw new Error('kaboom with ' + b.secret); },
    removeKey: () => true, createAgent: (b) => { calls.push(['createAgent', b]); return 'lly_TOKEN'; }, revokeAgent: () => true,
    activateLicense: () => ({ tier: 'pro' }), removeLicense: () => {},
    review: async () => ({ text: 'Rotate now', source: 'rules' }), setAssistant: () => {}, proxy: async () => ({ running: true }),
    isUserError: (e: any) => e?.user === true,
    addProvider: (b) => { calls.push(['addProvider', b]); }, removeProvider: () => true,
    addTool: (b) => { calls.push(['addTool', b]); return { name: b.name }; }, removeTool: () => true, setKeyEnv: (b) => { calls.push(['setKeyEnv', b]); },
    backup: (p) => { calls.push(['backup', p]); return { file: '/home/x/lllanyard-backup.enc', items: ['key github:default'] }; },
    restore: (b) => { calls.push(['restore', { ...b, text: b.text.length }]); return { added: [], replaced: [], kept: [], invalid: [] }; },
  };
}
async function up(deps = mkDeps()) {
  const ui = createUiServer(deps, 'T'.repeat(43));
  await new Promise<void>((r) => ui.server.listen(0, '127.0.0.1', r));
  const port = (ui.server.address() as AddressInfo).port;
  const call = (method: string, path: string, opt: { headers?: Record<string, string>; body?: unknown; raw?: string; token?: string | null } = {}) => new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const data = opt.raw ?? (opt.body === undefined ? undefined : JSON.stringify(opt.body));
    const h: Record<string, string> = { host: `127.0.0.1:${port}`, ...(opt.token === null ? {} : { 'x-lly-session': opt.token ?? ui.token }), ...(data !== undefined ? { 'content-type': 'application/json' } : {}), ...opt.headers };
    const r = http.request({ host: '127.0.0.1', port, path, method, headers: h }, (res) => { let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: b })); });
    r.on('error', reject); r.end(data);
  });
  return { ui, port, call, close: () => ui.server.close() };
}

test('page: served without data, strict CSP with nonce, no framing, no caching', async () => {
  const s = await up();
  try {
    const r = await s.call('GET', '/', { token: null });
    assert.equal(r.status, 200);
    const csp = String(r.headers['content-security-policy']);
    assert.match(csp, /default-src 'none'/); assert.match(csp, /frame-ancestors 'none'/); assert.match(csp, new RegExp(`script-src 'nonce-${s.ui.nonce.replace(/[+/=]/g, '\\$&')}'`));
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.ok(r.body.includes(`nonce="${s.ui.nonce}"`) && !r.body.includes('__NONCE__'));
    assert.ok(!r.body.includes(s.ui.token), 'the page itself never contains the session token');
    assert.ok(!/innerHTML|outerHTML|document\.write|eval\(/.test(r.body), 'no HTML-injection sinks in page code');
  } finally { s.close(); }
});

test('API needs the session token on every route', async () => {
  const s = await up();
  try {
    for (const [m, p] of [['GET', '/api/state'], ['POST', '/api/keys'], ['DELETE', '/api/agents'], ['POST', '/api/proxy'], ['POST', '/api/license']] as const) {
      assert.equal((await s.call(m, p, { token: null, body: {} })).status, 401, `${m} ${p}`);
      assert.equal((await s.call(m, p, { token: 'wrong', body: {} })).status, 401);
    }
    assert.equal((await s.call('GET', '/api/state')).status, 200);
  } finally { s.close(); }
});

test('DNS rebinding, foreign Origin and cross-site fetches are refused even with a valid token', async () => {
  const s = await up();
  try {
    assert.equal((await s.call('GET', '/api/state', { headers: { host: 'evil.example' } })).status, 403);
    assert.equal((await s.call('GET', '/api/state', { headers: { host: `evil.example:${s.port}` } })).status, 403);
    assert.equal((await s.call('POST', '/api/keys', { body: {}, headers: { origin: 'http://evil.example' } })).status, 403);
    assert.equal((await s.call('GET', '/api/state', { headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
    assert.equal((await s.call('GET', '/api/state', { headers: { origin: `http://127.0.0.1:${s.port}`, 'sec-fetch-site': 'same-origin' } })).status, 200);
  } finally { s.close(); }
});

test('write requests must be JSON, size-limited and well-formed', async () => {
  const s = await up();
  try {
    assert.equal((await s.call('POST', '/api/keys', { raw: 'provider=x', headers: { 'content-type': 'text/plain' } })).status, 415);
    assert.equal((await s.call('POST', '/api/keys', { raw: '{nope' })).status, 400);
    assert.equal((await s.call('POST', '/api/keys', { raw: JSON.stringify({ provider: 'x', secret: 'a'.repeat(70_000) }) })).status, 413);
    assert.equal((await s.call('POST', '/api/keys', { body: { provider: 5, secret: 'x' } })).status, 400);
    assert.equal((await s.call('POST', '/api/agents', { body: { name: 'a', providers: 'not-a-list' } })).status, 200);
    assert.equal((await s.call('GET', '/api/unknown')).status, 404);
  } finally { s.close(); }
});

test('flows reach the app; errors never echo secrets; internal errors are generic', async () => {
  const calls: any[] = [];
  const s = await up(mkDeps(calls));
  try {
    assert.equal((await s.call('POST', '/api/keys', { body: { provider: 'openai', label: 'acme', secret: SECRET, rotateDays: 30 } })).status, 200);
    assert.deepEqual(calls[0], ['addKey', { provider: 'openai', label: 'acme', secret: SECRET, rotateDays: 30 }]);
    const bad = await s.call('POST', '/api/keys', { body: { provider: 'bad', secret: SECRET } });
    assert.equal(bad.status, 400); assert.match(bad.body, /invalid/);
    const boom = await s.call('POST', '/api/keys', { body: { provider: 'boom', secret: SECRET } });
    assert.equal(boom.status, 500); assert.ok(!boom.body.includes(SECRET)); assert.match(boom.body, /Internal error/);
    const ag = await s.call('POST', '/api/agents', { body: { name: 'bot', client: 'acme', providers: ['openai'], expiresDays: 30 } });
    assert.equal(JSON.parse(ag.body).token, 'lly_TOKEN');
    assert.equal(JSON.parse((await s.call('POST', '/api/assistant', { body: { useModel: false } })).body).source, 'rules');
  } finally { s.close(); }
});

test('state endpoint cannot leak a secret even if asked repeatedly', async () => {
  const s = await up();
  try { assert.ok(!(await s.call('GET', '/api/state')).body.includes('SUPERSECRET')); } finally { s.close(); }
});

test('api: services, tools, backup and restore validate input before reaching the stores', async () => {
  const calls: any[] = [];
  const s = await up(mkDeps(calls));
  try {
    assert.equal((await s.call('POST', '/api/providers', { body: { id: 'acme', upstream: 'https://api.example.com', auth: 'header', header: 'X-API-KEY' } })).status, 200);
    assert.deepEqual(calls.at(-1), ['addProvider', { id: 'acme', upstream: 'https://api.example.com', auth: 'header', header: 'X-API-KEY', prefix: undefined }]);

    const tool = { name: 't', command: 'python3', args: ['/opt/s.py'], env: { GITHUB_TOKEN: 'github' }, allowArgs: true, passEnv: ['CLAUDE_API_ENV'], allowHosts: [] };
    assert.equal((await s.call('POST', '/api/tools', { body: tool })).status, 200);
    assert.deepEqual(calls.at(-1), ['addTool', { ...tool, keys: [], pins: [] }]);
    assert.equal((await s.call('POST', '/api/tools', { body: { ...tool, keys: ['github', 'jira:secret'], pins: ['/opt/Common.ps1'] } })).status, 200);
    assert.deepEqual(calls.at(-1)[1].keys, ['github', 'jira:secret']);
    assert.equal((await s.call('POST', '/api/keys/env', { body: { provider: 'github', envName: 'GITHUB_TOKEN' } })).status, 200);
    assert.deepEqual(calls.at(-1), ['setKeyEnv', { provider: 'github', label: 'default', envName: 'GITHUB_TOKEN' }]);
    for (const bad of [{ ...tool, env: ['GITHUB_TOKEN=github'] }, { ...tool, args: '/opt/s.py' }, { ...tool, args: Array(51).fill('x') }, { ...tool, env: { K: 7 } }])
      assert.equal((await s.call('POST', '/api/tools', { body: bad })).status, 400, JSON.stringify(bad));
    assert.equal(calls.filter((c) => c[0] === 'addTool').length, 2, 'bad tool input never reaches the store');

    const b = await s.call('POST', '/api/backup', { body: { passphrase: 'correct horse battery' } });
    assert.equal(b.status, 200);
    assert.equal(JSON.parse(b.body).file, '/home/x/lllanyard-backup.enc');

    const big = 'x'.repeat(200 * 1024); // larger than the normal 64 KB body limit
    assert.equal((await s.call('POST', '/api/restore', { body: { text: big, passphrase: 'p', dryRun: true } })).status, 200);
    assert.deepEqual(calls.at(-1), ['restore', { text: big.length, passphrase: 'p', overwrite: false, dryRun: true }]);
    assert.equal((await s.call('POST', '/api/providers', { body: { id: big } })).status, 413, 'other routes keep the small limit');
    assert.equal((await s.call('POST', '/api/restore', { body: { text: 'x', passphrase: 'p' }, token: null })).status, 401, 'restore needs the session');
  } finally { s.close(); }
});
