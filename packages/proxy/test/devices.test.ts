import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { createProxy } from '../src/server.js';
import { startRelay, relayEnv } from '../src/relay.js';
import { DeviceStore, MemoryBackend, machineId } from '../../core/src/index.js';

const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-dev-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'), '-days', '2', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
const tls = { cert: readFileSync(path.join(dir, 'c.pem')), key: readFileSync(path.join(dir, 'k.pem')) };
const ca = tls.cert.toString();

async function setup(over: Record<string, unknown> = {}) {
  const seen: { key: string | undefined; machine: string | undefined; path: string }[] = [];
  const api = http.createServer((q, r) => { seen.push({ key: q.headers['x-key'] as string, machine: q.headers['x-lllanyard-machine'] as string, path: q.url ?? '' }); r.end('ok'); });
  await new Promise<void>((r) => api.listen(0, '127.0.0.1', r));
  const devices = new DeviceStore(new MemoryBackend());
  let verifyDevice = devices.verifier(3);
  const logs: any[] = [];
  const main = createProxy({
    store: { get: (p: string, l: string) => (p === 'github' ? (l === 'acme' ? 'ACME-KEY-1234567890' : 'REAL-KEY-1234567890') : null) },
    verify: (t) => (t === 'lly_agent_here' ? { name: 'claude-here', client: 'default' } : null),
    providers: { github: { upstream: `http://127.0.0.1:${(api.address() as AddressInfo).port}`, allowLocal: true, inject: (h, k) => { h['x-key'] = k; } } },
    tls, log: (r) => logs.push(r),
    devices: { verify: (t, m) => verifyDevice(t, m), pair: (c, m) => { const r = devices.pair(c, m); verifyDevice = devices.verifier(3); return r; } },
    agentsLoopbackOnly: true,
    keyVars: () => ({ GITHUB_TOKEN: 'github', ACME_TOKEN: 'github:acme' }),
    ...over,
  });
  await new Promise<void>((r) => main.listen(0, '127.0.0.1', r));
  const port = (main.address() as AddressInfo).port;
  return { devices, port, url: `https://127.0.0.1:${port}`, seen, logs, close: () => { main.close(); api.close(); } };
}

const req = (url: string, o: { method?: string; path: string; headers?: Record<string, string>; body?: string; secure?: boolean }) =>
  new Promise<{ status: number; body: string }>((resolve, reject) => {
    const lib: any = o.secure === false ? http : https;
    const r = lib.request(new URL(o.path, url), { method: o.method ?? 'GET', headers: o.headers ?? {}, ca, agent: false }, (res: http.IncomingMessage) => {
      let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode!, body: b }));
    });
    r.on('error', reject); r.end(o.body);
  });

const pair = (url: string, code: string, machine: string) => req(url, { method: 'POST', path: '/_lllanyard/pair', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code, machine }) });

test('a device pairs with a code, then reaches keys only from its own machine', async () => {
  const s = await setup();
  try {
    const M = machineId('laptop-hw');
    const { code } = s.devices.invite('laptop', 3);
    assert.equal((await pair(s.url, 'WRON-GCOD', M)).status, 400);
    const ok = await pair(s.url, code, M);
    assert.equal(ok.status, 200);
    const { token } = JSON.parse(ok.body);
    assert.equal((await pair(s.url, code, M)).status, 400, 'codes work once');

    const call = (machine?: string) => req(s.url, { path: '/github/user', headers: { authorization: `Bearer ${token}`, ...(machine ? { 'x-lllanyard-machine': machine } : {}) } });
    assert.equal((await call(M)).status, 200);
    assert.deepEqual(s.seen.at(-1), { key: 'REAL-KEY-1234567890', machine: undefined, path: '/user' }, 'the machine ID is not passed on');
    const other = await call(machineId('someone-else'));
    assert.equal(other.status, 401);
    assert.match(other.body, /different computer/);
    assert.equal((await call()).status, 401);

    const who = await req(s.url, { path: '/_lllanyard/whoami', headers: { authorization: `Bearer ${token}`, 'x-lllanyard-machine': M } });
    assert.deepEqual(JSON.parse(who.body), { name: 'device:laptop', client: 'default', providers: null, vars: { GITHUB_TOKEN: 'github', ACME_TOKEN: 'github:acme' }, keys: true }, 'variable names, never values');
    const agentWho = await req(s.url, { path: '/_lllanyard/whoami', headers: { authorization: 'Bearer lly_agent_here' } });
    assert.equal(JSON.parse(agentWho.body).vars, undefined);
  } finally { s.close(); }
});

test('the relay on a device: tools use a local token; the main computer sees the device', async () => {
  const s = await setup();
  try {
    const M = machineId('laptop-hw');
    const { token } = JSON.parse((await pair(s.url, s.devices.invite('laptop', 3).code, M)).body);
    const relay = await startRelay({ url: s.url, deviceToken: token, machine: M, ca, localToken: 'lly_local_abcdefghijklmnop' });
    try {
      const env = relayEnv(relay.base, 'lly_local_abcdefghijklmnop', { GITHUB_TOKEN: 'github' });
      assert.equal(env.GITHUB_TOKEN, 'lly_local_abcdefghijklmnop');
      assert.equal(env.LLLANYARD_GITHUB_URL, `${relay.base}/github`);
      const ok = await req(relay.base, { secure: false, path: '/github/repos?x=1', headers: { authorization: 'Bearer lly_local_abcdefghijklmnop' } });
      assert.equal(ok.status, 200);
      assert.equal(s.seen.at(-1)?.path, '/repos?x=1');
      assert.equal(s.logs.find((l) => l.status === 200)?.agent, 'device:laptop');
      assert.equal((await req(relay.base, { secure: false, path: '/github/x', headers: { authorization: `Bearer ${token}` } })).status, 401, 'the device token itself is not accepted by the relay');
      assert.equal((await req(relay.base, { secure: false, path: '/github/x', headers: { 'x-api-key': 'lly_local_abcdefghijklmnop', host: 'evil.example' } })).status, 403);
    } finally { relay.close(); }
  } finally { s.close(); }
});

test('Pro: agent tokens work on the main computer only; paired devices work from anywhere', async () => {
  let local = true;
  const s = await setup({ isLocalAddress: () => local });
  try {
    assert.equal((await req(s.url, { path: '/github/x', headers: { authorization: 'Bearer lly_agent_here' } })).status, 200);
    const M = machineId('laptop-hw');
    const { token } = JSON.parse((await pair(s.url, s.devices.invite('laptop', 3).code, M)).body);
    local = false; // as if the requests came from another computer
    const agent = await req(s.url, { path: '/github/x', headers: { authorization: 'Bearer lly_agent_here' } });
    assert.equal(agent.status, 403);
    assert.match(agent.body, /pair it/);
    assert.equal((await req(s.url, { path: '/github/x', headers: { authorization: `Bearer ${token}`, 'x-lllanyard-machine': M } })).status, 200);
  } finally { s.close(); }
});

const fetchKeys = (url: string, token: string, machine: string, vars: unknown) =>
  req(url, { method: 'POST', path: '/_lllanyard/keys', headers: { authorization: `Bearer ${token}`, 'x-lllanyard-machine': machine, 'content-type': 'application/json' }, body: JSON.stringify({ vars, tool: 'pwsh Deploy-App.ps1' }) });

test('exec --remote: a paired device gets just the keys it asks for, and the main computer logs it', async () => {
  const s = await setup();
  try {
    const M = machineId('laptop-hw');
    const { token } = JSON.parse((await pair(s.url, s.devices.invite('laptop', 3).code, M)).body);
    const r = await fetchKeys(s.url, token, M, ['ACME_TOKEN', 'NOT_A_KEY', 'constructor']);
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(r.body), { keys: { ACME_TOKEN: 'ACME-KEY-1234567890' } });
    assert.deepEqual(s.logs.find((l) => l.event === 'device-keys'), { ts: s.logs.find((l) => l.event === 'device-keys').ts, event: 'device-keys', agent: 'device:laptop', ip: '127.0.0.1', keys: ['ACME_TOKEN'], tool: 'pwsh Deploy-App.ps1' });
    assert.equal((await fetchKeys(s.url, token, machineId('other'), ['GITHUB_TOKEN'])).status, 401, 'not from another machine');
    assert.equal((await fetchKeys(s.url, 'lly_agent_here', M, ['GITHUB_TOKEN'])).status, 403, 'agent tokens can never fetch keys');
    assert.equal((await fetchKeys(s.url, token, M, 'GITHUB_TOKEN')).status, 400);
  } finally { s.close(); }
});

test('a device paired with --no-keys can use the proxy but never fetch a key', async () => {
  const s = await setup();
  try {
    const M = machineId('tablet-hw');
    const { token } = JSON.parse((await pair(s.url, s.devices.invite('tablet', 3, { noKeys: true }).code, M)).body);
    const r = await fetchKeys(s.url, token, M, ['GITHUB_TOKEN']);
    assert.equal(r.status, 403);
    assert.match(r.body, /no-keys/);
    assert.equal(JSON.parse((await req(s.url, { path: '/_lllanyard/whoami', headers: { authorization: `Bearer ${token}`, 'x-lllanyard-machine': M } })).body).keys, false);
    assert.equal((await req(s.url, { path: '/github/x', headers: { authorization: `Bearer ${token}`, 'x-lllanyard-machine': M } })).status, 200);
  } finally { s.close(); }
});
