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
import { AuthGuard } from '../src/ratelimit.js';
import { checkServeOptions } from '../src/serve-options.js';
import { AgentStore, MemoryBackend } from '../../core/src/index.js';

const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-tls-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'), '-days', '2', '-subj', '/CN=keys.team.test', '-addext', 'subjectAltName=DNS:keys.team.test'], { stdio: 'ignore' });
const tls = { cert: readFileSync(path.join(dir, 'c.pem')), key: readFileSync(path.join(dir, 'k.pem')) };

async function setup(over: Record<string, unknown> = {}) {
  const up = http.createServer((_q, r) => r.end('ok'));
  await new Promise<void>((r) => up.listen(0, '127.0.0.1', r));
  const upPort = (up.address() as AddressInfo).port;
  const logs: any[] = [];
  const srv = createProxy({
    store: { get: () => 'REAL-KEY-1234567890' },
    verify: (t) => (t === 'lly_good' ? { name: 'alice', client: 'default' } : null),
    providers: { fake: { upstream: `http://127.0.0.1:${upPort}`, allowLocal: true, inject: () => {} } },
    log: (r) => logs.push(r), ...over,
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const port = (srv.address() as AddressInfo).port;
  return { port, logs, close: () => { srv.close(); up.close(); } };
}

const get = (port: number, headers: Record<string, string>, secure = false) => new Promise<{ status: number; body: string }>((resolve, reject) => {
  const lib: any = secure ? https : http;
  const req = lib.request({ host: '127.0.0.1', port, path: '/fake/x', method: 'GET', headers, ca: secure ? tls.cert : undefined, servername: secure ? 'keys.team.test' : undefined, agent: false }, (res: http.IncomingMessage) => {
    let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode!, body: b }));
  });
  req.on('error', reject); req.end();
});

test('shared mode: TLS, configured host name accepted, other host names rejected', async () => {
  const s = await setup({ tls, allowedHosts: ['keys.team.test'] });
  try {
    const ok = await get(s.port, { host: 'keys.team.test', authorization: 'Bearer lly_good' }, true);
    assert.equal(ok.status, 200);
    assert.equal((await get(s.port, { host: 'keys.team.test:8443', authorization: 'Bearer lly_good' }, true)).status, 200);
    assert.equal((await get(s.port, { host: 'evil.example', authorization: 'Bearer lly_good' }, true)).status, 403);
    assert.equal(s.logs.find((l) => l.status === 200)?.ip !== undefined, true, 'requests log the caller address');
  } finally { s.close(); }
});

test('without allowedHosts only loopback names work (DNS rebinding defence unchanged)', async () => {
  const s = await setup();
  try {
    assert.equal((await get(s.port, { host: 'keys.team.test', authorization: 'Bearer lly_good' })).status, 403);
    assert.equal((await get(s.port, { host: `127.0.0.1:${s.port}`, authorization: 'Bearer lly_good' })).status, 200);
  } finally { s.close(); }
});

test('brute force: repeated bad tokens lock the address out, even for a valid token, then it recovers', async () => {
  let t = 1_000_000;
  const s = await setup({ authGuard: new AuthGuard(5, 60_000, 60_000, () => t) });
  const h = (tok: string) => ({ host: `127.0.0.1:${s.port}`, authorization: `Bearer ${tok}` });
  try {
    for (let i = 0; i < 5; i++) assert.equal((await get(s.port, h('lly_bad' + i))).status, 401);
    assert.equal((await get(s.port, h('lly_good'))).status, 429);
    assert.ok(s.logs.some((l) => l.reason === 'auth-lockout'));
    t += 61_000;
    assert.equal((await get(s.port, h('lly_good'))).status, 200);
  } finally { s.close(); }
});

test('good logins reset the failure count', async () => {
  const g = new AuthGuard(3);
  g.fail('1.1.1.1'); g.fail('1.1.1.1'); g.ok('1.1.1.1'); g.fail('1.1.1.1'); g.fail('1.1.1.1');
  assert.equal(g.blocked('1.1.1.1'), false);
  g.fail('1.1.1.1');
  assert.equal(g.blocked('1.1.1.1'), true);
});

test('checkServeOptions: sharing needs Pro, TLS and a host name; loopback is always fine', () => {
  const t = { cert: 'c', key: 'k' };
  assert.doesNotThrow(() => checkServeOptions({}, 'free'));
  assert.doesNotThrow(() => checkServeOptions({ host: '127.0.0.1' }, 'free'));
  assert.throws(() => checkServeOptions({ host: '0.0.0.0', tls: t, allowedHosts: ['a.b'] }, 'free'), /Pro/);
  assert.throws(() => checkServeOptions({ host: '0.0.0.0', allowedHosts: ['a.b'] }, 'pro'), /TLS/);
  assert.throws(() => checkServeOptions({ host: '0.0.0.0', tls: t }, 'team'), /allow-host/);
  assert.doesNotThrow(() => checkServeOptions({ host: '0.0.0.0', tls: t, allowedHosts: ['a.b'] }, 'pro'));
});

test('agent tokens can expire; expired tokens stop verifying', () => {
  const a = new AgentStore(new MemoryBackend());
  const tok = a.create('temp', 'default', undefined, { expiresAt: new Date(Date.now() + 60_000) });
  const forever = a.create('perm');
  assert.equal(a.verifier()(tok)?.name, 'temp');
  assert.equal(a.verifier(() => Date.now() + 120_000)(tok), null);
  assert.equal(a.verifier(() => Date.now() + 120_000)(forever)?.name, 'perm');
  assert.throws(() => a.create('x', 'default', undefined, { expiresAt: new Date(Date.now() - 1000) }));
  assert.ok(a.list().find((x) => x.name === 'temp')!.expiresAt);
});
