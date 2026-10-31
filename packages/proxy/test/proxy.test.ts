import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createProxy, type ProxyDeps } from '../src/server.js';

type Seen = { url: string; headers: http.IncomingHttpHeaders; body: string };
let upstream: http.Server, other: http.Server;
let seen: Seen[] = [];
let otherHits = 0;
let upPort = 0;

const REAL = 'REAL-KEY-1234567890';
const ACME = 'ACME-KEY-0987654321';
const providers = () => ({
  fake: { upstream: `http://127.0.0.1:${upPort}`, allowLocal: true, inject: (h: http.OutgoingHttpHeaders, k: string) => { h['x-api-key'] = k; } },
  bearer: { upstream: `http://127.0.0.1:${upPort}`, allowLocal: true, inject: (h: http.OutgoingHttpHeaders, k: string) => { h['authorization'] = `Bearer ${k}`; } },
});

before(async () => {
  other = http.createServer((_q, r) => { otherHits++; r.end('stolen'); });
  await new Promise<void>((r) => other.listen(0, '127.0.0.1', r));
  const otherPort = (other.address() as AddressInfo).port;
  upstream = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen.push({ url: req.url!, headers: req.headers, body });
      if (req.url!.startsWith('/redirect')) { res.writeHead(302, { location: `http://127.0.0.1:${otherPort}/steal` }); return res.end(); }
      if (req.url!.startsWith('/sse')) {
        res.writeHead(200, { 'content-type': 'text/event-stream', 'set-cookie': 'a=b' });
        res.write('data: one\n\n');
        return setTimeout(() => res.end('data: two\n\n'), 250);
      }
      res.writeHead(201, { 'content-type': 'application/json', 'set-cookie': 'sid=1' });
      res.end(JSON.stringify({ ok: true, echo: body }));
    });
  });
  await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
  upPort = (upstream.address() as AddressInfo).port;
});
after(() => { upstream.close(); other.close(); });

async function withProxy<T>(over: Partial<ProxyDeps>, fn: (port: number, logs: any[]) => Promise<T>): Promise<T> {
  seen = []; otherHits = 0;
  const logs: any[] = [];
  const srv = createProxy({
    store: { get: (p, l) => (p === 'fake' || p === 'bearer' || p === 'dyn' ? (l === 'default' ? REAL : l === 'acme' ? ACME : null) : null) },
    verify: (t) => (t === 'lly_good' ? { name: 'a1', client: 'default' } : t === 'lly_acme' ? { name: 'a2', client: 'acme' } : t === 'lly_nokey' ? { name: 'a3', client: 'ghost' } : t === 'lly_scoped' ? { name: 'a4', client: 'default', providers: ['bearer'] } : null),
    providers: providers(), log: (r) => logs.push(r), ...over,
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  try { return await fn((srv.address() as AddressInfo).port, logs); } finally { srv.close(); }
}

function call(port: number, path: string, o: { method?: string; headers?: http.OutgoingHttpHeaders; body?: string } = {}) {
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: o.method ?? 'GET', headers: o.headers }, (res) => {
      let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: b }));
    });
    req.on('error', reject); req.end(o.body);
  });
}

test('injects the real key, strips the agent token, passes body and status through', () =>
  withProxy({}, async (port) => {
    const r = await call(port, '/fake/v1/messages?x=1', { method: 'POST', body: '{"hi":1}', headers: { 'x-api-key': 'lly_good', 'content-type': 'application/json', cookie: 'session=abc' } });
    assert.equal(r.status, 201);
    assert.equal(JSON.parse(r.body).echo, '{"hi":1}');
    assert.equal(seen[0]!.url, '/v1/messages?x=1');
    assert.equal(seen[0]!.headers['x-api-key'], REAL);
    assert.equal(seen[0]!.headers.cookie, undefined);
    assert.equal(JSON.stringify(seen[0]!.headers).includes('lly_good'), false);
    assert.equal(r.headers['set-cookie'], undefined);
  }));

test('Bearer-style providers: agent token in Authorization is replaced by the real key', () =>
  withProxy({}, async (port) => {
    await call(port, '/bearer/v1/chat', { headers: { authorization: 'Bearer lly_good' } });
    assert.equal(seen[0]!.headers.authorization, `Bearer ${REAL}`);
  }));

test('client scoping: agent bound to a client gets that client key; missing key gives 503', () =>
  withProxy({}, async (port) => {
    await call(port, '/fake/x', { headers: { 'x-api-key': 'lly_acme' } });
    assert.equal(seen[0]!.headers['x-api-key'], ACME);
    const r = await call(port, '/fake/x', { headers: { 'x-api-key': 'lly_nokey' } });
    assert.equal(r.status, 503);
  }));

test('rejects missing/invalid tokens without contacting upstream', () =>
  withProxy({}, async (port) => {
    assert.equal((await call(port, '/fake/x')).status, 401);
    assert.equal((await call(port, '/fake/x', { headers: { 'x-api-key': 'wrong' } })).status, 401);
    assert.equal(seen.length, 0);
  }));

test('blocks DNS-rebinding hosts and browser Origin requests (unless allowed)', async () => {
  await withProxy({}, async (port) => {
    assert.equal((await call(port, '/fake/x', { headers: { host: 'evil.com', 'x-api-key': 'lly_good' } })).status, 403);
    assert.equal((await call(port, '/fake/x', { headers: { origin: 'https://evil.com', 'x-api-key': 'lly_good' } })).status, 403);
    assert.equal(seen.length, 0);
  });
  await withProxy({ allowOrigin: true }, async (port) => {
    assert.equal((await call(port, '/fake/x', { headers: { origin: 'app://x', 'x-api-key': 'lly_good' } })).status, 201);
  });
});

test('path tricks cannot change the upstream host', () =>
  withProxy({}, async (port) => {
    assert.equal((await call(port, '/fake@evil.com/x', { headers: { 'x-api-key': 'lly_good' } })).status, 404);
    assert.equal((await call(port, '/nope/x', { headers: { 'x-api-key': 'lly_good' } })).status, 404);
    await call(port, '/fake//evil.com/x', { headers: { 'x-api-key': 'lly_good' } });
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.url, '//evil.com/x'); // stayed on the real upstream, as a path
  }));

test('redirects are not followed (key cannot be forwarded to a third party)', () =>
  withProxy({}, async (port) => {
    const r = await call(port, '/fake/redirect', { headers: { 'x-api-key': 'lly_good' } });
    assert.equal(r.status, 302);
    assert.equal(otherHits, 0);
  }));

test('streams SSE incrementally instead of buffering', () =>
  withProxy({}, async (port) => {
    const t0 = Date.now();
    const stamps: number[] = [];
    await new Promise<void>((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path: '/fake/sse', headers: { 'x-api-key': 'lly_good' } }, (res) => {
        res.on('data', () => stamps.push(Date.now() - t0));
        res.on('end', resolve);
      });
      req.on('error', reject); req.end();
    });
    assert.ok(stamps.length >= 2, `expected multiple chunks, got ${stamps.length}`);
    assert.ok(stamps[stamps.length - 1]! - stamps[0]! >= 150, 'chunks should arrive apart');
  }));

test('rate limit returns 429, then the kill switch blocks the agent', () =>
  withProxy({ rpm: 2 }, async (port) => {
    const codes: number[] = [];
    const msgs: string[] = [];
    for (let i = 0; i < 8; i++) { const r = await call(port, '/fake/x', { headers: { 'x-api-key': 'lly_good' } }); codes.push(r.status); msgs.push(r.body); }
    assert.deepEqual(codes.slice(0, 3), [201, 201, 429]);
    assert.ok(msgs[7]!.includes('kill switch'));
  }));

test('logs record agent/provider/status but never keys, tokens or query strings', () =>
  withProxy({}, async (port, logs) => {
    await call(port, '/fake/v1/x?secret=hunter2', { headers: { 'x-api-key': 'lly_good' } });
    await new Promise((r) => setTimeout(r, 30));
    const text = JSON.stringify(logs);
    assert.ok(logs.length >= 1 && logs[0].agent === 'a1' && logs[0].provider === 'fake');
    for (const bad of [REAL, 'lly_good', 'hunter2']) assert.equal(text.includes(bad), false, bad);
  }));

test('agent scoped to specific providers gets 403 elsewhere, and nothing reaches upstream', () =>
  withProxy({}, async (port) => {
    assert.equal((await call(port, '/fake/x', { headers: { 'x-api-key': 'lly_scoped' } })).status, 403);
    assert.equal(seen.length, 0);
    assert.equal((await call(port, '/bearer/x', { headers: { authorization: 'Bearer lly_scoped' } })).status, 201);
  }));

test('provider ids that are object prototype names are not providers', () =>
  withProxy({}, async (port) => {
    for (const id of ['constructor', 'toString', '__proto__', 'hasOwnProperty'])
      assert.equal((await call(port, `/${id}/x`, { headers: { 'x-api-key': 'lly_good' } })).status, 404, id);
  }));

test('providers can be resolved dynamically (function source)', () =>
  withProxy({ providers: (id) => (id === 'dyn' ? providers().fake : undefined) }, async (port) => {
    assert.equal((await call(port, '/dyn/x', { headers: { 'x-api-key': 'lly_good' } })).status, 201);
    assert.equal((await call(port, '/fake/x', { headers: { 'x-api-key': 'lly_good' } })).status, 404);
  }));

test('SSRF: private/loopback upstreams are refused unless the provider opts in with allowLocal', async () => {
  const p = providers().fake;
  // literal loopback IP, no opt-in -> refused before any connection
  await withProxy({ providers: { fake: { ...p, allowLocal: false } } }, async (port) => {
    assert.equal((await call(port, '/fake/x', { headers: { 'x-api-key': 'lly_good' } })).status, 403);
    assert.equal(seen.length, 0);
  });
  // hostname that resolves to loopback, no opt-in -> blocked at connect time
  await withProxy({ providers: { fake: { ...p, upstream: `http://localhost:${upPort}`, allowLocal: false } } }, async (port) => {
    assert.equal((await call(port, '/fake/x', { headers: { 'x-api-key': 'lly_good' } })).status, 502);
    assert.equal(seen.length, 0);
  });
  // explicit opt-in works
  await withProxy({ providers: { fake: { ...p, upstream: `http://localhost:${upPort}`, allowLocal: true } } }, async (port) => {
    assert.equal((await call(port, '/fake/x', { headers: { 'x-api-key': 'lly_good' } })).status, 201);
  });
});
