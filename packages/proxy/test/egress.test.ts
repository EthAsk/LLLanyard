import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { hostAllowed, startEgressProxy } from '../src/egress.js';

test('hostAllowed: exact and wildcard rules', () => {
  assert.equal(hostAllowed('api.github.com', ['api.github.com']), true);
  assert.equal(hostAllowed('API.GitHub.com.', ['api.github.com']), true);
  assert.equal(hostAllowed('evil.com', ['api.github.com']), false);
  assert.equal(hostAllowed('api.github.com.evil.com', ['api.github.com']), false);
  assert.equal(hostAllowed('x.example.com', ['*.example.com']), true);
  assert.equal(hostAllowed('a.b.example.com', ['*.example.com']), true);
  assert.equal(hostAllowed('example.com', ['*.example.com']), false);
  assert.equal(hostAllowed('badexample.com', ['*.example.com']), false);
});

// Test double for DNS: pretend allowed.example is a public host, but connect to our local echo server.
const fakeLookup = ((_h: string, _o: any, cb: any) => cb(null, [{ address: '127.0.0.1', family: 4 }])) as any;

async function setup(over: Record<string, unknown> = {}) {
  const echo = net.createServer((s) => s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))));
  await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r));
  const echoPort = (echo.address() as net.AddressInfo).port;
  const logs: any[] = [];
  const proxy = await startEgressProxy({ allow: ['allowed.example', '*.ok.example'], ports: [echoPort], log: (r) => logs.push(r), label: 't', lookup: fakeLookup, ...over });
  const auth = 'Basic ' + Buffer.from('lly:' + new URL(proxy.env.HTTPS_PROXY!).password).toString('base64');
  const connect = (target: string, a: string | null = auth) => new Promise<{ status: number; sock: net.Socket; rest: string }>((resolve, reject) => {
    const s = net.connect(proxy.port, '127.0.0.1');
    let buf = '';
    s.on('error', reject);
    s.on('data', (d) => {
      buf += d.toString();
      const i = buf.indexOf('\r\n\r\n');
      if (i >= 0) resolve({ status: Number(buf.slice(9, 12)), sock: s, rest: buf.slice(i + 4) });
    });
    s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${a ? `Proxy-Authorization: ${a}\r\n` : ''}\r\n`);
  });
  const done = () => { proxy.close(); echo.close(); };
  return { proxy, echoPort, logs, connect, done };
}

test('egress: allowed host tunnels data end to end', async () => {
  const t = await setup();
  try {
    const { status, sock } = await t.connect(`allowed.example:${t.echoPort}`);
    assert.equal(status, 200);
    const reply = await new Promise<string>((r) => { sock.once('data', (d) => r(d.toString())); sock.write('hi'); });
    assert.equal(reply, 'echo:hi');
    sock.destroy();
    assert.ok(t.logs.some((l) => l.decision === 'allow' && l.host === 'allowed.example'));
    // wildcard host too
    assert.equal((await t.connect(`sub.ok.example:${t.echoPort}`)).status, 200);
  } finally { t.done(); }
});

test('egress: unlisted hosts, other ports, IP literals and plain HTTP are refused and logged', async () => {
  const t = await setup();
  try {
    assert.equal((await t.connect(`evil.example:${t.echoPort}`)).status, 403);
    assert.equal((await t.connect('allowed.example:9999')).status, 403);
    assert.equal((await t.connect(`127.0.0.1:${t.echoPort}`)).status, 403);
    assert.equal((await t.connect(`[::1]:${t.echoPort}`)).status, 403);
    const reasons = t.logs.filter((l) => l.decision === 'deny').map((l) => l.reason);
    assert.deepEqual(reasons, ['host-not-allowed', 'port', 'ip-literal', 'ip-literal']);
    const status = await new Promise<number>((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: t.proxy.port, path: 'http://allowed.example/x', headers: { host: 'allowed.example' } }, (r) => { r.resume(); resolve(r.statusCode!); }).on('error', reject);
    });
    assert.equal(status, 403);
  } finally { t.done(); }
});

test('egress: needs the per-run password (other local programs cannot borrow the proxy)', async () => {
  const t = await setup();
  try {
    assert.equal((await t.connect(`allowed.example:${t.echoPort}`, null)).status, 407);
    assert.equal((await t.connect(`allowed.example:${t.echoPort}`, 'Basic ' + Buffer.from('lly:wrong').toString('base64'))).status, 407);
  } finally { t.done(); }
});

test('egress: allowlisted hostnames that resolve to private addresses are blocked (default lookup)', async () => {
  const t = await setup({ allow: ['localhost'], lookup: undefined });
  try {
    const r = await t.connect(`localhost:${t.echoPort}`);
    assert.equal(r.status, 502);
  } finally { t.done(); }
});

test('egress: environment points common proxy variables at the loopback proxy', async () => {
  const t = await setup();
  try {
    for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'https_proxy']) assert.match(t.proxy.env[k]!, /^http:\/\/lly:[\w-]+@127\.0\.0\.1:\d+$/);
    assert.equal(t.proxy.env.NO_PROXY, '');
  } finally { t.done(); }
});
