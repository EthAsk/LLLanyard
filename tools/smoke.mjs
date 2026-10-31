#!/usr/bin/env node
// Real-machine smoke test: run on Linux, macOS and Windows after `npm install && npm run build`.
//   node tools/smoke.mjs              # uses a throwaway encrypted vault; touches nothing of yours
//   node tools/smoke.mjs --keychain   # also does one add/remove cycle in your REAL OS keychain (uses a fake key, cleaned up)
// Prints PASS/FAIL per check and a report you can paste into an issue (it never contains secrets).
import { spawn, spawnSync } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'packages/cli/dist/index.js');
const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail && !ok ? `\n      ${detail}` : ''}`); };
const home = mkdtempSync(path.join(os.tmpdir(), 'lly-smoke-'));
const pass = path.join(home, 'pp'); writeFileSync(pass, 'smoke-test-passphrase-long-enough\n', { mode: 0o600 });
const port = await new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const env = { ...process.env, HOME: home, USERPROFILE: home, LLLANYARD_BACKEND: 'file', LLLANYARD_VAULT_PASSPHRASE_FILE: pass, LLLANYARD_PORT: String(port) };
const run = (args, input, e = env) => spawnSync(process.execPath, [cli, ...args], { env: e, input, encoding: 'utf8', timeout: 60_000 });
const get = (p, headers = {}, method = 'GET', host = '127.0.0.1', prt = port) => new Promise((res) => {
  const r = http.request({ host: '127.0.0.1', port: prt, path: p, method, headers: { host: `${host}:${prt}`, ...headers } }, (x) => { let b = ''; x.on('data', (c) => (b += c)); x.on('end', () => res({ status: x.statusCode, body: b })); });
  r.on('error', () => res({ status: 0, body: '' })); r.end();
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const children = [];
const stop = () => { for (const c of children) try { c.kill(); } catch {} };
process.on('exit', stop);

console.log(`LLLanyard smoke test on ${process.platform} ${os.arch()}, Node ${process.version}\n`);
check('Node 20 or newer', Number(process.versions.node.split('.')[0]) >= 20);
check('CLI is built (run: npm install && npm run build)', spawnSync(process.execPath, ['-e', `require('fs').accessSync(${JSON.stringify(cli)})`]).status === 0);

const FAKE = 'sk-smoke-' + 'A'.repeat(32);
let r;
// echo provider pointing at a local server that reports what it received
const upstream = http.createServer((q, s) => s.end(JSON.stringify({ auth: q.headers.authorization ?? null })));
await new Promise((ok) => upstream.listen(0, '127.0.0.1', ok));
const upPort = upstream.address().port;
r = run(['provider', 'add', 'echo', '--upstream', `http://127.0.0.1:${upPort}`, '--allow-local', '--auth', 'bearer']);
check('provider add', r.status === 0, r.stderr);
r = run(['add', 'echo', '--stdin'], FAKE + '\n');
check('store a key in the encrypted vault', r.status === 0 && !r.stdout.includes(FAKE), r.stderr);
r = run(['list']);
check('list shows the key without revealing it', r.status === 0 && r.stdout.includes('echo') && !r.stdout.includes(FAKE), r.stdout + r.stderr);
r = run(['agent', 'create', 'smoke-agent', '--providers', 'echo']);
const token = /lly_[A-Za-z0-9_-]+/.exec(r.stdout)?.[0];
check('create an agent token', Boolean(token), r.stderr);

const proxy = spawn(process.execPath, [cli, 'start', '--port', String(port)], { env, stdio: 'ignore' }); children.push(proxy);
await sleep(2500);
let g = await get('/echo/v1/x', { authorization: `Bearer ${token}` });
check('proxy injects the real key (upstream saw it, agent never held it)', g.status === 200 && g.body.includes(FAKE), `${g.status} ${g.body}`);
g = await get('/echo/v1/x', { authorization: 'Bearer lly_wrong' });
check('bad token is rejected (401)', g.status === 401, String(g.status));
g = await get('/echo/v1/x', { authorization: `Bearer ${token}` }, 'GET', 'evil.example');
check('wrong Host header is rejected (DNS-rebinding defence)', g.status === 403, String(g.status));
await sleep(500);
r = run(['usage', '--since', '1h']);
check('usage report counts the requests', r.status === 0 && /Requests\s+[1-9]/.test(r.stdout), r.stdout.slice(0, 200));
proxy.kill();

r = run(['mcp'], '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"key_status"}}\n');
check('MCP server answers and never shows the key', r.status === 0 && r.stdout.includes('"serverInfo"') && !r.stdout.includes(FAKE) && !r.stdout.includes('AAAA'), r.stderr);

const ui = spawn(process.execPath, [cli, 'ui', '--no-open', '--print-url', '--port', '0'], { env, stdio: ['ignore', 'pipe', 'ignore'] }); children.push(ui);
const url = await new Promise((ok) => { let b = ''; ui.stdout.on('data', (d) => { b += d; if (b.includes('\n')) ok(b.trim()); }); setTimeout(() => ok(''), 8000); });
const m = /^http:\/\/127\.0\.0\.1:(\d+)\/#s=([\w-]+)$/.exec(url);
check('UI starts on loopback and prints a private link', Boolean(m), url.replace(/#s=.*/, '#s=<hidden>'));
if (m) {
  const up = Number(m[1]);
  const a = await get('/api/state', { 'x-lly-session': m[2] }, 'GET', '127.0.0.1', up);
  const b = await get('/api/state', {}, 'GET', '127.0.0.1', up);
  check('UI API works with the session secret and is closed without it', a.status === 200 && b.status === 401 && !a.body.includes(FAKE), `${a.status}/${b.status}`);
}
ui.kill(); upstream.close();

r = run(['license', 'status']);
check('license status (free tier by default)', r.status === 0 && /Tier: free/.test(r.stdout), r.stdout + r.stderr);

// Sandbox availability (informational: not every machine has one)
const sb = spawnSync(process.execPath, ['-e', `import(${JSON.stringify('file://' + path.join(root, 'packages/core/dist/index.js'))}).then(m=>{const t=m.sandboxSelfTest();console.log(JSON.stringify(t))})`], { encoding: 'utf8' });
let sandbox = { ok: false, reason: 'could not run' }; try { sandbox = JSON.parse(sb.stdout.trim()); } catch {}
console.log(`INFO  tool sandbox: ${sandbox.ok ? `available (${sandbox.kind})` : `not available: ${sandbox.reason}`}`);

if (process.argv.includes('--keychain')) {
  const realEnv = { ...process.env, LLLANYARD_BACKEND: 'keychain' };
  delete realEnv.LLLANYARD_VAULT_PASSPHRASE_FILE;
  const d = run(['doctor'], undefined, realEnv);
  check('REAL OS keychain: write/read/delete cycle', d.status === 0 && /OS keychain is usable/.test(d.stdout), (d.stdout + d.stderr).slice(0, 300));
}

rmSync(home, { recursive: true, force: true });
const failed = results.filter((x) => !x.ok);
console.log(`\n${failed.length ? `${failed.length} FAILED` : 'ALL PASSED'} (${results.length} checks)`);
console.log('\n--- paste this report in an issue ---');
console.log(JSON.stringify({ platform: process.platform, arch: os.arch(), node: process.version, sandbox: sandbox.ok ? sandbox.kind : sandbox.reason, failed: failed.map((x) => x.name) }));
stop();
process.exit(failed.length ? 1 : 0);
