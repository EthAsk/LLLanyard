import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { askLocalModel, assertLocalEndpoint, buildFacts, buildPrompt, ruleBasedReview, summarize, type KeyMeta } from '../src/index.js';

const NOW = new Date('2026-10-27T00:00:00Z');
const meta = (provider: string, label: string, ageDays: number, rotate = 90): KeyMeta => ({ id: `${provider}:${label}`, provider, label, rotateAfterDays: rotate, last4: 'WXYZ', createdAt: new Date(NOW.getTime() - ageDays * 86400_000).toISOString() });
const keys = [meta('openai', 'default', 120), meta('anthropic', 'default', 80), meta('github', 'acme', 10)];

test('facts and prompt contain metadata only (no last4, no key values)', () => {
  const f = buildFacts(keys, summarize([], 0), NOW);
  const p = buildPrompt(f, 'what now?');
  const all = JSON.stringify(f) + p.system + p.user;
  assert.ok(!all.includes('WXYZ'));
  assert.match(p.user, /"state":"overdue"/);
  assert.match(p.system, /untrusted/);
});

test('rule-based review prioritises overdue, then soon, and mentions the kill switch', () => {
  const f = buildFacts(keys, { ...summarize([], 0), killSwitch: 2, denied: 1 } as any, NOW);
  const r = ruleBasedReview(f);
  assert.match(r, /Rotate now \(overdue\): openai\/default \(30 days late\)/);
  assert.match(r, /Rotate soon: anthropic\/default \(in 10 days\)/);
  assert.match(r, /kill switch tripped 2/);
  assert.match(ruleBasedReview(buildFacts([], undefined, NOW)), /No keys/);
});

test('only loopback model endpoints are allowed', () => {
  for (const ok of ['http://127.0.0.1:11434', 'http://localhost:1234', 'http://[::1]:8080']) assert.doesNotThrow(() => assertLocalEndpoint(ok), ok);
  for (const bad of ['http://example.com', 'http://192.168.1.5:11434', 'https://api.openai.com', 'ftp://127.0.0.1', 'http://user:pw@127.0.0.1', 'nonsense', 'http://127.0.0.1.evil.com'])
    assert.throws(() => assertLocalEndpoint(bad), undefined, bad);
});

async function fakeModel(handler: (req: http.IncomingMessage, body: string, res: http.ServerResponse) => void) {
  const s = http.createServer((q, r) => { let b = ''; q.on('data', (c) => (b += c)); q.on('end', () => handler(q, b, r)); });
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, close: () => s.close() };
}

test('ollama and openai-style local models both work; request carries no secrets', async () => {
  let seen = '';
  const m = await fakeModel((q, b, r) => { seen = q.url + ' ' + b; r.setHeader('content-type', 'application/json'); r.end(JSON.stringify(q.url === '/api/chat' ? { message: { content: 'Rotate openai first.' } } : { choices: [{ message: { content: 'Rotate openai first (v1).' } }] })); });
  try {
    const f = buildFacts(keys, undefined, NOW);
    assert.equal(await askLocalModel({ endpoint: m.url, model: 'x', kind: 'ollama' }, f), 'Rotate openai first.');
    assert.equal(await askLocalModel({ endpoint: m.url, model: 'x', kind: 'openai' }, f), 'Rotate openai first (v1).');
    assert.ok(!seen.includes('WXYZ'));
  } finally { m.close(); }
});

test('model errors are explained, oversized or junk answers rejected', async () => {
  const f = buildFacts(keys, undefined, NOW);
  await assert.rejects(askLocalModel({ endpoint: 'http://127.0.0.1:9', model: 'x' }, f), /No local model server/);
  const nf = await fakeModel((_q, _b, r) => { r.statusCode = 404; r.end('{}'); });
  await assert.rejects(askLocalModel({ endpoint: nf.url, model: 'ghost' }, f), /installed/); nf.close();
  const junk = await fakeModel((_q, _b, r) => r.end('<html>')); await assert.rejects(askLocalModel({ endpoint: junk.url, model: 'x' }, f), /unreadable/); junk.close();
  const big = await fakeModel((_q, _b, r) => r.end('x'.repeat(300_000))); await assert.rejects(askLocalModel({ endpoint: big.url, model: 'x' }, f)); big.close();
  await assert.rejects(askLocalModel({ endpoint: 'http://example.com', model: 'x' }, f), /localhost/);
});
