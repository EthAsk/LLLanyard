import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createUsageLog, parseSince, parseUsage, readUsage, renderDashboard, summarize } from '../src/index.js';

const T = (h: number) => new Date(Date.UTC(2026, 9, 27, h)).toISOString();
const recs = [
  { ts: T(1), agent: 'cursor', client: 'acme', provider: 'openai', status: 200, ms: 100 },
  { ts: T(2), agent: 'cursor', client: 'acme', provider: 'openai', status: 200, ms: 300 },
  { ts: T(3), agent: 'claude', client: 'default', provider: 'anthropic', status: 502, ms: 50 },
  { ts: T(4), agent: 'claude', provider: 'anthropic', status: 429, killed: true },
  { ts: T(5), agent: 'bot', provider: 'stripe', status: 403, reason: 'provider-not-allowed' },
  { ts: T(6), event: 'egress', tool: 'gh', host: 'evil.com', decision: 'deny' },
  { ts: T(7), event: 'egress', tool: 'gh', host: 'evil.com', decision: 'deny' },
];

test('summarize: totals, grouping, percentiles, egress denials', () => {
  const s = summarize(recs, 0, Date.now());
  assert.equal(s.requests, 5); assert.equal(s.errors, 1); assert.equal(s.rateLimited, 1); assert.equal(s.killSwitch, 1); assert.equal(s.denied, 1);
  assert.equal(s.byProvider[0]!.name, 'openai'); assert.equal(s.byProvider[0]!.p95, 300);
  assert.equal(s.byClient.find((r) => r.name === '(unknown)')!.requests, 2);
  assert.deepEqual(s.egressDenied, [{ host: 'evil.com', tool: 'gh', count: 2 }]);
  assert.equal(s.perDay.length, 1);
});

test('parseUsage: ignores damaged lines and honours the time window', () => {
  const text = recs.map((r) => JSON.stringify(r)).join('\n') + '\nnot json\n{broken\n';
  assert.equal(parseUsage(text).length, 7);
  assert.equal(parseUsage(text, Date.parse(T(4))).length, 4);
});

test('usage log: private permissions, rotation, readable back', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-use-'));
  const f = path.join(dir, 'sub', 'usage.jsonl');
  const log = createUsageLog(f, 300);
  for (let i = 0; i < 20; i++) log.write({ ts: new Date().toISOString(), provider: 'openai', status: 200, i });
  if (process.platform !== 'win32') assert.equal(statSync(f).mode & 0o077, 0, 'file is owner-only');
  assert.ok(existsSync(f + '.1'), 'rotated');
  assert.ok(readFileSync(f, 'utf8').length <= 400);
  assert.ok(readUsage(f).length >= 2);
});

test('dashboard: escapes hostile names, no scripts, strict CSP', () => {
  const html = renderDashboard(summarize([{ ts: T(1), agent: '<img src=x onerror=alert(1)>', provider: 'x"><script>', status: 200, ms: 1 }], 0));
  assert.ok(!html.includes('<img src=x') && !html.includes('<script'));
  assert.match(html, /default-src 'none'/);
  assert.match(html, /&lt;img src=x/);
});

test('parseSince', () => {
  assert.equal(parseSince('24h', 1e12), 1e12 - 86400_000);
  assert.equal(parseSince('7d', 1e12), 1e12 - 7 * 86400_000);
  assert.throws(() => parseSince('soon'));
});
