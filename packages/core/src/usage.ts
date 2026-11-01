import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Where the proxy keeps its request log (metadata only: no keys, bodies or query strings). */
export const usageLogPath = (home = os.homedir()) => path.join(home, '.lllanyard', 'usage.jsonl');

export interface UsageLog { write(rec: Record<string, unknown>): void }

/** Append-only JSONL with 0600 permissions in a 0700 directory; rotates to `.1` at maxBytes so it can't grow forever. */
export function createUsageLog(file = usageLogPath(), maxBytes = 10 * 1024 * 1024): UsageLog {
  let size = 0, ready = false;
  const init = () => {
    const dir = path.dirname(file);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    try { chmodSync(dir, 0o700); } catch { /* not ours to chmod on some filesystems */ }
    size = existsSync(file) ? statSync(file).size : 0;
    ready = true;
  };
  return {
    write(rec) {
      try {
        if (!ready) init();
        const line = JSON.stringify(rec) + '\n';
        if (size + line.length > maxBytes) { renameSync(file, file + '.1'); size = 0; }
        appendFileSync(file, line, { mode: 0o600 });
        size += line.length;
      } catch { /* logging must never break the proxy */ }
    },
  };
}

export interface UsageRecord { ts: string; agent?: string; client?: string; provider?: string; method?: string; path?: string; status?: number; ms?: number; reason?: string; killed?: boolean; event?: string; decision?: string; host?: string; tool?: string; keys?: string[] }

export function parseUsage(text: string, sinceMs = 0, untilMs = Infinity): UsageRecord[] {
  const out: UsageRecord[] = [];
  for (const line of text.split('\n')) {
    if (!line.startsWith('{')) continue;
    try {
      const r = JSON.parse(line) as UsageRecord;
      const t = Date.parse(r.ts);
      if (Number.isFinite(t) && t >= sinceMs && t <= untilMs) out.push(r);
    } catch { /* skip damaged lines */ }
  }
  return out;
}

export function readUsage(file = usageLogPath(), sinceMs = 0, untilMs = Infinity): UsageRecord[] {
  const parts: string[] = [];
  for (const f of [file + '.1', file]) { try { parts.push(readFileSync(f, 'utf8')); } catch { /* missing */ } }
  return parseUsage(parts.join('\n'), sinceMs, untilMs);
}

export interface Row { name: string; requests: number; errors: number; rateLimited: number; p50: number; p95: number }
export interface UsageSummary {
  sinceMs: number; untilMs: number;
  requests: number; errors: number; rateLimited: number; killSwitch: number; denied: number;
  byProvider: Row[]; byAgent: Row[]; byClient: Row[];
  perDay: { day: string; requests: number; errors: number }[];
  egressDenied: { host: string; tool: string; count: number }[];
  scriptRuns: { tool: string; count: number; last: string }[]; // commands started with `lllanyard exec`
  deviceKeys: { device: string; tool: string; keys: string[]; count: number; last: string }[]; // keys sent to paired devices (exec --remote)
}

const pct = (xs: number[], p: number) => { if (!xs.length) return 0; const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]!; };

export function summarize(records: UsageRecord[], sinceMs: number, untilMs = Date.now()): UsageSummary {
  const proxy = records.filter((r) => typeof r.status === 'number' && r.event === undefined);
  const group = (key: (r: UsageRecord) => string | undefined): Row[] => {
    const m = new Map<string, UsageRecord[]>();
    for (const r of proxy) { const k = key(r) ?? '(unknown)'; (m.get(k) ?? m.set(k, []).get(k)!).push(r); }
    return [...m].map(([name, rs]) => ({
      name, requests: rs.length, errors: rs.filter((r) => r.status! >= 500 || r.status === 502).length, rateLimited: rs.filter((r) => r.status === 429).length,
      p50: pct(rs.filter((r) => r.ms !== undefined).map((r) => r.ms!), 50), p95: pct(rs.filter((r) => r.ms !== undefined).map((r) => r.ms!), 95),
    })).sort((a, b) => b.requests - a.requests);
  };
  const days = new Map<string, { requests: number; errors: number }>();
  for (const r of proxy) {
    const d = r.ts.slice(0, 10);
    const e = days.get(d) ?? days.set(d, { requests: 0, errors: 0 }).get(d)!;
    e.requests++; if (r.status! >= 500) e.errors++;
  }
  const eg = new Map<string, { host: string; tool: string; count: number }>();
  for (const r of records) if (r.event === 'egress' && r.decision === 'deny') {
    const k = `${r.tool}\0${r.host}`;
    (eg.get(k) ?? eg.set(k, { host: String(r.host), tool: String(r.tool ?? '?'), count: 0 }).get(k)!).count++;
  }
  return {
    sinceMs, untilMs, requests: proxy.length,
    errors: proxy.filter((r) => r.status! >= 500).length,
    rateLimited: proxy.filter((r) => r.status === 429).length,
    killSwitch: proxy.filter((r) => r.killed).length,
    denied: proxy.filter((r) => r.status === 403).length,
    byProvider: group((r) => r.provider), byAgent: group((r) => r.agent), byClient: group((r) => r.client),
    perDay: [...days].map(([day, v]) => ({ day, ...v })).sort((a, b) => a.day.localeCompare(b.day)),
    egressDenied: [...eg.values()].sort((a, b) => b.count - a.count).slice(0, 20),
    scriptRuns: [...records.filter((r) => r.event === 'exec').reduce((m, r) => {
      const k = String(r.tool ?? '?'), e = m.get(k) ?? { tool: k, count: 0, last: r.ts };
      e.count++; if (r.ts > e.last) e.last = r.ts;
      return m.set(k, e);
    }, new Map<string, { tool: string; count: number; last: string }>()).values()].sort((a, b) => b.last.localeCompare(a.last)).slice(0, 20),
    deviceKeys: [...records.filter((r) => r.event === 'device-keys').reduce((m, r) => {
      const device = String(r.agent ?? '?').replace(/^device:/, ''), tool = String(r.tool ?? '?'), keys = Array.isArray(r.keys) ? r.keys.map(String) : [];
      const k = `${device}\0${tool}\0${keys.join(',')}`, e = m.get(k) ?? { device, tool, keys, count: 0, last: r.ts };
      e.count++; if (r.ts > e.last) e.last = r.ts;
      return m.set(k, e);
    }, new Map<string, { device: string; tool: string; keys: string[]; count: number; last: string }>()).values()].sort((a, b) => b.last.localeCompare(a.last)).slice(0, 20),
  };
}

export function parseSince(s: string, now = Date.now()): number {
  const m = /^(\d{1,4})([hd])$/.exec(s.trim());
  if (!m) throw new Error('Use --since like 24h, 7d or 30d.');
  return now - Number(m[1]) * (m[2] === 'h' ? 3600_000 : 86400_000);
}

const esc = (s: unknown) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** One self-contained page: no scripts, no external requests (CSP enforces it). All names are escaped. */
export function renderDashboard(s: UsageSummary, tier = 'pro'): string {
  const max = Math.max(1, ...s.perDay.map((d) => d.requests));
  const W = 560, H = 160, bw = s.perDay.length ? Math.max(4, Math.min(40, Math.floor((W - 20) / s.perDay.length) - 4)) : 20;
  const bars = s.perDay.map((d, i) => {
    const h = Math.round((d.requests / max) * (H - 30)), x = 10 + i * (bw + 4);
    return `<g><title>${esc(d.day)}: ${d.requests} requests, ${d.errors} errors</title><rect x="${x}" y="${H - 20 - h}" width="${bw}" height="${h}" rx="2" class="bar"/>` +
      (s.perDay.length <= 14 ? `<text x="${x + bw / 2}" y="${H - 6}" text-anchor="middle" class="ax">${esc(d.day.slice(5))}</text>` : '') + '</g>';
  }).join('');
  const table = (title: string, rows: Row[]) => `<h2>${esc(title)}</h2><table><thead><tr><th>Name</th><th>Requests</th><th>Errors</th><th>429s</th><th>p50 ms</th><th>p95 ms</th></tr></thead><tbody>${
    rows.length ? rows.map((r) => `<tr><td>${esc(r.name)}</td><td>${r.requests}</td><td>${r.errors}</td><td>${r.rateLimited}</td><td>${r.p50}</td><td>${r.p95}</td></tr>`).join('') : '<tr><td colspan="6">No data</td></tr>'}</tbody></table>`;
  const stat = (label: string, v: number, warn = false) => `<div class="stat${warn && v ? ' warn' : ''}"><div class="n">${v}</div><div class="l">${esc(label)}</div></div>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>LLLanyard usage</title><style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#e3e3e3;--card:#f7f7f7;--accent:#2f6fed;--warn:#c2410c}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#eee;--mut:#9a9a9a;--line:#2e2e2e;--card:#1d1d1d;--accent:#6b9bff;--warn:#fb923c}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:860px;margin-inline:auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}.sub{color:var(--mut);margin:0 0 20px}
.stats{display:flex;flex-wrap:wrap;gap:10px}.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:110px}
.stat .n{font-size:24px;font-weight:600}.stat .l{color:var(--mut);font-size:13px}.stat.warn .n{color:var(--warn)}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}th{color:var(--mut);font-weight:500}
td:not(:first-child),th:not(:first-child){text-align:right}.bar{fill:var(--accent)}.ax{fill:var(--mut);font-size:10px}svg{width:100%;height:auto;max-width:${W}px}
.scroll{overflow-x:auto}</style></head><body>
<h1>LLLanyard usage</h1>
<p class="sub">${esc(new Date(s.sinceMs).toISOString().slice(0, 10))} to ${esc(new Date(s.untilMs).toISOString().slice(0, 10))} · ${esc(tier)} · metadata only, no keys or request bodies</p>
<div class="stats">${stat('Requests', s.requests)}${stat('Server errors', s.errors, true)}${stat('Rate-limited (429)', s.rateLimited, true)}${stat('Kill-switch trips', s.killSwitch, true)}${stat('Blocked (403)', s.denied, true)}</div>
<h2>Requests per day</h2><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Requests per day">${bars || `<text x="10" y="40" class="ax">No requests in this period</text>`}</svg>
<div class="scroll">${table('By provider', s.byProvider)}${table('By agent', s.byAgent)}${table('By client', s.byClient)}</div>
<h2>Blocked egress attempts (sandboxed tools)</h2><table><thead><tr><th>Tool</th><th>Host</th><th>Attempts</th></tr></thead><tbody>${
  s.egressDenied.length ? s.egressDenied.map((e) => `<tr><td>${esc(e.tool)}</td><td>${esc(e.host)}</td><td>${e.count}</td></tr>`).join('') : '<tr><td colspan="3">None</td></tr>'}</tbody></table>
</body></html>`;
}
