import http from 'node:http';
import https from 'node:https';
import type { AgentIdentity, SecureStore } from '@lllanyard/core'; // type-only: no runtime dependency
import { isIP } from 'node:net';
import { isPublicAddress, safeLookup } from './netguard.js';
import { AuthGuard, RateLimiter } from './ratelimit.js';

export interface ProviderDef {
  upstream: string;
  inject(headers: http.OutgoingHttpHeaders, key: string): void;
  allowLocal?: boolean; // permit a loopback/private upstream (local model servers); default: public hosts only
}

export type ProviderSource = Record<string, ProviderDef> | ((id: string) => ProviderDef | undefined);

const DROP_REQ = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authorization', 'proxy-connection', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'expect', 'authorization', 'x-api-key', 'cookie',
]);
const DROP_RES = new Set(['connection', 'keep-alive', 'transfer-encoding', 'proxy-authenticate', 'upgrade', 'set-cookie']);

export interface ProxyDeps {
  store: Pick<SecureStore, 'get'>;
  verify: (token: string) => AgentIdentity | null;
  providers: ProviderSource;
  rpm?: number; // requests/minute per agent (default 120)
  allowOrigin?: boolean; // allow requests carrying a browser Origin header (default false)
  keyCacheMs?: number; // how long a key stays in proxy memory (default 30s)
  log?: (rec: Record<string, unknown>) => void;
  now?: () => number;
  allowedHosts?: string[]; // extra Host names accepted (shared/remote mode); loopback names are always accepted
  tls?: { cert: string | Buffer; key: string | Buffer }; // serve HTTPS (required by the CLI for non-loopback binds)
  authGuard?: AuthGuard;
}

export function createProxy(deps: ProxyDeps): http.Server | https.Server {
  const lookupProvider = (id: string): ProviderDef | undefined => {
    const src = deps.providers;
    if (typeof src === 'function') return src(id);
    return Object.prototype.hasOwnProperty.call(src, id) ? src[id] : undefined; // "constructor" etc. are not providers
  };
  const now = deps.now ?? Date.now;
  const limiter = new RateLimiter(deps.rpm ?? 120, { now });
  const log = deps.log ?? ((r) => process.stdout.write(JSON.stringify(r) + '\n'));
  const cache = new Map<string, { key: string; exp: number }>();
  const guard = deps.authGuard ?? new AuthGuard(10, 10 * 60_000, 15 * 60_000, now);
  const extraHosts = new Set((deps.allowedHosts ?? []).map((h) => h.toLowerCase()));

  const keyFor = (provider: string, client: string): string | null => {
    const ck = `${provider}:${client}`;
    const hit = cache.get(ck);
    if (hit && hit.exp > now()) return hit.key;
    const key = deps.store.get(provider, client);
    if (key) cache.set(ck, { key, exp: now() + (deps.keyCacheMs ?? 30_000) });
    else cache.delete(ck);
    return key;
  };

  const send = (res: http.ServerResponse, code: number, msg: string) => {
    if (res.headersSent) { res.destroy(); return; }
    const body = JSON.stringify({ error: msg });
    res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
    res.end(body);
  };

  const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const started = now();
    const ip = req.socket.remoteAddress ?? 'unknown';

    // Defence against DNS rebinding and drive-by web pages: only loopback Host values, no browser Origin.
    const port = req.socket.localPort;
    const host = String(req.headers.host ?? '').toLowerCase();
    if (![`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`].includes(host) && !extraHosts.has(host) && !extraHosts.has(host.replace(/:\d+$/, ''))) return send(res, 403, 'Forbidden host');
    if (req.headers.origin && !deps.allowOrigin) return send(res, 403, 'Browser-origin requests are not allowed');

    const m = /^\/([A-Za-z0-9-]+)(.*)$/s.exec(req.url ?? '/');
    if (!m) return send(res, 404, 'Not found');
    const provider = m[1]!.toLowerCase();
    let rest = m[2] ?? '';
    const def = lookupProvider(provider);
    if (!def) return send(res, 404, 'Unknown provider');
    if (rest === '') rest = '/';
    else if (rest.startsWith('?')) rest = '/' + rest;
    else if (!rest.startsWith('/')) return send(res, 404, 'Not found'); // blocks "/openai@evil.com"

    // Agent authentication: the placeholder token arrives as the agent's "API key".
    const bearer = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization ?? ''))?.[1];
    const xkey = typeof req.headers['x-api-key'] === 'string' ? req.headers['x-api-key'] : undefined;
    const token = bearer ?? xkey;
    if (guard.blocked(ip)) {
      log({ ts: new Date().toISOString(), ip, provider, status: 429, reason: 'auth-lockout' });
      res.setHeader('retry-after', '900');
      return send(res, 429, 'Too many failed attempts');
    }
    const agent = token ? deps.verify(token) : null;
    if (!agent) {
      guard.fail(ip);
      log({ ts: new Date().toISOString(), ip, provider, status: 401, reason: 'bad-token' });
      return send(res, 401, 'Invalid or missing agent token');
    }
    guard.ok(ip);

    // Least privilege: an agent created with --providers may only reach those.
    if (agent.providers && !agent.providers.includes(provider)) {
      log({ ts: new Date().toISOString(), agent: agent.name, provider, status: 403, reason: 'provider-not-allowed' });
      return send(res, 403, 'This agent is not allowed to use that provider');
    }

    const verdict = limiter.hit(agent.name);
    if (verdict !== 'ok') {
      log({ ts: new Date().toISOString(), agent: agent.name, provider, status: 429, killed: verdict === 'killed' });
      res.setHeader('retry-after', '60');
      return send(res, 429, verdict === 'killed' ? 'Agent blocked by kill switch' : 'Rate limit exceeded');
    }

    let key: string | null;
    try { key = keyFor(provider, agent.client); } catch { return send(res, 503, 'Key store unavailable'); }
    if (!key) return send(res, 503, `No ${provider} key stored for client "${agent.client}"`);

    // Never let the request path change the destination host.
    let target: URL;
    try { target = new URL(def.upstream + rest); } catch { return send(res, 400, 'Bad request path'); }
    if (target.origin !== new URL(def.upstream).origin) return send(res, 400, 'Bad request path');

    // SSRF guard: literal private/loopback IPs are refused here; hostnames are checked at connect time (safeLookup).
    const hostname = target.hostname.replace(/^\[|\]$/g, '');
    if (!def.allowLocal && isIP(hostname) && !isPublicAddress(hostname)) return send(res, 403, 'Upstream address not allowed');

    const headers: http.OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(req.headers)) if (!DROP_REQ.has(k) && v !== undefined) headers[k] = v;
    def.inject(headers, key);

    let up: http.ClientRequest | undefined;
    res.on('close', () => {
      log({ ts: new Date().toISOString(), agent: agent.name, client: agent.client, ip, provider, method: req.method,
            path: target.pathname, status: res.statusCode, ms: now() - started }); // no query string, no bodies
      up?.destroy();
    });

    // Redirects are never followed, so the key can't be forwarded to a third party.
    const lib = target.protocol === 'https:' ? https : http;
    try {
      up = lib.request(target, { method: req.method, headers, timeout: 300_000, ...(def.allowLocal ? {} : { lookup: safeLookup }) }, (ures) => {
        const rh: http.OutgoingHttpHeaders = {};
        for (const [k, v] of Object.entries(ures.headers)) if (!DROP_RES.has(k) && v !== undefined) rh[k] = v;
        res.writeHead(ures.statusCode ?? 502, rh);
        ures.pipe(res); // streams SSE untouched
      });
    } catch { return send(res, 502, 'Upstream request failed'); }
    up.on('timeout', () => up.destroy(new Error('upstream timeout')));
    up.on('error', () => send(res, 502, 'Upstream request failed'));
    req.pipe(up);
  };
  return deps.tls ? https.createServer({ ...deps.tls, minVersion: 'TLSv1.2' }, handler) : http.createServer(handler);
}
