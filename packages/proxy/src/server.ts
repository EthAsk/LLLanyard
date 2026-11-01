import http from 'node:http';
import https from 'node:https';
import type { AgentIdentity, DeviceIdentity, SecureStore } from '@lllanyard/core'; // type-only: no runtime dependency
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
  'transfer-encoding', 'upgrade', 'expect', 'authorization', 'x-api-key', 'cookie', 'x-lllanyard-machine',
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
  /**
   * Team members: where a request goes when this proxy holds no key for it (the team's shared proxy), and this
   * member's token there. Personal keys always win and never leave this machine.
   */
  team?: () => { url: string; token: string; ca?: string } | null;
  /**
   * Pro: paired devices. A device token works only with the machine ID it was paired with (x-lllanyard-machine).
   * pair() uses a one-time code from `lllanyard device add`.
   */
  devices?: {
    verify: (token: string, machine: string | undefined) => DeviceIdentity | 'wrong-machine' | null;
    pair: (code: string, machine: string) => { name: string; token: string };
  };
  /**
   * For paired devices: the variable names of this computer's keys (GITHUB_TOKEN → github or github:label), shown in
   * whoami, and the ones a device may fetch for one run (POST /_lllanyard/keys).
   */
  keyVars?: () => Record<string, string>;
  /** Pro: agent tokens work from this computer only; other computers must be paired devices. */
  agentsLoopbackOnly?: boolean;
  isLocalAddress?: (ip: string) => boolean; // test hook (default: loopback addresses)
}

const isLoopbackAddr = (ip: string) => ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';

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

  /** No personal key: pass the request to the team server, as this member, with the caller's own token removed. */
  const forward = (req: http.IncomingMessage, res: http.ServerResponse, team: { url: string; token: string; ca?: string },
    provider: string, rest: string, agent: AgentIdentity, ip: string, started: number) => {
    let target: URL;
    try { target = new URL(team.url + '/' + provider + rest); } catch { return send(res, 400, 'Bad request path'); }
    if (target.origin !== new URL(team.url).origin || target.protocol !== 'https:') return send(res, 400, 'Bad request path');

    const headers: http.OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(req.headers)) if (!DROP_REQ.has(k) && v !== undefined) headers[k] = v;
    headers.authorization = `Bearer ${team.token}`;

    let up: http.ClientRequest | undefined;
    res.on('close', () => {
      log({ ts: new Date().toISOString(), agent: agent.name, client: agent.client, ip, provider, via: 'team', method: req.method,
            path: target.pathname, status: res.statusCode, ms: now() - started });
      up?.destroy();
    });
    // The team server is usually on the local network or a VPN, so private addresses are expected here.
    try {
      up = https.request(target, { method: req.method, headers, timeout: 300_000, minVersion: 'TLSv1.2', ...(team.ca ? { ca: team.ca } : {}) }, (ures) => {
        const rh: http.OutgoingHttpHeaders = {};
        for (const [k, v] of Object.entries(ures.headers)) if (!DROP_RES.has(k) && v !== undefined) rh[k] = v;
        res.writeHead(ures.statusCode ?? 502, rh);
        ures.pipe(res);
      });
    } catch { return send(res, 502, 'Team server request failed'); }
    up.on('timeout', () => up.destroy(new Error('team server timeout')));
    up.on('error', () => send(res, 502, 'Team server unreachable'));
    req.pipe(up);
  };

  const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const started = now();
    const ip = req.socket.remoteAddress ?? 'unknown';

    // Defence against DNS rebinding and drive-by web pages: only loopback Host values, no browser Origin.
    const port = req.socket.localPort;
    const host = String(req.headers.host ?? '').toLowerCase();
    if (![`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`].includes(host) && !extraHosts.has(host) && !extraHosts.has(host.replace(/:\d+$/, ''))) return send(res, 403, 'Forbidden host');
    if (req.headers.origin && !deps.allowOrigin) return send(res, 403, 'Browser-origin requests are not allowed');

    // Pairing a device: a one-time code (from `lllanyard device add` here) and the device's machine ID, for a token.
    if (req.url === '/_lllanyard/pair') {
      if (!deps.devices) return send(res, 404, 'Not found');
      if (req.method !== 'POST') return send(res, 405, 'Use POST');
      if (guard.blocked(ip)) { res.setHeader('retry-after', '900'); return send(res, 429, 'Too many failed attempts'); }
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (d: string) => { body += d; if (body.length > 4096) req.destroy(); });
      req.on('end', () => {
        try {
          const { code, machine } = JSON.parse(body) as { code?: unknown; machine?: unknown };
          if (typeof code !== 'string' || typeof machine !== 'string') throw new Error('Send a pairing code and machine ID.');
          const r = deps.devices!.pair(code, machine);
          guard.ok(ip);
          log({ ts: new Date().toISOString(), event: 'device-paired', device: r.name, ip });
          const out = JSON.stringify(r);
          res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(out), 'cache-control': 'no-store' });
          res.end(out);
        } catch (e) {
          guard.fail(ip);
          log({ ts: new Date().toISOString(), ip, status: 400, reason: 'pair-failed' });
          send(res, 400, (e as Error).message);
        }
      });
      return;
    }

    // A token check with no key involved: lets a member's LLLanyard test its link to this server.
    const whoami = req.url === '/_lllanyard/whoami';
    const keysReq = req.url === '/_lllanyard/keys';
    const m = whoami || keysReq ? null : /^\/([A-Za-z0-9-]+)(.*)$/s.exec(req.url ?? '/');
    if (!m && !whoami && !keysReq) return send(res, 404, 'Not found');
    const provider = m ? m[1]!.toLowerCase() : '';
    let rest = m?.[2] ?? '';
    const def = m ? lookupProvider(provider) : undefined;
    const team = deps.team?.() ?? null;
    if (m && !def && !team) return send(res, 404, 'Unknown provider');
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
    const machine = typeof req.headers['x-lllanyard-machine'] === 'string' ? req.headers['x-lllanyard-machine'] : undefined;
    const dev = token && deps.devices ? deps.devices.verify(token, machine) : null;
    if (dev === 'wrong-machine') {
      guard.fail(ip);
      log({ ts: new Date().toISOString(), ip, provider, status: 401, reason: 'device-wrong-machine' });
      return send(res, 401, 'This device token belongs to a different computer. Pair this one: lllanyard device join');
    }
    const agent = dev ?? (token ? deps.verify(token) : null);
    if (!agent) {
      guard.fail(ip);
      log({ ts: new Date().toISOString(), ip, provider, status: 401, reason: 'bad-token' });
      return send(res, 401, 'Invalid or missing agent token');
    }
    if (!dev && deps.agentsLoopbackOnly && !(deps.isLocalAddress ?? isLoopbackAddr)(ip)) {
      log({ ts: new Date().toISOString(), agent: agent.name, ip, provider, status: 403, reason: 'agent-not-local' });
      return send(res, 403, 'Agent tokens work on this computer only. To use your keys from another computer, pair it: lllanyard device add <name> (Pro allows 3 devices)');
    }
    guard.ok(ip);
    if (whoami) {
      const vars = dev && deps.keyVars ? deps.keyVars() : undefined;
      const body = JSON.stringify({ name: agent.name, client: agent.client, providers: agent.providers ?? null, ...(dev ? { vars: vars ?? {}, keys: dev.keys } : {}) });
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
      return res.end(body);
    }

    // exec --remote on a paired device: the keys for one run, by variable name. Nothing else can ask for a key.
    if (keysReq) {
      if (!dev) return send(res, 403, 'Only a paired device can fetch keys');
      if (!dev.keys) return send(res, 403, 'This device was paired to use the proxy only (device add --no-keys), so it cannot fetch keys');
      if (req.method !== 'POST') return send(res, 405, 'Use POST');
      if (limiter.hit(agent.name) !== 'ok') { res.setHeader('retry-after', '60'); return send(res, 429, 'Rate limit exceeded'); }
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (d: string) => { body += d; if (body.length > 16_384) req.destroy(); });
      req.on('end', () => {
        let vars: unknown, tool: unknown;
        try { ({ vars, tool } = JSON.parse(body)); } catch { return send(res, 400, 'Bad request'); }
        if (!Array.isArray(vars) || vars.length > 50 || !vars.every((v) => typeof v === 'string')) return send(res, 400, 'Send the variable names you need');
        const map = deps.keyVars?.() ?? {};
        const keys: Record<string, string> = {};
        try {
          for (const v of vars as string[]) {
            const ref = Object.prototype.hasOwnProperty.call(map, v) ? map[v] : undefined;
            if (!ref) continue;
            const i = ref.indexOf(':');
            const k = deps.store.get(i < 0 ? ref : ref.slice(0, i), i < 0 ? 'default' : ref.slice(i + 1));
            if (k) keys[v] = k;
          }
        } catch { return send(res, 503, 'Key store unavailable'); }
        log({ ts: new Date().toISOString(), event: 'device-keys', agent: agent.name, ip, keys: Object.keys(keys), tool: typeof tool === 'string' ? tool.slice(0, 200) : undefined });
        const out = JSON.stringify({ keys });
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(out), 'cache-control': 'no-store' });
        res.end(out);
      });
      return;
    }

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

    let key: string | null = null;
    if (def) {
      try { key = keyFor(provider, agent.client); } catch { if (!team) return send(res, 503, 'Key store unavailable'); }
    }
    if (!key) {
      if (team) return forward(req, res, team, provider, rest, agent, ip, started);
      return send(res, 503, `No ${provider} key stored for client "${agent.client}"`);
    }
    if (!def) return send(res, 404, 'Unknown provider');

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
