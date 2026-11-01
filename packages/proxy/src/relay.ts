import http from 'node:http';
import https from 'node:https';
import { timingSafeEqual } from 'node:crypto';
import type { AddressInfo } from 'node:net';

/**
 * Runs on a paired device (no API keys here). Tools on this device talk to the relay on 127.0.0.1 with a local
 * token; the relay passes each request to the main computer's proxy with this device's token and machine ID, and
 * the main computer adds the real key. Neither the device token nor the machine ID reaches the tool.
 */
export interface RelayOptions {
  url: string; // the main computer's shared proxy, https://host:port
  deviceToken: string;
  machine: string;
  ca?: string;
  localToken: string; // what tools on this device use as their API key
  port?: number; // default: any free port
  log?: (rec: Record<string, unknown>) => void;
}

const DROP = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding',
  'upgrade', 'expect', 'authorization', 'x-api-key', 'cookie', 'x-lllanyard-machine',
]);
const DROP_RES = new Set(['connection', 'keep-alive', 'transfer-encoding', 'proxy-authenticate', 'upgrade', 'set-cookie']);

const same = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

export function startRelay(o: RelayOptions): Promise<{ port: number; base: string; close: () => void }> {
  const origin = new URL(o.url).origin;
  const send = (res: http.ServerResponse, code: number, msg: string) => {
    if (res.headersSent) { res.destroy(); return; }
    const body = JSON.stringify({ error: msg });
    res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
    res.end(body);
  };

  const server = http.createServer((req, res) => {
    const port = req.socket.localPort;
    const host = String(req.headers.host ?? '').toLowerCase();
    if (![`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`].includes(host)) return send(res, 403, 'Forbidden host');
    if (req.headers.origin) return send(res, 403, 'Browser-origin requests are not allowed');
    const bearer = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization ?? ''))?.[1];
    const xkey = typeof req.headers['x-api-key'] === 'string' ? req.headers['x-api-key'] : undefined;
    const token = bearer ?? xkey;
    if (!token || !same(token, o.localToken)) return send(res, 401, 'Invalid or missing token for the LLLanyard relay');
    if (!(req.url ?? '').startsWith('/') || (req.url ?? '').startsWith('//')) return send(res, 404, 'Not found');

    let target: URL;
    try { target = new URL(origin + req.url); } catch { return send(res, 400, 'Bad request path'); }
    if (target.origin !== origin) return send(res, 400, 'Bad request path');

    const headers: http.OutgoingHttpHeaders = {};
    for (const [k, v] of Object.entries(req.headers)) if (!DROP.has(k) && v !== undefined) headers[k] = v;
    headers.authorization = `Bearer ${o.deviceToken}`;
    headers['x-lllanyard-machine'] = o.machine;

    const started = Date.now();
    let up: http.ClientRequest | undefined;
    res.on('close', () => { o.log?.({ ts: new Date().toISOString(), via: 'relay', method: req.method, path: target.pathname, status: res.statusCode, ms: Date.now() - started }); up?.destroy(); });
    try {
      up = https.request(target, { method: req.method, headers, timeout: 300_000, minVersion: 'TLSv1.2', ...(o.ca ? { ca: o.ca } : {}) }, (ures) => {
        const rh: http.OutgoingHttpHeaders = {};
        for (const [k, v] of Object.entries(ures.headers)) if (!DROP_RES.has(k) && v !== undefined) rh[k] = v;
        res.writeHead(ures.statusCode ?? 502, rh);
        ures.pipe(res);
      });
    } catch { return send(res, 502, 'Could not reach your main computer'); }
    up.on('timeout', () => up.destroy(new Error('timeout')));
    up.on('error', (e) => send(res, 502, `Could not reach your main computer (${o.url}): ${e.message}`));
    req.pipe(up);
  });

  return new Promise((resolve, reject) => {
    server.once('error', (e: NodeJS.ErrnoException) => reject(new Error(e.code === 'EADDRINUSE' ? `Port ${o.port} is already in use (choose another with --port)` : e.message)));
    server.listen(o.port ?? 0, '127.0.0.1', () => {
      const port = (server.address() as AddressInfo).port;
      resolve({ port, base: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}

/**
 * Environment for a tool on a paired device: SDK base URLs pointing at the relay, and the relay's token as each
 * API key. `keyVars` are the main computer's variable names for its keys (e.g. GITHUB_TOKEN → github).
 */
export function relayEnv(base: string, localToken: string, keyVars: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {
    LLLANYARD_PROXY_URL: base,
    ANTHROPIC_BASE_URL: `${base}/anthropic`, ANTHROPIC_API_KEY: localToken,
    OPENAI_BASE_URL: `${base}/openai/v1`, OPENAI_API_KEY: localToken,
  };
  for (const [name, provider] of Object.entries(keyVars)) {
    env[name] = localToken;
    const id = provider.split(':')[0]!.toUpperCase().replace(/-/g, '_');
    env[`LLLANYARD_${id}_URL`] = `${base}/${provider.split(':')[0]}`;
  }
  return env;
}
