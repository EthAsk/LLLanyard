import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { safeLookup } from './netguard.js';

export function hostAllowed(host: string, allow: string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return allow.some((a) => (a.startsWith('*.') ? h.length > a.length - 1 && h.endsWith(a.slice(1)) : h === a));
}

export interface EgressOptions {
  allow: string[]; // exact hosts or *.suffix wildcards
  ports?: number[]; // default [443]
  log?: (rec: Record<string, unknown>) => void;
  label?: string; // tool name, for logs
  lookup?: typeof safeLookup; // test hook; production always uses safeLookup (public addresses only)
  unixSocket?: string; // listen on this unix socket instead of TCP loopback (used by the sandbox bridge)
}

export interface EgressProxy {
  env: Record<string, string>; // proxy variables for TCP mode (empty in unix-socket mode: use proxyEnv with the bridge port)
  port: number; // 0 in unix-socket mode
  password: string; // per-run proxy password
  socketPath?: string;
  close: () => void;
}

// Same variables as core's proxyEnv(); duplicated so this package keeps no runtime dependency on core.
function proxyEnv(url: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) env[k] = url;
  env.NO_PROXY = ''; env.no_proxy = '';
  env.NODE_USE_ENV_PROXY = '1';
  return env;
}

const digest = (s: string) => createHash('sha256').update(s).digest();

/**
 * A tiny CONNECT-only forward proxy on loopback. A tool started with HTTPS_PROXY pointing here can only open
 * HTTPS tunnels to allowlisted hosts, and only to public IP addresses. It needs a per-run password so other local
 * programs can't borrow it.
 *
 * LIMIT: this is best-effort. Tools that honour proxy settings are constrained; a deliberately malicious tool can
 * ignore them. Hard enforcement needs an OS sandbox or container (see README).
 */
export function startEgressProxy(opts: EgressOptions): Promise<EgressProxy> {
  const ports = new Set(opts.ports ?? [443]);
  const log = opts.log ?? (() => {});
  const lookup = opts.lookup ?? safeLookup;
  const secret = randomBytes(18).toString('base64url');
  const wantAuth = digest('Basic ' + Buffer.from(`lly:${secret}`).toString('base64'));
  const sockets = new Set<net.Socket>();
  const note = (decision: 'allow' | 'deny', host: string, port: number | string, reason?: string) =>
    log({ ts: new Date().toISOString(), event: 'egress', tool: opts.label, decision, host, port, ...(reason ? { reason } : {}) });

  const server = http.createServer((req, res) => {
    note('deny', String(req.headers.host ?? ''), 80, 'plain-http');
    res.writeHead(403, { 'content-type': 'text/plain' });
    res.end('LLLanyard egress: only HTTPS tunnels to approved hosts are allowed.\n');
  });

  server.on('connect', (req, client: net.Socket, head: Buffer) => {
    sockets.add(client);
    client.once('close', () => sockets.delete(client));
    client.on('error', () => client.destroy());
    const reply = (code: number, msg: string) => { client.end(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\n\r\n`); };

    const given = digest(String(req.headers['proxy-authorization'] ?? ''));
    if (!timingSafeEqual(given, wantAuth)) return reply(407, 'Proxy Authentication Required');

    const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/.exec(req.url ?? '');
    if (!m) return reply(400, 'Bad Request');
    const host = (m[1] ?? m[2]!).toLowerCase();
    const port = Number(m[3]);
    if (net.isIP(host)) { note('deny', host, port, 'ip-literal'); return reply(403, 'Forbidden'); }
    if (!ports.has(port)) { note('deny', host, port, 'port'); return reply(403, 'Forbidden'); }
    if (!hostAllowed(host, opts.allow)) { note('deny', host, port, 'host-not-allowed'); return reply(403, 'Forbidden'); }

    const upstream = net.connect({ host, port, lookup: lookup as any });
    sockets.add(upstream);
    upstream.once('close', () => sockets.delete(upstream));
    upstream.setTimeout(300_000, () => upstream.destroy());
    upstream.on('error', () => { if (!client.destroyed && !client.writableEnded) reply(502, 'Bad Gateway'); upstream.destroy(); });
    upstream.once('connect', () => {
      note('allow', host, port);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
      client.once('close', () => upstream.destroy());
      upstream.once('close', () => client.destroy());
    });
  });

  const close = () => { server.close(); for (const s of sockets) s.destroy(); };
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    if (opts.unixSocket) {
      const socketPath = opts.unixSocket;
      server.listen(socketPath, () => {
        try { chmodSync(socketPath, 0o600); } catch { /* best effort; the directory is private */ }
        resolve({ env: {}, port: 0, password: secret, socketPath, close });
      });
      return;
    }
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as net.AddressInfo).port;
      resolve({ env: proxyEnv(`http://lly:${secret}@127.0.0.1:${port}`), port, password: secret, close });
    });
  });
}
