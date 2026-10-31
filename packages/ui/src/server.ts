import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import { PAGE } from './page.js';

/** What the UI needs from the rest of the app. Injected so the server is testable without a keychain. */
export interface UiDeps {
  state: () => unknown; // everything the page shows; must never contain secrets
  addKey: (b: { provider: string; label: string; secret: string; rotateDays?: number; envName?: string }) => void;
  removeKey: (provider: string, label: string) => boolean;
  createAgent: (b: { name: string; client: string; providers?: string[]; expiresDays?: number }) => string;
  revokeAgent: (name: string) => boolean;
  activateLicense: (key: string) => unknown;
  removeLicense: () => void;
  review: (b: { question?: string; useModel: boolean }) => Promise<{ text: string; source: 'model' | 'rules'; note?: string }>;
  setAssistant: (b: { endpoint: string; model: string; kind: 'ollama' | 'openai' }) => void;
  proxy: (action: 'start' | 'stop') => Promise<unknown>;
  addProvider: (b: { id: string; upstream: string; auth: 'bearer' | 'header'; header?: string; prefix?: string }) => void;
  removeProvider: (id: string) => boolean;
  addTool: (b: { name: string; command: string; args: string[]; env: Record<string, string>; keys: string[]; pins: string[]; allowArgs: boolean; passEnv: string[]; allowHosts: string[] }) => unknown;
  setKeyEnv: (b: { provider: string; label: string; envName?: string }) => void;
  removeTool: (name: string) => boolean;
  setup: (b: { app: 'claude-desktop' | 'claude-code'; remove: boolean; restart: boolean; scriptDirs: string[] }) => unknown; // connect an AI app
  backup: (passphrase: string) => { file: string; items: string[] }; // writes the encrypted file; returns where and what
  restore: (b: { text: string; passphrase: string; overwrite: boolean; dryRun: boolean }) => unknown;
  isUserError: (e: unknown) => boolean; // errors whose message is safe to show
  log?: (m: string) => void;
}

const MAX_BODY = 64 * 1024;
const MAX_BACKUP = 2 * 1024 * 1024; // restore uploads the whole backup file
const digest = (s: string) => createHash('sha256').update(s).digest();

export interface UiServer { server: http.Server; token: string; nonce: string }

export function createUiServer(deps: UiDeps, token = randomBytes(32).toString('base64url')): UiServer {
  const nonce = randomBytes(16).toString('base64');
  const want = digest(token);
  const log = deps.log ?? (() => {});

  const csp = `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
  const base = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'cross-origin-resource-policy': 'same-origin' };
  const json = (res: http.ServerResponse, code: number, body: unknown) => {
    const b = JSON.stringify(body);
    res.writeHead(code, { ...base, 'content-type': 'application/json', 'content-length': Buffer.byteLength(b) });
    res.end(b);
  };

  const server = http.createServer((req, res) => {
    // Refusals are sent before any request body is read. Discard the body and close the connection, so the client
    // gets the refusal rather than a reset from a half-read keep-alive connection.
    const deny = (code: number, error: string) => { req.resume(); res.setHeader('connection', 'close'); return json(res, code, { error }); };
    const port = req.socket.localPort;
    const host = String(req.headers.host ?? '').toLowerCase();
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) return deny(403, 'Forbidden host'); // DNS rebinding
    const url = new URL(req.url ?? '/', `http://${host}`);

    if (req.method === 'GET' && url.pathname === '/') {
      const html = PAGE.replaceAll('__NONCE__', nonce);
      res.writeHead(200, { ...base, 'content-type': 'text/html; charset=utf-8', 'content-security-policy': csp, 'x-frame-options': 'DENY' });
      return void res.end(html);
    }
    if (!url.pathname.startsWith('/api/')) return deny(404, 'Not found');

    // Every API call needs the session token (given only to whoever launched the UI) ...
    const given = digest(String(req.headers['x-lly-session'] ?? ''));
    if (!timingSafeEqual(given, want)) return deny(401, 'Missing or invalid session. Reopen LLLanyard from the app or the link printed by `lllanyard ui`.');
    // ... and must come from this page itself.
    const origin = req.headers.origin;
    if (origin && origin !== `http://${host}`) return deny(403, 'Cross-origin request refused');
    const site = req.headers['sec-fetch-site'];
    if (site && site !== 'same-origin' && site !== 'none') return deny(403, 'Cross-site request refused');

    const route = `${req.method} ${url.pathname}`;
    const readBody = (max = MAX_BODY): Promise<any> => new Promise((resolve, reject) => {
      if (!/^application\/json\b/i.test(String(req.headers['content-type'] ?? ''))) return reject(Object.assign(new Error('Content-Type must be application/json'), { code: 415 }));
      let n = 0, over = false; const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => { if (over) return; n += c.length; if (n > max) { over = true; chunks.length = 0; reject(Object.assign(new Error('Request too large'), { code: 413 })); return; } chunks.push(c); });
      req.on('end', () => { if (over) return; try { const v = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}; resolve(v && typeof v === 'object' && !Array.isArray(v) ? v : {}); } catch { reject(Object.assign(new Error('Invalid JSON'), { code: 400 })); } });
      req.on('error', reject);
    });
    const s = (v: unknown, max = 600) => (typeof v === 'string' && v.length <= max ? v : (() => { throw Object.assign(new Error('Invalid input'), { code: 400 }); })());
    const bad = (): never => { throw Object.assign(new Error('Invalid input'), { code: 400 }); };
    const optList = (v: unknown) => (Array.isArray(v) ? v.slice(0, 20).map((x) => s(x, 64)) : undefined);
    const list = (v: unknown, n: number, max: number) => (Array.isArray(v) && v.length <= n ? v.map((x) => s(x, max)) : v === undefined ? [] : bad());
    const strMap = (v: unknown) => {
      if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length > 20) return bad();
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [s(k, 128), s(x, 130)]));
    };
    const optInt = (v: unknown) => (v === undefined || v === null || v === '' ? undefined : Number.isInteger(v) ? (v as number) : (() => { throw Object.assign(new Error('Invalid number'), { code: 400 }); })());

    (async () => {
      switch (route) {
        case 'GET /api/state': return json(res, 200, deps.state());
        case 'POST /api/keys': {
          const b = await readBody();
          deps.addKey({ provider: s(b.provider, 64), label: s(b.label ?? 'default', 64), secret: s(b.secret, 600), rotateDays: optInt(b.rotateDays), ...(b.envName ? { envName: s(b.envName, 128) } : {}) });
          return json(res, 200, { ok: true });
        }
        case 'DELETE /api/keys': { const b = await readBody(); return json(res, 200, { ok: deps.removeKey(s(b.provider, 64), s(b.label ?? 'default', 64)) }); }
        case 'POST /api/agents': {
          const b = await readBody();
          const token = deps.createAgent({ name: s(b.name, 64), client: s(b.client ?? 'default', 64), providers: optList(b.providers), expiresDays: optInt(b.expiresDays) });
          return json(res, 200, { token }); // shown once by the page; only a hash is stored
        }
        case 'DELETE /api/agents': { const b = await readBody(); return json(res, 200, { ok: deps.revokeAgent(s(b.name, 64)) }); }
        case 'POST /api/license': { const b = await readBody(); return json(res, 200, { license: deps.activateLicense(s(b.key, 2000)) }); }
        case 'DELETE /api/license': deps.removeLicense(); return json(res, 200, { ok: true });
        case 'POST /api/assistant': { const b = await readBody(); return json(res, 200, await deps.review({ question: typeof b.question === 'string' ? b.question.slice(0, 500) : undefined, useModel: b.useModel === true })); }
        case 'POST /api/assistant/config': {
          const b = await readBody();
          deps.setAssistant({ endpoint: s(b.endpoint, 200), model: s(b.model, 100), kind: b.kind === 'openai' ? 'openai' : 'ollama' });
          return json(res, 200, { ok: true });
        }
        case 'POST /api/proxy': { const b = await readBody(); return json(res, 200, await deps.proxy(b.action === 'stop' ? 'stop' : 'start')); }
        case 'POST /api/providers': {
          const b = await readBody();
          deps.addProvider({ id: s(b.id, 64), upstream: s(b.upstream, 300), auth: b.auth === 'header' ? 'header' : 'bearer',
            header: b.header ? s(b.header, 64) : undefined, prefix: b.prefix ? s(b.prefix, 20) : undefined });
          return json(res, 200, { ok: true });
        }
        case 'DELETE /api/providers': { const b = await readBody(); return json(res, 200, { ok: deps.removeProvider(s(b.id, 64)) }); }
        case 'POST /api/tools': {
          const b = await readBody();
          const tool = deps.addTool({ name: s(b.name, 64), command: s(b.command, 400), args: list(b.args, 50, 1000), env: strMap(b.env),
            keys: list(b.keys, 20, 130), pins: list(b.pins, 10, 400),
            allowArgs: b.allowArgs === true, passEnv: list(b.passEnv, 20, 128), allowHosts: list(b.allowHosts, 20, 253) });
          return json(res, 200, { tool });
        }
        case 'POST /api/keys/env': {
          const b = await readBody();
          deps.setKeyEnv({ provider: s(b.provider, 64), label: s(b.label ?? 'default', 64), envName: b.envName ? s(b.envName, 128) : undefined });
          return json(res, 200, { ok: true });
        }
        case 'POST /api/setup': {
          const b = await readBody();
          if (b.app !== 'claude-desktop' && b.app !== 'claude-code') return json(res, 400, { error: 'Unknown app' });
          return json(res, 200, { result: await deps.setup({ app: b.app, remove: b.remove === true, restart: b.restart === true, scriptDirs: list(b.scriptDirs, 20, 1000) }) });
        }
        case 'DELETE /api/tools': { const b = await readBody(); return json(res, 200, { ok: deps.removeTool(s(b.name, 64)) }); }
        case 'POST /api/backup': { const b = await readBody(); return json(res, 200, deps.backup(s(b.passphrase, 1000))); }
        case 'POST /api/restore': {
          const b = await readBody(MAX_BACKUP);
          return json(res, 200, deps.restore({ text: s(b.text, MAX_BACKUP), passphrase: s(b.passphrase, 1000), overwrite: b.overwrite === true, dryRun: b.dryRun === true }));
        }
        default: return json(res, 404, { error: 'Not found' });
      }
    })().catch((e: any) => {
      if (typeof e?.code === 'number') { if (e.code === 413) res.setHeader('connection', 'close'); return json(res, e.code, { error: e.message }); }
      if (deps.isUserError(e)) return json(res, 400, { error: e.message });
      log(`internal error on ${route}: ${e?.name ?? 'Error'}`); // never log request bodies
      json(res, 500, { error: 'Internal error' });
    });
  });
  return { server, token, nonce };
}
