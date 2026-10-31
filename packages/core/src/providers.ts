import { isIP } from 'node:net';
import { defaultBackend, type SecretBackend } from './storage/backend.js';
import { assertName, StoreError } from './storage/keyring-store.js';

export type AuthSpec = { type: 'bearer' } | { type: 'header'; name: string; prefix?: string };

export interface ProviderConfig {
  id: string;
  upstream: string; // https origin, optionally with a fixed path prefix (e.g. https://openrouter.ai/api)
  auth: AuthSpec;
  allowLocal?: boolean; // loopback upstreams only (local model servers, dev APIs)
}

// Built-in providers: the API host and how each one sends its key.
export const BUILTIN_PROVIDERS: ProviderConfig[] = [
  { id: 'openai', upstream: 'https://api.openai.com', auth: { type: 'bearer' } },
  { id: 'anthropic', upstream: 'https://api.anthropic.com', auth: { type: 'header', name: 'x-api-key' } },
  { id: 'gemini', upstream: 'https://generativelanguage.googleapis.com', auth: { type: 'header', name: 'x-goog-api-key' } },
  { id: 'openrouter', upstream: 'https://openrouter.ai/api', auth: { type: 'bearer' } },
  { id: 'github', upstream: 'https://api.github.com', auth: { type: 'bearer' } },
  { id: 'slack', upstream: 'https://slack.com/api', auth: { type: 'bearer' } },
  { id: 'stripe', upstream: 'https://api.stripe.com', auth: { type: 'bearer' } },
  { id: 'notion', upstream: 'https://api.notion.com', auth: { type: 'bearer' } },
];
const BUILTIN_IDS = new Set(BUILTIN_PROVIDERS.map((p) => p.id));
export const isBuiltinProvider = (id: string) => BUILTIN_IDS.has(id.toLowerCase());

const HEADER_RE = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;
const FORBIDDEN_HEADERS = new Set([
  'host', 'content-length', 'content-type', 'transfer-encoding', 'connection', 'upgrade', 'te', 'cookie', 'set-cookie', 'proxy-authorization',
]);
const PREFIX_RE = /^[\x20-\x7e]{1,20}$/;
const isLoopbackHost = (h: string) => h === 'localhost' || h === '127.0.0.1' || h === '::1';

/** Validates and normalises a provider definition. Throws StoreError with a plain-language reason. */
export function validateProvider(cfg: ProviderConfig, opts: { allowBuiltinId?: boolean } = {}): ProviderConfig {
  assertName('provider id', cfg.id);
  const id = cfg.id.toLowerCase();
  if (!opts.allowBuiltinId && BUILTIN_IDS.has(id)) throw new StoreError(`"${id}" is a built-in provider and cannot be redefined.`);

  let u: URL;
  try { u = new URL(cfg.upstream); } catch { throw new StoreError(`Invalid upstream URL "${cfg.upstream}".`); }
  if (u.username || u.password) throw new StoreError('Upstream URL must not contain credentials.');
  if (u.search || u.hash) throw new StoreError('Upstream URL must not contain a query string or fragment.');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host) throw new StoreError('Upstream URL has no host.');
  const loopback = isLoopbackHost(host);

  if (cfg.allowLocal) {
    if (!loopback) throw new StoreError('allowLocal is only valid for loopback upstreams (localhost, 127.0.0.1, ::1).');
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new StoreError('Upstream must be http(s).');
  } else {
    if (u.protocol !== 'https:') throw new StoreError('Upstream must use https (use --allow-local for a loopback server).');
    if (loopback || isIP(host)) throw new StoreError('Upstream must be a public hostname, not an IP address or localhost.');
  }

  const a = cfg.auth;
  let auth: AuthSpec;
  if (a?.type === 'bearer') auth = { type: 'bearer' };
  else if (a?.type === 'header') {
    if (!HEADER_RE.test(a.name) || FORBIDDEN_HEADERS.has(a.name.toLowerCase())) throw new StoreError(`Invalid auth header name "${a.name}".`);
    if (a.prefix !== undefined && !PREFIX_RE.test(a.prefix)) throw new StoreError('Auth prefix must be 1-20 printable characters.');
    auth = a.prefix !== undefined ? { type: 'header', name: a.name, prefix: a.prefix } : { type: 'header', name: a.name };
  } else throw new StoreError('auth must be "bearer" or "header".');

  const upstream = u.origin + u.pathname.replace(/\/+$/, '');
  return { id, upstream, auth, ...(cfg.allowLocal ? { allowLocal: true } : {}) };
}

const INDEX = '__providers__';

/**
 * Custom providers live in the OS keychain (not a config file), so something that can merely edit
 * files cannot repoint a provider at an attacker's host to harvest the injected key.
 */
export class ProviderStore {
  constructor(private backend: SecretBackend = defaultBackend()) {}

  private ids(): string[] {
    const raw = this.backend.get(INDEX);
    if (!raw) return [];
    try { const v = JSON.parse(raw); if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v; } catch { /* */ }
    throw new StoreError('Provider index is corrupted; refusing to overwrite it.');
  }

  set(cfg: ProviderConfig): ProviderConfig {
    const v = validateProvider(cfg);
    const ids = this.ids();
    this.backend.set(`provider:${v.id}`, JSON.stringify(v));
    if (!ids.includes(v.id)) this.backend.set(INDEX, JSON.stringify([...ids, v.id]));
    return v;
  }

  get(id: string): ProviderConfig | null {
    const raw = this.backend.get(`provider:${id.toLowerCase()}`);
    if (!raw) return null;
    try { return validateProvider(JSON.parse(raw)); } catch { return null; } // invalid entries are ignored, never used
  }

  list(): ProviderConfig[] {
    return this.ids().map((id) => this.get(id)).filter((p): p is ProviderConfig => p !== null);
  }

  remove(id: string): boolean {
    const n = id.toLowerCase();
    const existed = this.backend.delete(`provider:${n}`);
    this.backend.set(INDEX, JSON.stringify(this.ids().filter((x) => x !== n)));
    return existed;
  }
}

/** Built-ins first; custom providers can never shadow them (validateProvider forbids the ids). */
export function allProviders(store: ProviderStore): Record<string, ProviderConfig> {
  const out: Record<string, ProviderConfig> = Object.create(null);
  for (const p of store.list()) out[p.id] = p;
  for (const p of BUILTIN_PROVIDERS) out[p.id] = p;
  return out;
}
