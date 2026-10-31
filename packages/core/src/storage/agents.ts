import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { defaultBackend, type SecretBackend } from './backend.js';
import { assertName, StoreError } from './keyring-store.js';

export interface AgentIdentity {
  name: string;
  client: string; // which key label this agent may use (freelancer/agency mode)
  providers?: string[]; // if set, the only providers this agent may call (least privilege)
}
interface AgentRecord { hash: string; client: string; createdAt: string; providers?: string[]; expiresAt?: string }

const INDEX = '__agents__';
const sha = (t: string) => createHash('sha256').update(t).digest();

/**
 * Agents authenticate to the proxy with a placeholder token ("lly_...").
 * Only a SHA-256 hash is stored, so the token cannot be recovered; it is worthless outside the proxy.
 */
export class AgentStore {
  constructor(private backend: SecretBackend = defaultBackend()) {}

  private names(): string[] {
    const raw = this.backend.get(INDEX);
    if (!raw) return [];
    try { const v = JSON.parse(raw); if (Array.isArray(v)) return v.filter((x) => typeof x === 'string'); } catch { /* */ }
    throw new StoreError('Agent index is corrupted; refusing to overwrite it.');
  }

  create(name: string, client = 'default', providers?: string[], opts: { expiresAt?: Date } = {}): string {
    assertName('agent name', name);
    assertName('client', client);
    const n = name.toLowerCase();
    const token = 'lly_' + randomBytes(32).toString('base64url');
    const rec: AgentRecord = { hash: sha(token).toString('hex'), client: client.toLowerCase(), createdAt: new Date().toISOString() };
    if (providers?.length) {
      providers.forEach((p) => assertName('provider', p));
      rec.providers = [...new Set(providers.map((p) => p.toLowerCase()))];
    }
    if (opts.expiresAt) {
      if (!(opts.expiresAt.getTime() > Date.now())) throw new StoreError('Expiry must be in the future.');
      rec.expiresAt = opts.expiresAt.toISOString();
    }
    this.backend.set(`agent:${n}`, JSON.stringify(rec));
    const names = this.names();
    if (!names.includes(n)) this.backend.set(INDEX, JSON.stringify([...names, n]));
    return token; // shown once, never stored
  }

  revoke(name: string): boolean {
    const n = name.toLowerCase();
    const existed = this.backend.delete(`agent:${n}`);
    this.backend.set(INDEX, JSON.stringify(this.names().filter((x) => x !== n)));
    return existed;
  }

  list(): { name: string; client: string; createdAt: string; providers?: string[]; expiresAt?: string }[] {
    return this.names().flatMap((name) => {
      const raw = this.backend.get(`agent:${name}`);
      if (!raw) return [];
      const r = JSON.parse(raw) as AgentRecord;
      return [{ name, client: r.client, createdAt: r.createdAt, providers: r.providers, expiresAt: r.expiresAt }];
    });
  }

  /** Snapshot verifier: one keychain read burst up front instead of one per request. */
  verifier(now: () => number = Date.now): (token: string) => AgentIdentity | null {
    const records = this.names().flatMap((name) => {
      const raw = this.backend.get(`agent:${name}`);
      if (!raw) return [];
      const r = JSON.parse(raw) as AgentRecord;
      return [{ name, client: r.client, providers: r.providers, exp: r.expiresAt ? Date.parse(r.expiresAt) : Infinity, hash: Buffer.from(r.hash, 'hex') }];
    });
    return (token) => {
      const h = sha(token);
      let found: AgentIdentity | null = null;
      for (const r of records) {
        if (r.hash.length === h.length && timingSafeEqual(r.hash, h) && r.exp > now()) found = { name: r.name, client: r.client, ...(r.providers ? { providers: r.providers } : {}) };
      }
      return found;
    };
  }
}
