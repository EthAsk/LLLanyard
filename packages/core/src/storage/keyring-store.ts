import { FREE_LIMITS } from '../limits.js';
import { defaultBackend, type SecretBackend } from './backend.js';
import type { KeyMeta, SecureStore, SetOptions } from './types.js';

export class StoreError extends Error {}

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
export const SECRET_RE = /^[\x21-\x7e]{8,512}$/; // printable ASCII, no whitespace/newlines
const INDEX = '__index__';

const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

export function assertName(what: string, v: string) {
  if (!NAME_RE.test(v)) throw new StoreError(`Invalid ${what} "${v}" (use letters, digits, . _ - ; max 64 chars)`);
}

export class KeyringStore implements SecureStore {
  private maxKeys: number;
  constructor(private backend: SecretBackend = defaultBackend(), opts: { maxKeys?: number } = {}) {
    this.maxKeys = opts.maxKeys ?? FREE_LIMITS.maxKeys;
  }

  // Secrets and metadata live in separate keychain entries; the index only holds short ids,
  // so it stays far below Windows' ~2.5 KB credential size limit.
  private id(provider: string, label: string) {
    assertName('provider', provider);
    assertName('label', label);
    return `${provider.toLowerCase()}:${label.toLowerCase()}`;
  }

  private readIds(): string[] {
    const raw = this.backend.get(INDEX);
    if (!raw) return [];
    try {
      const v = JSON.parse(raw);
      if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v;
    } catch { /* fallthrough */ }
    throw new StoreError('Key index is corrupted; refusing to overwrite it. Run `lllanyard doctor`.');
  }

  private readMeta(id: string): KeyMeta | null {
    const raw = this.backend.get(`meta:${id}`);
    if (!raw) return null;
    try { return JSON.parse(raw) as KeyMeta; } catch { return null; }
  }

  set(provider: string, secret: string, opts: SetOptions = {}): KeyMeta {
    const label = opts.label ?? 'default';
    const id = this.id(provider, label);
    if (!SECRET_RE.test(secret)) throw new StoreError('Key looks invalid (8-512 printable characters, no spaces or newlines).');
    const ids = this.readIds();
    const exists = ids.includes(id);
    if (!exists && ids.length >= this.maxKeys) {
      throw new StoreError(`Free tier allows ${this.maxKeys} keys. Remove one or upgrade.`);
    }
    const prev = exists ? this.readMeta(id) : null;
    const days = opts.rotateAfterDays ?? prev?.rotateAfterDays ?? 90;
    if (!Number.isInteger(days) || days < 1 || days > 3650) throw new StoreError('rotateAfterDays must be 1-3650');
    const envName = opts.envName ?? prev?.envName; // rotating a key keeps its variable name
    if (envName !== undefined && !ENV_NAME_RE.test(envName)) throw new StoreError(`Invalid variable name "${envName}".`);
    const [p, l] = id.split(':') as [string, string];
    const meta: KeyMeta = { id, provider: p, label: l, createdAt: new Date().toISOString(), rotateAfterDays: days, last4: secret.slice(-4), ...(envName ? { envName } : {}) };
    this.backend.set(`key:${id}`, secret);
    this.backend.set(`meta:${id}`, JSON.stringify(meta));
    if (!exists) this.backend.set(INDEX, JSON.stringify([...ids, id]));
    return meta;
  }

  /** Sets (or clears, with undefined) the variable name a key is given to tools as. Metadata only; the key is unchanged. */
  setEnvName(provider: string, label = 'default', envName?: string): KeyMeta {
    const id = this.id(provider, label);
    const meta = this.readMeta(id);
    if (!meta || !this.readIds().includes(id)) throw new StoreError(`No ${id} key stored.`);
    if (envName !== undefined && !ENV_NAME_RE.test(envName)) throw new StoreError(`Invalid variable name "${envName}".`);
    const { envName: _old, ...rest } = meta;
    const next: KeyMeta = envName ? { ...rest, envName } : rest;
    this.backend.set(`meta:${id}`, JSON.stringify(next));
    return next;
  }

  get(provider: string, label = 'default'): string | null {
    return this.backend.get(`key:${this.id(provider, label)}`);
  }

  list(): KeyMeta[] {
    return this.readIds().map((id) => this.readMeta(id)).filter((m): m is KeyMeta => m !== null);
  }

  remove(provider: string, label = 'default'): boolean {
    const id = this.id(provider, label);
    const existed = this.backend.delete(`key:${id}`);
    this.backend.delete(`meta:${id}`);
    this.backend.set(INDEX, JSON.stringify(this.readIds().filter((x) => x !== id)));
    return existed;
  }
}
