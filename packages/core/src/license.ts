import { createPublicKey, verify } from 'node:crypto';
import { defaultBackend, type SecretBackend } from './storage/backend.js';
import { FREE_LIMITS } from './limits.js';

export type Tier = 'free' | 'pro' | 'team';
export interface LicensePayload { v: 1; id: string; tier: 'pro' | 'team'; seats: number; iat: number; exp: number; sub?: string }
export type Verified = { ok: true; payload: LicensePayload } | { ok: false; reason: string };

/**
 * The licensor's Ed25519 public key (PEM). License keys are signed with the matching private key, which is never
 * distributed.
 */
export const LICENSE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQwu+cr0JvXmoYwUjfvwXZ6C471QUpUcyMJsYqQqYyGw=
-----END PUBLIC KEY-----
`;

export const TIER_LIMITS: Record<Tier, { maxKeys: number }> = {
  free: { maxKeys: FREE_LIMITS.maxKeys },
  pro: { maxKeys: 250 },
  team: { maxKeys: 500 },
};

/** Agent tokens allowed per licensed seat (a person typically has a few devices/agents). */
export const AGENTS_PER_SEAT = 3;

const b64u = (s: string) => Buffer.from(s, 'base64url');

/** Offline check: `lly1.<payload>.<signature>`; nothing is sent anywhere. */
export function verifyLicense(token: string, publicKeyPem: string = LICENSE_PUBLIC_KEY, nowMs = Date.now()): Verified {
  try {
    if (!publicKeyPem) return { ok: false, reason: 'This build has no license public key configured.' };
    const parts = token.trim().split('.');
    if (parts.length !== 3 || parts[0] !== 'lly1') return { ok: false, reason: 'Not a LLLanyard license.' };
    const sigOk = verify(null, Buffer.from(`lly1.${parts[1]}`), createPublicKey(publicKeyPem), b64u(parts[2]!));
    if (!sigOk) return { ok: false, reason: 'Signature check failed (license is invalid or edited).' };
    const p = JSON.parse(b64u(parts[1]!).toString('utf8')) as LicensePayload;
    if (p.v !== 1 || (p.tier !== 'pro' && p.tier !== 'team') || !Number.isInteger(p.seats) || p.seats < 1 || !Number.isFinite(p.exp) || typeof p.id !== 'string')
      return { ok: false, reason: 'License contents are malformed.' };
    if (p.exp * 1000 < nowMs) return { ok: false, reason: `License expired on ${new Date(p.exp * 1000).toISOString().slice(0, 10)}.` };
    return { ok: true, payload: p };
  } catch {
    return { ok: false, reason: 'License could not be read.' };
  }
}

const SLOT = '__license__';

export class LicenseStore {
  constructor(private backend: SecretBackend = defaultBackend(), private publicKey: string = LICENSE_PUBLIC_KEY) {}
  activate(token: string, nowMs = Date.now()): LicensePayload {
    const v = verifyLicense(token, this.publicKey, nowMs);
    if (!v.ok) throw new Error(v.reason);
    this.backend.set(SLOT, token.trim());
    return v.payload;
  }
  remove() { this.backend.delete(SLOT); }
  /** The stored license text, valid or not (refresh sends it to get its renewal). */
  token(): string | undefined { return this.backend.get(SLOT) ?? undefined; }
  status(nowMs = Date.now()): { tier: Tier; payload?: LicensePayload; problem?: string } {
    const t = this.backend.get(SLOT);
    if (!t) return { tier: 'free' };
    const v = verifyLicense(t, this.publicKey, nowMs);
    return v.ok ? { tier: v.payload.tier, payload: v.payload } : { tier: 'free', problem: v.reason }; // lapsed = free; existing keys keep working
  }
  limits(nowMs = Date.now()) { return TIER_LIMITS[this.status(nowMs).tier]; }
  /** Free: 5 agents. Licensed: seats x AGENTS_PER_SEAT (never below the free allowance). */
  maxAgents(nowMs = Date.now()): number {
    const st = this.status(nowMs);
    return st.payload ? Math.max(FREE_LIMITS.maxAgents, st.payload.seats * AGENTS_PER_SEAT) : FREE_LIMITS.maxAgents;
  }
}

/** Where paid licenses are sold and renewed. Only `refreshLicense` contacts it, and only for a stored paid license. */
export const LICENSE_SERVER = process.env.LLLANYARD_LICENSE_SERVER ?? 'https://lllanyard.app';
/** Days before a license runs out when start-up checks for its renewed key. */
export const REFRESH_WINDOW_DAYS = 7;

export type RefreshResult =
  | { kind: 'renewed'; payload: LicensePayload }
  | { kind: 'current'; message: string }
  | { kind: 'none' }
  | { kind: 'failed'; message: string };

/**
 * Asks the license server for the newest key of the stored license (after a subscription renews) and stores it.
 * Sends only the stored license itself. Does nothing without a stored license that this server issued.
 */
export async function refreshLicense(store: LicenseStore, fetchFn: typeof fetch = fetch): Promise<RefreshResult> {
  const token = store.token();
  if (!token) return { kind: 'none' };
  const parts = token.split('.');
  let sub: unknown;
  try { sub = JSON.parse(b64u(parts[1] ?? '').toString('utf8')).sub; } catch { return { kind: 'none' }; }
  if (typeof sub !== 'string' || !sub.startsWith('lic_')) return { kind: 'none' }; // not sold through the server
  try {
    const res = await fetchFn(`${LICENSE_SERVER}/api/licence/refresh`, {
      method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ licence: token }), signal: AbortSignal.timeout(10_000),
    });
    const body = (await res.json().catch(() => ({}))) as { licence?: unknown; message?: unknown };
    if (!res.ok) return { kind: 'failed', message: typeof body.message === 'string' ? body.message : `License server answered ${res.status}.` };
    if (typeof body.licence === 'string') return { kind: 'renewed', payload: store.activate(body.licence) };
    return { kind: 'current', message: typeof body.message === 'string' ? body.message : 'No newer key yet.' };
  } catch (e) {
    return { kind: 'failed', message: `Could not reach the license server: ${(e as Error).message}` };
  }
}

/** True when start-up should look for a renewed key: a paid license ends within the window (or ended recently). */
export function refreshDue(store: LicenseStore, nowMs = Date.now()): boolean {
  if (process.env.LLLANYARD_NO_LICENSE_REFRESH) return false;
  const token = store.token();
  if (!token) return false;
  try {
    const p = JSON.parse(b64u(token.split('.')[1] ?? '').toString('utf8')) as Partial<LicensePayload>;
    if (typeof p.exp !== 'number' || typeof p.sub !== 'string' || !p.sub.startsWith('lic_')) return false;
    const left = p.exp * 1000 - nowMs;
    return left < REFRESH_WINDOW_DAYS * 86_400_000 && left > -60 * 86_400_000;
  } catch { return false; }
}
