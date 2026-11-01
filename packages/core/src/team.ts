import { defaultBackend, type SecretBackend } from './storage/backend.js';

/**
 * A Team member's link to the team's shared proxy. The member's own LLLanyard keeps their personal keys; a request
 * for a key they don't hold goes on to the team server, authenticated with the member's own team token. Personal
 * keys never leave this machine, and the team server's keys never come here.
 */
export interface TeamLink {
  url: string; // https://keys.example.com:3443, no path
  token: string; // this member's agent token on the team server
  ca?: string; // PEM of a private certificate authority that signed the team server's certificate
  joinedAt: string;
}

const SLOT = '__team__';

/** Checks and normalises a team server address: HTTPS only (tokens must not cross the network in clear), no path. */
export function normaliseTeamUrl(input: string): string {
  let u: URL;
  try { u = new URL(input.trim()); } catch { throw new Error('Give the team server address, such as https://keys.example.com:3443'); }
  if (u.protocol !== 'https:') throw new Error('The team server must use https:// (tokens would otherwise cross the network unencrypted).');
  if (u.username || u.password) throw new Error('Leave the user name and password out of the address: the token is given separately.');
  if ((u.pathname !== '/' && u.pathname !== '') || u.search || u.hash) throw new Error('Give just the address and port, with no path, such as https://keys.example.com:3443');
  return u.origin;
}

export class TeamStore {
  constructor(private backend: SecretBackend = defaultBackend()) {}

  get(): TeamLink | null {
    const raw = this.backend.get(SLOT);
    if (!raw) return null;
    try {
      const v = JSON.parse(raw) as TeamLink;
      return typeof v.url === 'string' && typeof v.token === 'string' ? v : null;
    } catch {
      return null;
    }
  }

  set(link: { url: string; token: string; ca?: string }): TeamLink {
    const token = link.token.trim();
    if (!/^lly_[A-Za-z0-9_-]{16,}$/.test(token)) throw new Error('That is not an LLLanyard agent token (they start with lly_).');
    if (link.ca !== undefined && !link.ca.includes('-----BEGIN CERTIFICATE-----')) throw new Error('The CA file must be a PEM certificate.');
    const v: TeamLink = { url: normaliseTeamUrl(link.url), token, ...(link.ca ? { ca: link.ca } : {}), joinedAt: new Date().toISOString() };
    this.backend.set(SLOT, JSON.stringify(v));
    return v;
  }

  remove(): boolean { return this.backend.delete(SLOT); }
}
