import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { normaliseTeamUrl } from './team.js';
import { FREE_LIMITS } from './limits.js';
import { validateProvider } from './providers.js';
import { defaultBackend, type SecretBackend } from './storage/backend.js';
import { MIN_PASSPHRASE } from './storage/file-backend.js';
import { assertName, SECRET_RE, StoreError } from './storage/keyring-store.js';
import { validateTool } from './tools.js';

/**
 * Encrypted backup of everything LLLanyard keeps in the secret store: keys (+ metadata), custom providers, approved
 * tools, agents and the license. The OS keychain can't be enumerated, so items are found through each store's index.
 *
 * The file is AES-256-GCM with a scrypt-derived key (same scheme as the file vault, different AAD so a backup can't be
 * mistaken for a vault). Agents are copied as their token hashes, so existing agent tokens keep working after a restore.
 * Restore validates every item before writing anything and never touches items it doesn't recognise.
 */
const AAD = Buffer.from('lllanyard-backup-v1');
const KDF = { n: 1 << 17, r: 8, p: 1 };
const MAGIC = 'lllanyard-backup';

// Index entry and record prefixes used by each store (keyring-store, providers, agents, tools, license).
const KINDS = {
  key: { index: '__index__', records: (id: string) => [`key:${id}`, `meta:${id}`] },
  provider: { index: '__providers__', records: (id: string) => [`provider:${id}`] },
  tool: { index: '__tools__', records: (id: string) => [`tool:${id}`] },
  agent: { index: '__agents__', records: (id: string) => [`agent:${id}`] },
} as const;
type Kind = keyof typeof KINDS;
const LICENSE = '__license__';
const TEAM = '__team__';

export interface BackupItem { kind: Kind | 'license' | 'team'; id: string; records: Record<string, string> }
export interface BackupPayload { v: 1; createdAt: string; items: BackupItem[] }
interface Header { v: 1; app: typeof MAGIC; kdf: { n: number; r: number; p: number; salt: string }; nonce: string; ct: string; tag: string }

function readIndex(backend: SecretBackend, account: string): string[] {
  const raw = backend.get(account);
  if (!raw) return [];
  try { const v = JSON.parse(raw); if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v; } catch { /* */ }
  throw new StoreError(`Index ${account} is corrupted; refusing to back up a partial store.`);
}

/** Reads every item from the store. Items whose records are missing (half-deleted) are left out. */
export function collectItems(backend: SecretBackend = defaultBackend()): BackupItem[] {
  const items: BackupItem[] = [];
  for (const kind of Object.keys(KINDS) as Kind[]) {
    for (const id of readIndex(backend, KINDS[kind].index)) {
      const records: Record<string, string> = {};
      for (const acct of KINDS[kind].records(id)) {
        const v = backend.get(acct);
        if (v !== null) records[acct] = v;
      }
      if (Object.keys(records).length === KINDS[kind].records(id).length) items.push({ kind, id, records });
    }
  }
  const lic = backend.get(LICENSE);
  if (lic) items.push({ kind: 'license', id: 'license', records: { [LICENSE]: lic } });
  const team = backend.get(TEAM);
  if (team) items.push({ kind: 'team', id: 'team', records: { [TEAM]: team } });
  return items;
}

const derive = (pass: string, salt: Buffer, kdf: { n: number; r: number; p: number }) =>
  scryptSync(pass, salt, 32, { N: kdf.n, r: kdf.r, p: kdf.p, maxmem: 256 * 1024 * 1024 });

/** Returns the backup file contents (JSON text). Contains secrets, so callers must write it with private permissions. */
export function createBackup(passphrase: string, backend: SecretBackend = defaultBackend(), now = new Date()): { text: string; items: BackupItem[] } {
  if (passphrase.length < MIN_PASSPHRASE) throw new StoreError(`Backup passphrase must be at least ${MIN_PASSPHRASE} characters.`);
  const items = collectItems(backend);
  const payload: BackupPayload = { v: 1, createdAt: now.toISOString(), items };
  const salt = randomBytes(16), nonce = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', derive(passphrase, salt, KDF), nonce);
  c.setAAD(AAD);
  const ct = Buffer.concat([c.update(JSON.stringify(payload), 'utf8'), c.final()]);
  const header: Header = { v: 1, app: MAGIC, kdf: { ...KDF, salt: salt.toString('base64') }, nonce: nonce.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
  return { text: JSON.stringify(header), items };
}

/** Decrypts and parses a backup. A wrong passphrase or an edited file is always an error. */
export function readBackup(text: string, passphrase: string): BackupPayload {
  let h: Header;
  try { h = JSON.parse(text); } catch { throw new StoreError('Not a LLLanyard backup file.'); }
  if (h?.app !== MAGIC) throw new StoreError('Not a LLLanyard backup file.');
  if (h.v !== 1) throw new StoreError(`Unsupported backup version ${h.v}.`);
  if (!h.kdf || h.kdf.n > 1 << 20 || h.kdf.n < 1 << 14 || h.kdf.r > 32 || h.kdf.p > 16) throw new StoreError('Backup KDF parameters out of range; refusing to open.');
  const d = createDecipheriv('aes-256-gcm', derive(passphrase, Buffer.from(h.kdf.salt, 'base64'), h.kdf), Buffer.from(h.nonce, 'base64'));
  d.setAAD(AAD);
  d.setAuthTag(Buffer.from(h.tag, 'base64'));
  let p: BackupPayload;
  try { p = JSON.parse(Buffer.concat([d.update(Buffer.from(h.ct, 'base64')), d.final()]).toString('utf8')); }
  catch { throw new StoreError('Could not open the backup: wrong passphrase, or the file was modified.'); }
  if (p?.v !== 1 || !Array.isArray(p.items)) throw new StoreError('Backup contents are malformed.');
  return p;
}

const parse = (s: string | undefined) => { try { return s === undefined ? undefined : JSON.parse(s); } catch { return undefined; } };

/** Throws a plain-language reason if an item from a backup is not something the stores would have written. */
function checkItem(it: BackupItem): void {
  if (!it || typeof it.id !== 'string' || typeof it.records !== 'object' || it.records === null) throw new StoreError('malformed item');
  const expected = it.kind === 'license' ? [LICENSE] : it.kind === 'team' ? [TEAM] : KINDS[it.kind as Kind]?.records(it.id);
  if (!expected) throw new StoreError(`unknown item type "${it.kind}"`);
  const got = Object.keys(it.records);
  if (got.length !== expected.length || !expected.every((a) => typeof it.records[a] === 'string')) throw new StoreError('unexpected records');
  const r = it.records;
  switch (it.kind) {
    case 'key': {
      const [p, l, ...extra] = it.id.split(':');
      if (!p || !l || extra.length) throw new StoreError('bad key id');
      assertName('provider', p); assertName('label', l);
      if (it.id !== it.id.toLowerCase()) throw new StoreError('bad key id');
      if (!SECRET_RE.test(r[`key:${it.id}`]!)) throw new StoreError('key value is not valid');
      const meta = parse(r[`meta:${it.id}`]);
      if (meta?.id !== it.id || typeof meta.createdAt !== 'string' || !Number.isInteger(meta.rotateAfterDays)) throw new StoreError('key metadata is not valid');
      return;
    }
    case 'provider': {
      const v = validateProvider(parse(r[`provider:${it.id}`]));
      if (v.id !== it.id) throw new StoreError('provider id mismatch');
      return;
    }
    case 'tool': {
      const v = validateTool(parse(r[`tool:${it.id}`]));
      if (v.name !== it.id) throw new StoreError('tool name mismatch');
      return;
    }
    case 'agent': {
      assertName('agent name', it.id);
      const a = parse(r[`agent:${it.id}`]);
      if (typeof a?.hash !== 'string' || !/^[0-9a-f]{64}$/.test(a.hash) || typeof a.client !== 'string') throw new StoreError('agent record is not valid');
      assertName('client', a.client);
      return;
    }
    case 'license':
      if (!/^lly1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(r[LICENSE]!.trim())) throw new StoreError('license is not valid');
      return;
    case 'team': {
      const t = parse(r[TEAM]);
      if (typeof t?.url !== 'string' || typeof t.token !== 'string' || !/^lly_[A-Za-z0-9_-]{16,}$/.test(t.token)) throw new StoreError('team link is not valid');
      try { if (normaliseTeamUrl(t.url) !== t.url) throw new Error(); } catch { throw new StoreError('team link is not valid'); }
      if (t.ca !== undefined && (typeof t.ca !== 'string' || !t.ca.includes('-----BEGIN CERTIFICATE-----'))) throw new StoreError('team link is not valid');
      return;
    }
  }
}

export interface RestoreOptions {
  overwrite?: boolean; // replace items that already exist (default: keep the current ones)
  dryRun?: boolean;
  maxKeys?: number; // key limit for the current tier
}
export interface RestoreReport {
  added: BackupItem[];
  replaced: BackupItem[];
  kept: BackupItem[]; // already present and not overwritten
  invalid: { item: BackupItem; reason: string }[];
}

/**
 * Merges a backup into the store. Everything is validated and the key limit checked before the first write;
 * items not in the backup are never removed.
 */
export function restoreBackup(payload: BackupPayload, backend: SecretBackend = defaultBackend(), opts: RestoreOptions = {}): RestoreReport {
  const report: RestoreReport = { added: [], replaced: [], kept: [], invalid: [] };
  const current = Object.fromEntries((Object.keys(KINDS) as Kind[]).map((k) => [k, readIndex(backend, KINDS[k].index)])) as Record<Kind, string[]>;
  const hasLicense = backend.get(LICENSE) !== null;
  const hasTeam = backend.get(TEAM) !== null;

  for (const it of payload.items) {
    try { checkItem(it); } catch (e) { report.invalid.push({ item: it, reason: (e as Error).message }); continue; }
    const exists = it.kind === 'license' ? hasLicense : it.kind === 'team' ? hasTeam : current[it.kind].includes(it.id);
    if (!exists) report.added.push(it);
    else if (opts.overwrite) report.replaced.push(it);
    else report.kept.push(it);
  }

  const maxKeys = opts.maxKeys ?? FREE_LIMITS.maxKeys;
  const newKeys = report.added.filter((i) => i.kind === 'key').length;
  if (current.key.length + newKeys > maxKeys)
    throw new StoreError(`Restoring would give ${current.key.length + newKeys} keys; your plan allows ${maxKeys}. Remove some keys first, or upgrade.`);
  if (opts.dryRun) return report;

  // Records first, indexes last: an interrupted restore leaves unindexed records, never index entries pointing at nothing.
  for (const it of [...report.added, ...report.replaced]) for (const [acct, v] of Object.entries(it.records)) backend.set(acct, v);
  for (const kind of Object.keys(KINDS) as Kind[]) {
    const fresh = report.added.filter((i) => i.kind === kind).map((i) => i.id);
    if (fresh.length) backend.set(KINDS[kind].index, JSON.stringify([...current[kind], ...fresh]));
  }
  return report;
}

/** "key openai:default", "tool github-mcp", ... for listing what a backup contains. */
export const describeItem = (it: BackupItem) => (it.kind === 'license' || it.kind === 'team' ? (it.kind === 'team' ? 'team server link' : 'license') : `${it.kind} ${it.id}`);
