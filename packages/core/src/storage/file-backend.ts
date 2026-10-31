import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { SecretBackend } from './backend.js';

/**
 * Encrypted vault for machines with no OS keychain (headless servers, containers, CI).
 *
 * One file, AES-256-GCM, key derived from a passphrase with scrypt (N=2^17). A wrong passphrase or a modified file is
 * detected (GCM tag), never silently accepted. Writes are atomic (temp file + rename) and serialised across processes
 * with a lock file. The passphrase comes from a 0600 file (LLLANYARD_VAULT_PASSPHRASE_FILE, works with systemd
 * LoadCredential / Docker secrets), the LLLANYARD_VAULT_PASSPHRASE variable, or an interactive prompt in the CLI.
 *
 * LIMIT: anyone who can read the passphrase file AND the vault as your user can decrypt it. This protects the vault at rest
 * (backups, disk images, other users), not against a process already running as the same user with access to both.
 */
const AAD = Buffer.from('lllanyard-vault-v1');
const KDF = { n: 1 << 17, r: 8, p: 1 };
export const MIN_PASSPHRASE = 12;

interface Header { v: 1; kdf: { n: number; r: number; p: number; salt: string }; nonce: string; ct: string; tag: string }

export const defaultVaultPath = () => process.env.LLLANYARD_VAULT_PATH ?? path.join(os.homedir(), '.lllanyard', 'vault.enc');

let interactivePassphrase: string | undefined;
/** The CLI calls this after prompting, so the library itself never reads a terminal. */
export function setVaultPassphrase(p: string | undefined) { interactivePassphrase = p; }

export function vaultPassphrase(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const f = env.LLLANYARD_VAULT_PASSPHRASE_FILE;
  if (f) {
    if (process.platform !== 'win32' && (statSync(f).mode & 0o077) !== 0) throw new Error(`Passphrase file ${f} is readable by other users. Fix with: chmod 600 ${f}`);
    return readFileSync(f, 'utf8').replace(/\r?\n$/, '');
  }
  return env.LLLANYARD_VAULT_PASSPHRASE ?? interactivePassphrase;
}

const sleep = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

export class FileBackend implements SecretBackend {
  private cache?: { sig: string; data: Record<string, string> };
  private key?: { salt: string; k: Buffer };
  constructor(private file: string = defaultVaultPath(), private passphrase: () => string | undefined = () => vaultPassphrase()) {}

  exists() { return existsSync(this.file); }

  private derive(salt: Buffer, kdf = KDF): Buffer {
    const pass = this.passphrase();
    if (!pass) throw new Error('The file vault needs a passphrase: set LLLANYARD_VAULT_PASSPHRASE_FILE (a chmod 600 file), or run in a terminal to be prompted.');
    const id = salt.toString('base64');
    if (this.key?.salt === id) return this.key.k;
    const k = scryptSync(pass, salt, 32, { N: kdf.n, r: kdf.r, p: kdf.p, maxmem: 256 * 1024 * 1024 });
    this.key = { salt: id, k };
    return k;
  }

  private load(): Record<string, string> {
    if (!existsSync(this.file)) return {};
    const st = statSync(this.file);
    const sig = `${st.mtimeMs}:${st.size}`;
    if (this.cache?.sig === sig) return this.cache.data;
    const h = JSON.parse(readFileSync(this.file, 'utf8')) as Header;
    if (h.v !== 1) throw new Error('Unsupported vault version.');
    const salt = Buffer.from(h.kdf.salt, 'base64');
    if (h.kdf.n > 1 << 20 || h.kdf.n < 1 << 14) throw new Error('Vault KDF parameters out of range; refusing to open.');
    const d = createDecipheriv('aes-256-gcm', this.derive(salt, h.kdf), Buffer.from(h.nonce, 'base64'));
    d.setAAD(AAD); d.setAuthTag(Buffer.from(h.tag, 'base64'));
    let data: Record<string, string>;
    try { data = JSON.parse(Buffer.concat([d.update(Buffer.from(h.ct, 'base64')), d.final()]).toString('utf8')); }
    catch { throw new Error('Could not open the vault: wrong passphrase, or the file was modified.'); }
    this.cache = { sig, data };
    return data;
  }

  private save(data: Record<string, string>) {
    const dir = path.dirname(this.file);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const pass = this.passphrase();
    if (!existsSync(this.file) && (pass?.length ?? 0) < MIN_PASSPHRASE) throw new Error(`Vault passphrase must be at least ${MIN_PASSPHRASE} characters.`);
    let salt: Buffer, kdf = KDF;
    if (existsSync(this.file)) { const h = JSON.parse(readFileSync(this.file, 'utf8')) as Header; salt = Buffer.from(h.kdf.salt, 'base64'); kdf = h.kdf; }
    else salt = randomBytes(16);
    const key = this.derive(salt, kdf);
    const nonce = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key, nonce);
    c.setAAD(AAD);
    const ct = Buffer.concat([c.update(JSON.stringify(data), 'utf8'), c.final()]);
    const header: Header = { v: 1, kdf: { ...kdf, salt: salt.toString('base64') }, nonce: nonce.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
    const tmp = `${this.file}.${process.pid}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    try { writeSync(fd, JSON.stringify(header)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, this.file);
    try { chmodSync(this.file, 0o600); } catch { /* best effort on exotic filesystems */ }
    this.cache = undefined;
  }

  private locked<T>(fn: () => T): T {
    mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const lock = this.file + '.lock';
    for (let i = 0; ; i++) {
      try { closeSync(openSync(lock, 'wx', 0o600)); break; }
      catch (e: any) {
        if (e.code !== 'EEXIST') throw e;
        try { if (Date.now() - statSync(lock).mtimeMs > 10_000) unlinkSync(lock); } catch { /* raced; retry */ }
        if (i > 200) throw new Error('The vault is locked by another process.');
        sleep(25);
      }
    }
    try { return fn(); } finally { try { unlinkSync(lock); } catch { /* */ } }
  }

  get(account: string): string | null { const v = this.load()[account]; return v === undefined ? null : v; }
  set(account: string, value: string): void { this.locked(() => { this.cache = undefined; const d = this.load(); d[account] = value; this.save(d); }); }
  delete(account: string): boolean {
    return this.locked(() => {
      this.cache = undefined;
      const d = this.load();
      if (!(account in d)) return false;
      delete d[account]; this.save(d); return true;
    });
  }
}
