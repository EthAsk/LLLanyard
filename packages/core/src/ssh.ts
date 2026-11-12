import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { RunResult } from './mcp-server.js';
import { minimalEnv } from './run.js';
import { createScrubber } from './scrub.js';
import { defaultBackend, type SecretBackend } from './storage/backend.js';
import { assertName, StoreError } from './storage/keyring-store.js';

/**
 * SSH logins kept in the keychain: a host, a user, and either a private key (with its passphrase, if it has one) or a
 * password. The secret is never put in a file in your home folder, a command line or an environment variable of the
 * shell: a key is loaded into a throwaway ssh-agent for the length of one session, a password is handed to ssh through
 * its askpass helper.
 */
export interface SshEntry {
  name: string;
  host: string;
  user: string;
  port: number;
  auth: 'key' | 'password';
  secret: string; // private key (PEM / OpenSSH text) or password
  passphrase?: string; // for an encrypted private key
  publicKey?: string; // one line, to paste into the server's authorized_keys
  createdAt: string;
}
export type SshMeta = Omit<SshEntry, 'secret' | 'passphrase'> & { hasPassphrase: boolean; last4: string };

const INDEX = '__ssh__';
const HOST_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$/; // no leading "-": a host must never be read as an ssh option
const USER_RE = /^[A-Za-z0-9_.][A-Za-z0-9_.@-]{0,63}$/;
export const SSH_RESERVED = new Set(['add', 'generate', 'list', 'remove', 'pubkey', 'with', 'connect', 'help']);

export function assertSshName(name: string) {
  assertName('connection name', name);
  if (SSH_RESERVED.has(name.toLowerCase())) throw new StoreError(`"${name}" is a lllanyard ssh command; pick another name.`);
}

export const PRIVATE_KEY_RE = /-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----[\s\S]+?-----END \1PRIVATE KEY-----/;

/** Tidies pasted key text: unix line endings, no stray spaces, exactly one trailing newline. Throws if it isn't a private key. */
export function normaliseKey(text: string): string {
  const t = text.replace(/\r\n?/g, '\n').trim();
  const m = PRIVATE_KEY_RE.exec(t);
  if (!m) throw new StoreError('That does not look like a private key (expected -----BEGIN OPENSSH PRIVATE KEY----- ... -----END ...).');
  return m[0]!.split('\n').map((l) => l.trim()).join('\n') + '\n';
}

/** Whether a private key needs a passphrase. Reads the key text only; nothing is run. */
export function keyIsEncrypted(key: string): boolean {
  if (/ENCRYPTED PRIVATE KEY-----|Proc-Type:\s*4,ENCRYPTED/.test(key)) return true; // PKCS#8 and old-style PEM
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/.exec(key);
  if (!m) return false;
  const buf = Buffer.from(m[1]!.replace(/\s+/g, ''), 'base64');
  const magic = 'openssh-key-v1\0';
  if (buf.subarray(0, magic.length).toString('latin1') !== magic) return false;
  const len = buf.readUInt32BE(magic.length);
  return buf.subarray(magic.length + 4, magic.length + 4 + len).toString('latin1') !== 'none';
}

export function validateSsh(v: unknown): SshEntry {
  const e = v as Partial<SshEntry> | null;
  if (!e || typeof e !== 'object') throw new StoreError('SSH record is malformed.');
  assertSshName(String(e.name));
  if (typeof e.host !== 'string' || !HOST_RE.test(e.host)) throw new StoreError('Invalid host name or address.');
  if (typeof e.user !== 'string' || !USER_RE.test(e.user)) throw new StoreError('Invalid user name.');
  if (!Number.isInteger(e.port) || e.port! < 1 || e.port! > 65535) throw new StoreError('Port must be 1-65535.');
  if (e.auth !== 'key' && e.auth !== 'password') throw new StoreError('Unknown SSH login type.');
  if (typeof e.secret !== 'string' || !e.secret || e.secret.length > 20_000) throw new StoreError('SSH secret is missing or too long.');
  if (e.auth === 'key') normaliseKey(e.secret);
  else if (/[\r\n\0]/.test(e.secret)) throw new StoreError('A password cannot contain line breaks.');
  if (e.passphrase !== undefined && (typeof e.passphrase !== 'string' || /[\r\n\0]/.test(e.passphrase))) throw new StoreError('Invalid passphrase.');
  if (e.publicKey !== undefined && (typeof e.publicKey !== 'string' || /[\r\n]/.test(e.publicKey.trim()) || e.publicKey.length > 2000)) throw new StoreError('Invalid public key.');
  return {
    name: e.name!, host: e.host, user: e.user, port: e.port!, auth: e.auth, secret: e.secret,
    ...(e.passphrase ? { passphrase: e.passphrase } : {}), ...(e.publicKey ? { publicKey: e.publicKey.trim() } : {}),
    createdAt: typeof e.createdAt === 'string' ? e.createdAt : new Date().toISOString(),
  };
}

const toMeta = (e: SshEntry): SshMeta => {
  const { secret, passphrase, ...rest } = e;
  return { ...rest, hasPassphrase: Boolean(passphrase), last4: e.auth === 'key' ? '' : secret.slice(-2).replace(/./g, '•') };
};

/**
 * A login is stored as one JSON record, split across several keychain entries when it is long: Windows Credential
 * Manager refuses entries over about 2.5 KB (and stores them as UTF-16), which RSA keys easily exceed.
 * A short record is stored as is; a long one is a head entry "#N" plus N chunk entries `ssh:<name>#1` ... `#N`.
 */
export const SSH_CHUNK = 900;

export function readSshRecord(backend: SecretBackend, name: string): string | null {
  const head = backend.get(`ssh:${name}`);
  if (head === null || !head.startsWith('#')) return head;
  const n = Number(head.slice(1));
  if (!Number.isInteger(n) || n < 1 || n > 64) return null;
  let out = '';
  for (let i = 1; i <= n; i++) {
    const c = backend.get(`ssh:${name}#${i}`);
    if (c === null) return null; // half-written or half-deleted: treat as missing rather than return a broken key
    out += c;
  }
  return out;
}

export function writeSshRecord(backend: SecretBackend, name: string, json: string): void {
  const old = backend.get(`ssh:${name}`);
  const oldN = old?.startsWith('#') ? Number(old.slice(1)) || 0 : 0;
  const n = json.length <= SSH_CHUNK ? 0 : Math.ceil(json.length / SSH_CHUNK);
  if (n > 64) throw new StoreError('That login is too large to store.');
  // Chunks first, head last: an interrupted write leaves the previous login (or nothing), never a mixed one.
  for (let i = 1; i <= n; i++) backend.set(`ssh:${name}#${i}`, json.slice((i - 1) * SSH_CHUNK, i * SSH_CHUNK));
  backend.set(`ssh:${name}`, n ? `#${n}` : json);
  for (let i = n + 1; i <= oldN; i++) backend.delete(`ssh:${name}#${i}`);
}

export function deleteSshRecord(backend: SecretBackend, name: string): boolean {
  const head = backend.get(`ssh:${name}`);
  const n = head?.startsWith('#') ? Number(head.slice(1)) || 0 : 0;
  const existed = backend.delete(`ssh:${name}`);
  for (let i = 1; i <= n; i++) backend.delete(`ssh:${name}#${i}`);
  return existed;
}

export class SshStore {
  constructor(private backend: SecretBackend = defaultBackend()) {}

  private ids(): string[] {
    const raw = this.backend.get(INDEX);
    if (!raw) return [];
    try { const v = JSON.parse(raw); if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v; } catch { /* */ }
    throw new StoreError('SSH index is corrupted; refusing to overwrite it. Run `lllanyard doctor`.');
  }

  /** `maxTotal` is the plan's limit; SSH logins count towards the same limit as keys (`otherCount` = keys already stored). */
  set(entry: Omit<SshEntry, 'createdAt'> & { createdAt?: string }, opts: { maxTotal?: number; otherCount?: number } = {}): SshMeta {
    const e = validateSsh({ ...entry, name: entry.name.toLowerCase() });
    const ids = this.ids();
    const exists = ids.includes(e.name);
    if (!exists && opts.maxTotal !== undefined && ids.length + (opts.otherCount ?? 0) >= opts.maxTotal)
      throw new StoreError(`Your plan allows ${opts.maxTotal} keys and SSH logins in total. Remove one or upgrade.`);
    try { writeSshRecord(this.backend, e.name, JSON.stringify(e)); }
    catch (err) { if (err instanceof StoreError) throw err; throw new StoreError(`The keychain would not store this login: ${(err as Error).message}`); }
    if (!exists) this.backend.set(INDEX, JSON.stringify([...ids, e.name]));
    return toMeta(e);
  }

  get(name: string): SshEntry | null {
    const raw = readSshRecord(this.backend, name.toLowerCase());
    if (!raw) return null;
    try { return validateSsh(JSON.parse(raw)); } catch { return null; }
  }

  list(): SshMeta[] {
    return this.ids().map((id) => this.get(id)).filter((e): e is SshEntry => e !== null).map(toMeta);
  }

  count(): number { return this.ids().length; }

  remove(name: string): boolean {
    const id = name.toLowerCase();
    const existed = deleteSshRecord(this.backend, id);
    this.backend.set(INDEX, JSON.stringify(this.ids().filter((x) => x !== id)));
    return existed;
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------------------------------------

export const knownHostsPath = (home = os.homedir()) => path.join(home, '.lllanyard', 'ssh_known_hosts');

export interface SshSession {
  env: NodeJS.ProcessEnv; // give this to ssh (and whatever else should use these logins)
  close(): void;
}

function askpassScript(dir: string, platform: NodeJS.Platform): string {
  if (platform === 'win32') {
    const f = path.join(dir, 'askpass.cmd');
    writeFileSync(f, '@echo off\r\nsetlocal EnableDelayedExpansion\r\necho(!LLLANYARD_ASKPASS_SECRET!\r\n');
    return f;
  }
  const f = path.join(dir, 'askpass.sh');
  writeFileSync(f, '#!/bin/sh\nprintf \'%s\\n\' "$LLLANYARD_ASKPASS_SECRET"\n', { mode: 0o700 });
  chmodSync(f, 0o700);
  return f;
}

export interface SessionDeps {
  platform?: NodeJS.Platform;
  base?: NodeJS.ProcessEnv;
  tmp?: string;
}

/**
 * Prepares ssh to use the given logins and returns the environment to run it with.
 * - key logins: macOS and Linux start a private ssh-agent (a socket only you can reach) and load each key into it,
 *   so the key is never written to a file; Windows has no such agent socket, so the key goes in a 0600 file in a
 *   private temporary folder for the session. Either way it is gone when the session ends.
 * - a password login (one only) is answered by an askpass helper that reads it from this session's environment.
 */
export async function openSshSession(entries: SshEntry[], deps: SessionDeps = {}): Promise<SshSession> {
  const platform = deps.platform ?? process.platform;
  const base = deps.base ?? process.env;
  const keys = entries.filter((e) => e.auth === 'key');
  const passwords = entries.filter((e) => e.auth === 'password');
  if (passwords.length > 1) throw new StoreError('Only one password login can be used in a session (ssh gives the helper no way to tell them apart).');
  if (passwords.length && keys.length) throw new StoreError('Mixing a password login with key logins in one session is not supported.');

  const dir = mkdtempSync(path.join(deps.tmp ?? os.tmpdir(), 'lly-ssh-'));
  try { chmodSync(dir, 0o700); } catch { /* not ours to chmod on some filesystems */ }
  const env: NodeJS.ProcessEnv = { ...minimalEnv(base) };
  let agent: ReturnType<typeof spawn> | null = null;
  const close = () => {
    try { agent?.kill(); } catch { /* already gone */ }
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  };

  try {
    const askpass = askpassScript(dir, platform);
    const askEnv = (secret: string) => ({ SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: 'force', DISPLAY: base.DISPLAY ?? ':0', LLLANYARD_ASKPASS_SECRET: secret });

    if (passwords.length) {
      Object.assign(env, askEnv(passwords[0]!.secret));
      return { env, close };
    }
    if (!keys.length) return { env, close };

    if (platform === 'win32') {
      if (keys.length > 1) throw new StoreError('On Windows one key login can be used at a time.');
      const k = keys[0]!;
      const f = path.join(dir, 'id');
      writeFileSync(f, k.secret, { mode: 0o600 });
      env.LLLANYARD_SSH_KEYFILE = f;
      if (k.passphrase) Object.assign(env, askEnv(k.passphrase));
      return { env, close };
    }

    const sock = path.join(dir, 'a.sock');
    agent = spawn('ssh-agent', ['-D', '-a', sock], { stdio: 'ignore', env: minimalEnv(base) });
    agent.on('error', () => { /* reported below as a missing socket */ });
    for (let i = 0; i < 100 && !existsSync(sock); i++) await new Promise((r) => setTimeout(r, 30));
    if (!existsSync(sock)) throw new StoreError('Could not start ssh-agent. Is OpenSSH installed? (`ssh-agent` must be on your PATH.)');
    env.SSH_AUTH_SOCK = sock;
    for (const k of keys) {
      const r = spawnSync('ssh-add', ['-'], {
        input: k.secret, encoding: 'utf8', env: { ...env, ...(k.passphrase ? askEnv(k.passphrase) : {}) }, timeout: 20_000,
      });
      if (r.status !== 0) throw new StoreError(`Could not load the key for "${k.name}"${k.passphrase ? '' : ' (it may need a passphrase; re-add it with one)'}: ${(r.stderr || r.error?.message || '').trim()}`);
    }
    return { env, close };
  } catch (e) {
    close();
    throw e;
  }
}

/** ssh arguments to reach one stored login. Everything after the target is the remote command. */
export function sshArgs(e: SshEntry, session: SshSession, extra: string[] = [], home = os.homedir()): string[] {
  const kh = knownHostsPath(home);
  try { mkdirSync(path.dirname(kh), { recursive: true, mode: 0o700 }); } catch { /* ssh will say */ }
  const a = ['-o', `UserKnownHostsFile=${kh}`, '-o', 'StrictHostKeyChecking=accept-new', '-p', String(e.port)];
  if (e.auth === 'password') a.push('-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'PubkeyAuthentication=no');
  else {
    a.push('-o', 'PasswordAuthentication=no');
    if (session.env.LLLANYARD_SSH_KEYFILE) a.push('-o', 'IdentitiesOnly=yes', '-i', session.env.LLLANYARD_SSH_KEYFILE);
    else a.push('-o', `IdentityAgent=${session.env.SSH_AUTH_SOCK}`);
  }
  a.push(`${e.user}@${e.host}`, ...extra);
  return a;
}

/** Makes a new ed25519 key pair with ssh-keygen in a private folder and returns it; nothing is left on disk. */
export function generateKey(comment: string, tmp = os.tmpdir()): { privateKey: string; publicKey: string } {
  const dir = mkdtempSync(path.join(tmp, 'lly-keygen-'));
  try {
    chmodSync(dir, 0o700);
    const f = path.join(dir, 'id');
    const r = spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', comment, '-f', f], { encoding: 'utf8' });
    if (r.status !== 0) throw new StoreError(`ssh-keygen failed: ${(r.stderr || r.error?.message || 'is OpenSSH installed?').trim()}`);
    return { privateKey: normaliseKey(readFileSync(f, 'utf8')), publicKey: readFileSync(f + '.pub', 'utf8').trim() };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

/** The public key for a private key without a passphrase (used to show what to put in authorized_keys). */
export function publicKeyOf(privateKey: string, tmp = os.tmpdir()): string | undefined {
  const dir = mkdtempSync(path.join(tmp, 'lly-keygen-'));
  try {
    chmodSync(dir, 0o700);
    const f = path.join(dir, 'id');
    writeFileSync(f, privateKey, { mode: 0o600 });
    const r = spawnSync('ssh-keygen', ['-y', '-P', '', '-f', f], { encoding: 'utf8', timeout: 10_000 });
    return r.status === 0 ? r.stdout.trim() : undefined;
  } catch { return undefined; } finally { rmSync(dir, { recursive: true, force: true }); }
}

export const SSH_COMMAND_MAX = 1500;

/** The text of the confirmation dialog for an AI asking to run a command on a server. */
export function describeSshRun(e: Pick<SshEntry, 'name' | 'user' | 'host' | 'port'>, command: string, requester = 'Claude'): string {
  return [
    `${requester} wants to run a command on a server.`, '',
    `Login: ${e.name} (${e.user}@${e.host}${e.port === 22 ? '' : ':' + e.port})`,
    `Command: ${command}`,
    '', 'It runs with your stored login. Only click Run if you expect this command.',
  ].join('\n');
}

/**
 * Runs one command on the server (no terminal, no input) and returns what it printed. The login's own secrets are
 * redacted from the output. Stops after `timeoutSec`.
 */
export async function runSshCommand(e: SshEntry, command: string, opts: { timeoutSec?: number; limit?: number; session?: SessionDeps } = {}): Promise<RunResult> {
  if (!command.trim() || command.length > SSH_COMMAND_MAX || /\0/.test(command)) throw new StoreError(`Give a command of 1-${SSH_COMMAND_MAX} characters.`);
  const session = await openSshSession([e], opts.session);
  const limit = opts.limit ?? 100_000;
  const secrets = [e.auth === 'password' ? e.secret : '', e.passphrase ?? '', ...(e.auth === 'key' ? e.secret.split('\n') : [])].filter(Boolean);
  const scrub = createScrubber(secrets);
  let output = '', truncated = false, timedOut = false;
  scrub.on('data', (d: Buffer | string) => { output += String(d); if (output.length > limit) { output = output.slice(-limit); truncated = true; } });
  const done = new Promise<void>((r) => scrub.on('end', () => r()));
  try {
    const args = ['-T', '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', ...(e.auth === 'key' ? ['-o', 'BatchMode=yes'] : []), ...sshArgs(e, session, [command])];
    const code = await new Promise<number>((resolve) => {
      const child = spawn('ssh', args, { stdio: ['ignore', 'pipe', 'pipe'], env: session.env });
      const timer = setTimeout(() => { timedOut = true; child.kill(); }, (opts.timeoutSec ?? 600) * 1000);
      child.stdout.on('data', (d) => scrub.write(d));
      child.stderr.on('data', (d) => scrub.write(d));
      child.on('error', (err) => { scrub.write(`could not start ssh: ${err.message}\n`); clearTimeout(timer); resolve(127); });
      child.on('close', (c) => { clearTimeout(timer); resolve(c ?? 1); });
    });
    scrub.end();
    await done;
    return { exitCode: code, output, truncated, timedOut };
  } finally { session.close(); }
}
