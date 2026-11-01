import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { defaultBackend, type SecretBackend } from './storage/backend.js';
import { assertName, StoreError } from './storage/keyring-store.js';
import type { AgentIdentity } from './storage/agents.js';
import type { Tier } from './license.js';

/**
 * Pro: your own devices reach this computer's proxy as paired devices. Each device is paired once with a short code,
 * gets its own token, and that token only works together with the machine ID of the computer it was paired on
 * (sent by LLLanyard on that device). A copied token does not work on another computer.
 *
 * The machine ID is reported by the device, so this stops a token being passed around; it is not proof against
 * someone who deliberately fakes the ID.
 */

/** Paired devices per plan. Free can't share the proxy at all; Team has no device limit. */
export const DEVICE_LIMITS: Record<Tier, number> = { free: 0, pro: 3, team: Number.POSITIVE_INFINITY };

/** The header a paired device sends its machine ID in. */
export const MACHINE_HEADER = 'x-lllanyard-machine';

const sha = (s: string) => createHash('sha256').update(s).digest('hex');

/** Reads this computer's hardware or OS install ID. Never sent as-is: see machineId(). */
export function rawMachineId(platform: NodeJS.Platform = process.platform): string {
  try {
    if (platform === 'darwin') {
      const o = execFileSync('/usr/sbin/ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], { encoding: 'utf8', timeout: 5000 });
      const m = /"IOPlatformUUID"\s*=\s*"([^"]+)"/.exec(o);
      if (m) return m[1]!;
    } else if (platform === 'win32') {
      const o = execFileSync('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'], { encoding: 'utf8', timeout: 5000, windowsHide: true });
      const m = /MachineGuid\s+REG_SZ\s+(\S+)/i.exec(o);
      if (m) return m[1]!;
    } else {
      for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) {
        try { const v = readFileSync(f, 'utf8').trim(); if (v) return v; } catch { /* next */ }
      }
    }
  } catch { /* fall through */ }
  throw new StoreError("Couldn't read this computer's machine ID, so it can't be paired as a device.");
}

/** What a device sends: a hash of its machine ID, so the ID itself never leaves the device. */
export const machineId = (raw: string = rawMachineId()) => sha('lllanyard-device:' + raw.trim().toLowerCase());

const MACHINE_RE = /^[0-9a-f]{64}$/;
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O or 1/I
const CODE_MINUTES = 10;
const normCode = (c: string) => c.toUpperCase().replace(/[^A-Z0-9]/g, '');

interface DeviceRecord { name: string; machine: string; tokenHash: string; pairedAt: string; noKeys?: boolean }
interface Invite { name: string; codeHash: string; expires: string; noKeys?: boolean }

/** A paired device as the proxy sees it. keys: may it fetch real keys for one run (exec --remote)? */
export type DeviceIdentity = AgentIdentity & { device: true; keys: boolean };
interface State { devices: DeviceRecord[]; invites: Invite[] }

const SLOT = '__devices__';

export class DeviceStore {
  constructor(private backend: SecretBackend = defaultBackend(), private now: () => number = Date.now) {}

  private read(): State {
    const raw = this.backend.get(SLOT);
    if (!raw) return { devices: [], invites: [] };
    try {
      const v = JSON.parse(raw) as State;
      if (Array.isArray(v.devices) && Array.isArray(v.invites)) return v;
    } catch { /* below */ }
    throw new StoreError('The device list is corrupted; refusing to overwrite it.');
  }
  private write(s: State) {
    s.invites = s.invites.filter((i) => Date.parse(i.expires) > this.now());
    this.backend.set(SLOT, JSON.stringify(s));
  }

  list(): { name: string; pairedAt: string; pending: boolean; expires?: string; keys: boolean }[] {
    const s = this.read();
    return [
      ...s.devices.map((d) => ({ name: d.name, pairedAt: d.pairedAt, pending: false, keys: !d.noKeys })),
      ...s.invites.filter((i) => Date.parse(i.expires) > this.now()).map((i) => ({ name: i.name, pairedAt: '', pending: true, expires: i.expires, keys: !i.noKeys })),
    ];
  }

  /** Paired devices plus unexpired codes: what counts towards the plan's limit. */
  used(): number { return this.list().length; }

  /**
   * Makes a one-time pairing code for a new device (valid 10 minutes). Replaces an unused code for the same name.
   * Re-pairing a name that is already paired replaces that device when the code is used. noKeys: the device can only
   * go through this computer's proxy and never receives a key (exec --remote then works as relay does).
   */
  invite(name: string, limit: number, opts: { noKeys?: boolean } = {}): { code: string; expires: string } {
    assertName('device name', name);
    const n = name.toLowerCase();
    const s = this.read();
    s.invites = s.invites.filter((i) => i.name !== n && Date.parse(i.expires) > this.now());
    const others = s.devices.filter((d) => d.name !== n).length + s.invites.length;
    if (others >= limit) {
      throw new StoreError(limit === 0
        ? 'Pairing devices needs Pro (up to 3 of your own devices) or Team. See: lllanyard license activate'
        : `Your plan allows ${limit} devices. Remove one first: lllanyard device remove <name>`);
    }
    let code = '';
    for (let i = 0; i < 8; i++) code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
    const expires = new Date(this.now() + CODE_MINUTES * 60_000).toISOString();
    s.invites.push({ name: n, codeHash: sha('code:' + code), expires, ...(opts.noKeys ? { noKeys: true } : {}) });
    this.write(s);
    return { code: `${code.slice(0, 4)}-${code.slice(4)}`, expires };
  }

  /** Uses a pairing code: ties a new token to the device's machine ID. Returns the token (shown to the device once). */
  pair(code: string, machine: string): { name: string; token: string } {
    if (!MACHINE_RE.test(machine)) throw new StoreError('Missing or malformed machine ID.');
    const s = this.read();
    const h = Buffer.from(sha('code:' + normCode(code)), 'hex');
    const inv = s.invites.find((i) => Date.parse(i.expires) > this.now() && timingSafeEqual(Buffer.from(i.codeHash, 'hex'), h));
    if (!inv) throw new StoreError('That pairing code is wrong or has expired. Make a new one on the main computer: lllanyard device add <name>');
    const clash = s.devices.find((d) => d.machine === machine && d.name !== inv.name);
    if (clash) throw new StoreError(`This computer is already paired as "${clash.name}".`);
    const token = 'lly_dev_' + randomBytes(32).toString('base64url');
    s.invites = s.invites.filter((i) => i !== inv);
    s.devices = s.devices.filter((d) => d.name !== inv.name);
    s.devices.push({ name: inv.name, machine, tokenHash: sha(token), pairedAt: new Date(this.now()).toISOString(), ...(inv.noKeys ? { noKeys: true } : {}) });
    this.write(s);
    return { name: inv.name, token };
  }

  remove(name: string): boolean {
    const n = name.toLowerCase();
    const s = this.read();
    const before = s.devices.length + s.invites.length;
    s.devices = s.devices.filter((d) => d.name !== n);
    s.invites = s.invites.filter((i) => i.name !== n);
    this.write(s);
    return s.devices.length + s.invites.length < before;
  }

  /**
   * Snapshot check for the proxy. A device's token is accepted only with the machine ID it was paired with.
   * Devices beyond the plan's limit (e.g. after moving from Team to Pro) stop working, oldest pairings kept.
   */
  verifier(limit: number): (token: string, machine: string | undefined) => DeviceIdentity | 'wrong-machine' | null {
    const devices = this.read().devices.slice().sort((a, b) => a.pairedAt.localeCompare(b.pairedAt)).slice(0, Number.isFinite(limit) ? limit : undefined);
    const records = devices.map((d) => ({ name: d.name, machine: d.machine, keys: !d.noKeys, hash: Buffer.from(d.tokenHash, 'hex') }));
    return (token, machine) => {
      if (!token.startsWith('lly_dev_')) return null;
      const h = Buffer.from(sha(token), 'hex');
      const r = records.find((x) => timingSafeEqual(x.hash, h));
      if (!r) return null;
      if (!machine || machine.length !== r.machine.length || !timingSafeEqual(Buffer.from(machine), Buffer.from(r.machine))) return 'wrong-machine';
      return { name: `device:${r.name}`, client: 'default', device: true, keys: r.keys };
    };
  }
}

/**
 * On a paired device: where its keys live (the main computer) and its device token. Kept in this device's
 * keychain. Holds no API keys.
 */
export interface RemoteLink { url: string; token: string; name: string; ca?: string; pairedAt: string; relayToken?: string }

const REMOTE = '__remote__';

export class RemoteStore {
  constructor(private backend: SecretBackend = defaultBackend()) {}
  get(): RemoteLink | null {
    const raw = this.backend.get(REMOTE);
    if (!raw) return null;
    try { const v = JSON.parse(raw) as RemoteLink; return typeof v.url === 'string' && typeof v.token === 'string' ? v : null; } catch { return null; }
  }
  set(link: Omit<RemoteLink, 'pairedAt'> & { pairedAt?: string }): RemoteLink {
    if (!/^lly_dev_[A-Za-z0-9_-]{16,}$/.test(link.token)) throw new StoreError('That is not a device token.');
    const v: RemoteLink = { ...link, pairedAt: link.pairedAt ?? new Date().toISOString() };
    this.backend.set(REMOTE, JSON.stringify(v));
    return v;
  }
  /** The fixed token tools on this device use for the long-running relay (lllanyard relay). Made on first use. */
  relayToken(): string {
    const link = this.get() ?? (() => { throw new StoreError('This computer is not paired. See: lllanyard device join'); })();
    if (link.relayToken) return link.relayToken;
    const t = 'lly_local_' + randomBytes(24).toString('base64url');
    this.set({ ...link, relayToken: t });
    return t;
  }
  remove(): boolean { return this.backend.delete(REMOTE); }
}
