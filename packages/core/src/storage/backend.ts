import { createRequire } from 'node:module';
import { SERVICE } from '../constants.js';
import { FileBackend } from './file-backend.js';

/** Thin seam over the OS secret store so logic is testable without touching a real keychain. */
export interface SecretBackend {
  get(account: string): string | null;
  set(account: string, value: string): void;
  delete(account: string): boolean;
}

export class MemoryBackend implements SecretBackend {
  private m = new Map<string, string>();
  get(a: string) { return this.m.get(a) ?? null; }
  set(a: string, v: string) { this.m.set(a, v); }
  delete(a: string) { return this.m.delete(a); }
}

function explain(err: unknown): Error {
  const msg = err instanceof Error ? err.message : String(err);
  if (process.platform === 'linux' && /secret|dbus|org\.freedesktop|keyring/i.test(msg)) {
    return new Error(
      'No Secret Service available. Install and unlock a keyring ' +
        '(Debian/Ubuntu: sudo apt install gnome-keyring libsecret-1-0) and run inside a desktop/D-Bus session. ' +
        'On a headless server, use the encrypted file vault instead: set LLLANYARD_BACKEND=file.'
    );
  }
  return err instanceof Error ? err : new Error(msg);
}

/** macOS Keychain / Windows Credential Manager (DPAPI) / Linux Secret Service. */
export class KeyringBackend implements SecretBackend {
  // Loaded lazily so importing the library never fails on machines without the native module.
  private Entry: any;
  constructor(private service: string = SERVICE) {}
  private entry(account: string) {
    if (!this.Entry) {
      const require = createRequire(import.meta.url);
      try {
        this.Entry = require('@napi-rs/keyring').Entry;
      } catch {
        throw new Error('The OS keychain module (@napi-rs/keyring) is not installed. Run "npm install" first.');
      }
    }
    return new this.Entry(this.service, account);
  }
  get(account: string): string | null {
    try { return this.entry(account).getPassword() ?? null; } catch (e) { throw explain(e); }
  }
  set(account: string, value: string): void {
    try { this.entry(account).setPassword(value); } catch (e) { throw explain(e); }
  }
  delete(account: string): boolean {
    try { return Boolean(this.entry(account).deletePassword()); } catch (e) { throw explain(e); }
  }
}

let shared: SecretBackend | undefined;
export const backendKind = () => process.env.LLLANYARD_BACKEND ?? 'keychain';
/** The backend every store uses: the OS keychain by default, or the encrypted file vault with LLLANYARD_BACKEND=file. */
export function defaultBackend(): SecretBackend {
  if (shared) return shared;
  const kind = backendKind();
  if (kind === 'file') shared = new FileBackend();
  else if (kind === 'keychain') shared = new KeyringBackend();
  else throw new Error(`Unknown LLLANYARD_BACKEND "${kind}" (use keychain or file).`);
  return shared;
}
