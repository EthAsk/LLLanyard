import {
  AgentStore, DEFAULT_PORT, LicenseStore, createUsageLog, KeyringStore, ProviderStore, allProviders, type ProviderConfig,
} from '@lllanyard/core';
import { createProxy, type ProviderDef } from './server.js';
import { fromConfig } from './providers.js';

export { createProxy } from './server.js';
export { fromConfig } from './providers.js';
export { isPublicAddress } from './netguard.js';
export { startEgressProxy, hostAllowed } from './egress.js';
export { AuthGuard } from './ratelimit.js';
export { checkServeOptions } from './serve-options.js';
export type { ServeOptions } from './serve-options.js';
export type { EgressProxy, EgressOptions } from './egress.js';
export type { ProxyDeps, ProviderDef, ProviderSource } from './server.js';

import { checkServeOptions, type ServeOptions } from './serve-options.js';

/** Starts the proxy. By default loopback only; a non-loopback host needs a Pro license, TLS and --allow-host. */
export function startProxy(opts: ServeOptions = {}): Promise<{ port: number; close: () => void }> {
  const host = opts.host ?? '127.0.0.1';
  checkServeOptions(opts, new LicenseStore().status().tier);
  const port = opts.port ?? Number(process.env.LLLANYARD_PORT ?? DEFAULT_PORT);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');

  const agents = new AgentStore();
  const providerStore = new ProviderStore();
  const build = (): Map<string, ProviderDef> => {
    const m = new Map<string, ProviderDef>();
    const cfgs: Record<string, ProviderConfig> = allProviders(providerStore);
    for (const [id, c] of Object.entries(cfgs)) m.set(id, fromConfig(c));
    return m;
  };
  let verify = agents.verifier();
  let providers = build();
  // Picks up new/revoked agents and provider changes within ~10s without a keychain read per request.
  const timer = setInterval(() => {
    try { verify = agents.verifier(); providers = build(); } catch (e) { process.stderr.write(`refresh failed: ${(e as Error).message}\n`); }
  }, 10_000);
  timer.unref();

  const usage = createUsageLog();
  const server = createProxy({
    store: new KeyringStore(),
    log: (r) => { process.stdout.write(JSON.stringify(r) + '\n'); usage.write(r); },
    verify: (t) => verify(t),
    providers: (id) => providers.get(id),
    rpm: Number(process.env.LLLANYARD_RPM ?? 120),
    allowOrigin: process.env.LLLANYARD_ALLOW_ORIGIN === '1',
    tls: opts.tls, allowedHosts: opts.allowedHosts,
  });

  return new Promise((resolve, reject) => {
    server.once('error', (e: NodeJS.ErrnoException) =>
      reject(new Error(e.code === 'EADDRINUSE' ? `Port ${port} is already in use (set --port or LLLANYARD_PORT)` : e.message)));
    server.listen(port, host, () => resolve({ port, close: () => { clearInterval(timer); server.close(); } }));
  });
}
