const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);

export interface ServeOptions { port?: number; host?: string; tls?: { cert: string | Buffer; key: string | Buffer }; allowedHosts?: string[] }

/** Rules for exposing the proxy beyond this machine. Pure so it can be tested; startProxy enforces it. */
export function checkServeOptions(o: ServeOptions, tier: 'free' | 'pro' | 'team'): void {
  if (!o.host || LOOPBACK.has(o.host)) return;
  if (tier === 'free') throw new Error('Sharing the proxy beyond this computer needs Pro (your own devices) or Team (your team). See: lllanyard license activate');
  if (!o.tls) throw new Error('A shared proxy must use TLS: pass --tls-cert and --tls-key. Plain HTTP would expose agent tokens on the network.');
  if (!o.allowedHosts?.length) throw new Error('Pass --allow-host <name> with the DNS name your team uses to reach this server.');
}

