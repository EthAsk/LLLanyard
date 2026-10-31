import type { ProviderConfig } from '@lllanyard/core'; // type-only
import type { ProviderDef } from './server.js';

/** Turns a stored provider config into the proxy's runtime definition. */
export function fromConfig(c: ProviderConfig): ProviderDef {
  const a = c.auth;
  return {
    upstream: c.upstream,
    allowLocal: c.allowLocal,
    inject: a.type === 'bearer'
      ? (h, k) => { h['authorization'] = `Bearer ${k}`; }
      : (h, k) => { h[a.name.toLowerCase()] = (a.prefix ?? '') + k; },
  };
}
