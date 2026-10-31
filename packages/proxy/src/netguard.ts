import dns from 'node:dns';
import { isIP } from 'node:net';

/** True only for globally routable addresses. Loopback, private, link-local (cloud metadata), CGNAT etc. are false. */
export function isPublicAddress(addr: string): boolean {
  const ip = addr.replace(/^\[|\]$/g, '').toLowerCase();
  const fam = isIP(ip);
  if (fam === 4) {
    const [a, b] = ip.split('.').map(Number) as [number, number];
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false; // multicast + reserved
    if (a === 192 && b === 0) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    return true;
  }
  if (fam === 6) {
    if (ip === '::' || ip === '::1') return false;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
    if (mapped) return isPublicAddress(mapped[1]!);
    const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(ip);
    if (hex) { const hi = parseInt(hex[1]!, 16), lo = parseInt(hex[2]!, 16); return isPublicAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`); }
    const first = parseInt(ip.split(':')[0] || '0', 16);
    if ((first & 0xfe00) === 0xfc00) return false; // fc00::/7 unique local
    if ((first & 0xffc0) === 0xfe80) return false; // fe80::/10 link-local
    if ((first & 0xff00) === 0xff00) return false; // multicast
    return true;
  }
  return false;
}

/** dns.lookup replacement that refuses to connect to non-public addresses (SSRF / DNS-rebinding defence). */
export function safeLookup(hostname: string, options: any, callback: any): void {
  const opts = typeof options === 'function' ? {} : options;
  const cb = typeof options === 'function' ? options : callback;
  dns.lookup(hostname, opts, (err: any, address: any, family: any) => {
    if (err) return cb(err, address, family);
    const list: { address: string }[] = Array.isArray(address) ? address : [{ address }];
    if (!list.length || list.some((a) => !isPublicAddress(a.address))) {
      const e: NodeJS.ErrnoException = new Error(`Blocked: ${hostname} resolves to a non-public address`);
      e.code = 'EBLOCKED';
      return cb(e, address, family);
    }
    cb(null, address, family);
  });
}
