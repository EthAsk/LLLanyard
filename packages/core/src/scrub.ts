import { Transform } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';

/**
 * Every form a leaked secret is likely to take in output: as-is, base64 / base64url (at all three byte alignments,
 * so it is caught even when embedded in a larger encoded blob), hex, and URL-encoded.
 * Only characters fully determined by the secret are matched, which keeps false positives negligible.
 */
export function secretVariants(secret: string): string[] {
  const out = new Set<string>([secret]);
  const buf = Buffer.from(secret, 'utf8');
  for (let k = 0; k < 3; k++) {
    const enc = Buffer.concat([Buffer.alloc(k, 0x41), buf]).toString('base64').replace(/=+$/, '');
    const n = k + buf.length;
    const r = n % 3;
    const end = Math.floor(n / 3) * 4 + (r === 0 ? 0 : r === 1 ? 1 : 2);
    const piece = enc.slice([0, 2, 3][k]!, end);
    if (piece.length >= 12) {
      out.add(piece);
      out.add(piece.replace(/\+/g, '-').replace(/\//g, '_'));
    }
  }
  const hex = buf.toString('hex');
  out.add(hex);
  out.add(hex.toUpperCase());
  const url = encodeURIComponent(secret);
  if (url !== secret) out.add(url);
  return [...out].filter((s) => s.length >= 8);
}

/** A Transform that also emits 'redacted' (count: number) whenever it replaces secrets. */
export type Scrubber = Transform;

/**
 * Streaming redaction of known secrets from text output (UTF-8). Emits a 'redacted' event with the number of
 * replacements, so callers can warn or stop a tool that is leaking.
 * - Output goes out as soon as it arrives, except a tail that could be the start of a secret (it ends with a prefix of
 *   one). So prompts without a newline (`Read-Host`, `input()`) show immediately, and newline-delimited protocols
 *   (MCP over stdio) never stall, while a secret split across chunks is still caught.
 */
export function createScrubber(secrets: string[], replacement = '[REDACTED]'): Scrubber {
  const list = [...new Set(secrets.filter((s) => s.length >= 8).flatMap(secretVariants))].sort((a, b) => b.length - a.length);
  const maxLen = list.reduce((m, s) => Math.max(m, s.length), 0);
  // Length of the longest tail of s that some variant starts with (it might be completed by the next chunk).
  const unsafeTail = (s: string) => {
    for (let k = Math.min(maxLen - 1, s.length); k > 0; k--) {
      const tail = s.slice(s.length - k);
      if (list.some((x) => x.startsWith(tail))) return k;
    }
    return 0;
  };
  const dec = new StringDecoder('utf8');
  let pending = '';

  const scrub = (s: string) => {
    let n = 0;
    for (const x of list) {
      if (!s.includes(x)) continue;
      const parts = s.split(x);
      n += parts.length - 1;
      s = parts.join(replacement);
    }
    if (n) t.emit('redacted', n);
    return s;
  };

  const t: Transform = new Transform({
    transform(chunk: Buffer | string, _enc, cb) {
      const s = scrub(pending + (typeof chunk === 'string' ? chunk : dec.write(chunk)));
      const cut = s.length - unsafeTail(s);
      pending = s.slice(cut);
      cb(null, s.slice(0, cut));
    },
    flush(cb) {
      pending += dec.end();
      cb(null, scrub(pending));
    },
  });
  return t as Scrubber;
}
