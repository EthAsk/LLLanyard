#!/usr/bin/env node
// Vendor-side tool (keep the private key OFFLINE; never commit it).
//   node tools/issue-license.mjs gen-keys <dir>
//   node tools/issue-license.mjs issue --key <private.pem> --tier pro|team --days 365 [--seats 1] [--sub email-or-order-id]
import { generateKeyPairSync, createPrivateKey, sign, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const [cmd, ...rest] = process.argv.slice(2);
const opt = (n) => { const i = rest.indexOf(`--${n}`); return i >= 0 ? rest[i + 1] : undefined; };
const die = (m) => { console.error(m); process.exit(1); };

if (cmd === 'gen-keys') {
  const dir = rest[0] ?? die('Usage: gen-keys <dir>');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(path.join(dir, 'license-private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  writeFileSync(path.join(dir, 'license-public.pem'), pub);
  console.log('Keys written. Paste this into LICENSE_PUBLIC_KEY in packages/core/src/license.ts:\n\n' + pub);
} else if (cmd === 'issue') {
  const keyFile = opt('key') ?? die('--key <private.pem> required');
  const tier = opt('tier'); if (tier !== 'pro' && tier !== 'team') die('--tier must be pro or team');
  const days = Number(opt('days') ?? 365); const seats = Number(opt('seats') ?? 1);
  if (!(days > 0 && days <= 3650) || !Number.isInteger(seats) || seats < 1) die('Bad --days or --seats');
  const now = Math.floor(Date.now() / 1000);
  const payload = { v: 1, id: randomUUID(), tier, seats, iat: now, exp: now + Math.round(days * 86400), ...(opt('sub') ? { sub: opt('sub') } : {}) };
  const body = 'lly1.' + Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = sign(null, Buffer.from(body), createPrivateKey(readFileSync(keyFile)));
  console.log(`${body}.${sig.toString('base64url')}`);
} else die('Usage: gen-keys <dir> | issue --key <pem> --tier pro|team --days N [--seats N] [--sub X]');
