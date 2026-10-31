import test from 'node:test';
import assert from 'node:assert/strict';
import { isPublicAddress } from '../src/netguard.js';

test('isPublicAddress: blocks loopback, private, link-local/metadata, CGNAT, multicast, ULA and mapped forms', () => {
  const blocked = ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '224.0.0.1', '255.255.255.255', '::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:a9fe:a9fe', 'not-an-ip'];
  for (const a of blocked) assert.equal(isPublicAddress(a), false, a);
  const ok = ['8.8.8.8', '1.1.1.1', '172.32.0.1', '172.15.0.1', '100.63.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'];
  for (const a of ok) assert.equal(isPublicAddress(a), true, a);
});
