import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { createProxy, type ProviderDef } from '../src/server.js';
import { MemoryBackend, TeamStore, normaliseTeamUrl } from '../../core/src/index.js';

// The team server's certificate: for 127.0.0.1, so the member's proxy can reach it in the test.
const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-team-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'), '-days', '2', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
const tls = { cert: readFileSync(path.join(dir, 'c.pem')), key: readFileSync(path.join(dir, 'k.pem')) };

const listen = async (srv: http.Server) => { await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r)); return (srv.address() as AddressInfo).port; };

/** A fake API: records the key each request arrived with. */
async function api() {
  const seen: { key: string | undefined; auth: string | undefined; path: string }[] = [];
  const srv = http.createServer((q, r) => { seen.push({ key: q.headers['x-key'] as string | undefined, auth: q.headers.authorization, path: q.url ?? '' }); r.end('ok'); });
  return { seen, port: await listen(srv), close: () => srv.close() };
}
const provider = (port: number): ProviderDef => ({ upstream: `http://127.0.0.1:${port}`, allowLocal: true, inject: (h, k) => { h['x-key'] = k; } });

async function setup(memberAgentProviders?: string[], linked = true) {
  const personalApi = await api();
  const teamApi = await api();

  // The team server: holds the shared keys for alpha, beta and gamma; knows this member by their team token.
  const teamLogs: any[] = [];
  const team = createProxy({
    store: { get: (p) => `TEAM-${p.toUpperCase()}-KEY` },
    verify: (t) => (t === 'lly_member_team_token_0123456789' ? { name: 'alice', client: 'default' } : null),
    providers: { alpha: provider(teamApi.port), beta: provider(teamApi.port), gamma: provider(teamApi.port) },
    tls, log: (r) => teamLogs.push(r),
  });
  const teamPort = await listen(team as http.Server);

  // Alice's own LLLanyard: a personal key for alpha only, and no idea gamma exists.
  const memberLogs: any[] = [];
  const member = createProxy({
    store: { get: (p) => (p === 'alpha' ? 'PERSONAL-ALPHA-KEY' : null) },
    verify: (t) => (t === 'lly_laptop' ? { name: 'laptop-claude', client: 'default', providers: memberAgentProviders } : null),
    providers: { alpha: provider(personalApi.port), beta: provider(personalApi.port) },
    log: (r) => memberLogs.push(r),
    team: () => (linked ? { url: `https://127.0.0.1:${teamPort}`, token: 'lly_member_team_token_0123456789', ca: tls.cert.toString() } : null),
  });
  const memberPort = await listen(member as http.Server);

  const call = (p: string, token = 'lly_laptop') => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: memberPort, path: p, headers: { authorization: `Bearer ${token}` }, agent: false }, (res) => {
      let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode!, body: b }));
    });
    req.on('error', reject); req.end();
  });
  return {
    call, personalApi, teamApi, teamLogs, memberLogs, teamPort,
    close: () => { member.close(); team.close(); personalApi.close(); teamApi.close(); },
  };
}

test('a personal key is used here and never reaches the team server', async () => {
  const s = await setup();
  try {
    assert.equal((await s.call('/alpha/v1/x')).status, 200);
    assert.deepEqual(s.personalApi.seen.map((r) => r.key), ['PERSONAL-ALPHA-KEY']);
    assert.equal(s.teamApi.seen.length, 0);
    assert.equal(s.teamLogs.length, 0, 'the team server never hears about it');
  } finally { s.close(); }
});

test('no personal key: the request goes to the team server as this member, with the team key added there', async () => {
  const s = await setup();
  try {
    const r = await s.call('/beta/v1/models?x=1');
    assert.equal(r.status, 200);
    assert.deepEqual(s.teamApi.seen, [{ key: 'TEAM-BETA-KEY', auth: undefined, path: '/v1/models?x=1' }]);
    assert.equal(s.personalApi.seen.length, 0);
    assert.equal(s.teamLogs.find((l) => l.status === 200)?.agent, 'alice', 'the team server sees the member, not the device token');
    assert.equal(s.memberLogs.find((l) => l.provider === 'beta')?.via, 'team');

    // A provider only the team server knows about goes there too.
    assert.equal((await s.call('/gamma/v1/x')).status, 200);
    assert.equal(s.teamApi.seen.at(-1)?.key, 'TEAM-GAMMA-KEY');
  } finally { s.close(); }
});

test("a device token's limits apply before anything is forwarded", async () => {
  const s = await setup(['alpha']);
  try {
    assert.equal((await s.call('/beta/v1/x')).status, 403);
    assert.equal((await s.call('/beta/v1/x', 'lly_wrong')).status, 401);
    assert.equal(s.teamLogs.length, 0);
  } finally { s.close(); }
});

test('not linked: behaves as before', async () => {
  const s = await setup(undefined, false);
  try {
    assert.equal((await s.call('/beta/v1/x')).status, 503);
    assert.equal((await s.call('/gamma/v1/x')).status, 404);
  } finally { s.close(); }
});

test('the team server answers whoami for a valid token only, without touching a key', async () => {
  const s = await setup();
  try {
    const https = await import('node:https');
    const ask = (token: string) => new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = https.request({ host: '127.0.0.1', port: s.teamPort, path: '/_lllanyard/whoami', headers: { authorization: `Bearer ${token}` }, ca: tls.cert, agent: false }, (res) => {
        let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode!, body: b }));
      });
      req.on('error', reject); req.end();
    });
    const ok = await ask('lly_member_team_token_0123456789');
    assert.equal(ok.status, 200);
    assert.deepEqual(JSON.parse(ok.body), { name: 'alice', client: 'default', providers: null });
    assert.equal((await ask('lly_nope')).status, 401);
    assert.equal(s.teamApi.seen.length, 0);
  } finally { s.close(); }
});

test('team links: HTTPS only, no path or credentials, real tokens only', () => {
  assert.equal(normaliseTeamUrl('https://keys.example.com:3443/'), 'https://keys.example.com:3443');
  assert.throws(() => normaliseTeamUrl('http://keys.example.com:3443'), /https/);
  assert.throws(() => normaliseTeamUrl('https://keys.example.com/openai'), /no path/);
  assert.throws(() => normaliseTeamUrl('https://me:pw@keys.example.com'), /user name/);
  const store = new TeamStore(new MemoryBackend());
  assert.throws(() => store.set({ url: 'https://keys.example.com', token: 'sk-real-key' }), /lly_/);
  assert.throws(() => store.set({ url: 'https://keys.example.com', token: 'lly_aaaaaaaaaaaaaaaaaaaa', ca: 'not a cert' }), /PEM/);
  const link = store.set({ url: 'https://keys.example.com:3443', token: ' lly_aaaaaaaaaaaaaaaaaaaa ' });
  assert.equal(link.token, 'lly_aaaaaaaaaaaaaaaaaaaa');
  assert.equal(store.get()?.url, 'https://keys.example.com:3443');
  assert.equal(store.remove(), true);
  assert.equal(store.get(), null);
});
