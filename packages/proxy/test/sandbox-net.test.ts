import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startEgressProxy } from '../src/egress.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const bridgeTs = path.join(here, '../../core/src/sandbox-bridge.ts');

// Real kernel isolation check using a fresh network namespace (the same primitive bubblewrap's --unshare-net uses).
const can = spawnSync('unshare', ['--user', '--map-root-user', '--net', 'true']).status === 0 && spawnSync('python3', ['-c', '1']).status === 0;

const LO_UP = `import socket,struct,fcntl
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
ifr=struct.pack('16sH',b'lo',0)
f=struct.unpack('16sH',fcntl.ioctl(s,0x8913,ifr))[1]
fcntl.ioctl(s,0x8914,struct.pack('16sH',b'lo',f|1))`;

const CLIENT = `
const net=require('node:net');
const [echoPort,bridgePort,auth]=process.argv.slice(2);
const out={};
const tryConnect=(host,port)=>new Promise(r=>{const s=net.connect({host,port:+port,timeout:2000});s.on('connect',()=>{s.destroy();r('connected')});s.on('error',e=>r(e.code));s.on('timeout',()=>{s.destroy();r('timeout')});});
const via=(target)=>new Promise(r=>{const s=net.connect(+bridgePort,'127.0.0.1');let b='';s.on('error',e=>r('err:'+e.code));
 s.on('data',d=>{b+=d;const i=b.indexOf('\\r\\n\\r\\n');if(i<0)return;const st=+b.slice(9,12);if(st!==200){s.destroy();return r(st);}s.write('hi');s.once('data',d2=>{s.destroy();r(st+':'+d2)});});
 s.write('CONNECT '+target+' HTTP/1.1\\r\\nHost: '+target+'\\r\\nProxy-Authorization: '+auth+'\\r\\n\\r\\n');});
(async()=>{
 out.directHostLoopback=await tryConnect('127.0.0.1',echoPort);
 out.directInternet=await tryConnect('1.1.1.1',443);
 out.allowed=await via('allowed.example:'+echoPort);
 out.blocked=await via('evil.example:'+echoPort);
 console.log(JSON.stringify(out));
})();`;

test('real network namespace: no direct network; only the allowlisted tunnel works via the unix-socket bridge', { skip: !can && 'needs unshare + python3' }, async () => {
  const echo = net.createServer((s) => s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))));
  await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r));
  const echoPort = (echo.address() as net.AddressInfo).port;
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-'));
  const sock = path.join(dir, 'egress.sock');
  const fakeLookup = ((_h: string, _o: any, cb: any) => cb(null, [{ address: '127.0.0.1', family: 4 }])) as any;
  const proxy = await startEgressProxy({ allow: ['allowed.example'], ports: [echoPort], lookup: fakeLookup, unixSocket: sock });
  try {
    const client = path.join(dir, 'client.cjs'); writeFileSync(client, CLIENT);
    const lo = path.join(dir, 'lo.py'); writeFileSync(lo, LO_UP);
    const auth = 'Basic ' + Buffer.from('lly:' + proxy.password).toString('base64');
    const bridgePort = '34567';
    const script = `python3 ${lo} && exec ${process.execPath} --experimental-strip-types --no-warnings ${bridgeTs} ${sock} ${bridgePort} -- ${process.execPath} ${client} ${echoPort} ${bridgePort} '${auth}'`;
    const out = await new Promise<string>((resolve, reject) => {
      const c = spawn('unshare', ['--user', '--map-root-user', '--net', 'sh', '-c', script], { cwd: path.join(here, '../../..') });
      let o = '', e = '';
      c.stdout.on('data', (d) => (o += d)); c.stderr.on('data', (d) => (e += d));
      c.on('close', (code) => (code === 0 ? resolve(o) : reject(new Error(`exit ${code}: ${e}`))));
    });
    const r = JSON.parse(out.trim().split('\n').pop()!);
    assert.notEqual(r.directHostLoopback, 'connected', 'host loopback must be unreachable from inside the namespace');
    assert.notEqual(r.directInternet, 'connected', 'internet must be unreachable from inside the namespace');
    assert.equal(r.allowed, '200:echo:hi');
    assert.equal(r.blocked, 403);
  } finally { proxy.close(); echo.close(); rmSync(dir, { recursive: true, force: true }); }
});
