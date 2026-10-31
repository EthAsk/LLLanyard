import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import util from 'node:util';
import { redactFile, scan, scanText } from '../src/index.js';

const ANT = 'sk-ant-api03-' + 'Q'.repeat(40);
const OAI = 'sk-proj-' + 'Z'.repeat(40);
const mk = () => fs.mkdtemp(path.join(os.tmpdir(), 'lly-'));

test('scanText: detects providers once each; sk-ant is not also reported as openai', () => {
  const hits = scanText(`A=${ANT}\nB="${OAI}"\nC=ghp_${'a'.repeat(36)}\nD=AIza${'b'.repeat(35)}`);
  assert.deepEqual(hits.map((h) => h.provider), ['anthropic', 'openai', 'github', 'google']);
  assert.deepEqual(hits.map((h) => h.importable), [true, true, true, false]);
});

test('scan: finds keys, masks them, and never leaks plaintext via JSON or inspect', async () => {
  const d = await mk();
  await fs.writeFile(path.join(d, '.env'), `ANTHROPIC_API_KEY=${ANT}\nOPENAI_API_KEY=${OAI}\n`);
  const f = await scan({ roots: [d] });
  assert.equal(f.length, 2);
  for (const x of f) {
    assert.equal(JSON.stringify(x).includes('QQQQQ'), false);
    assert.equal(JSON.stringify(x).includes('ZZZZZ'), false);
    assert.equal(util.inspect(x).includes('QQQQQ'), false);
    assert.equal(String(x.masked).includes('QQQQQ'), false);
  }
  assert.equal(f.find((x) => x.provider === 'anthropic')!.reveal(), ANT);
});

test('scan: skips node_modules, symlinks and binary files', async () => {
  const d = await mk();
  const outside = await mk();
  await fs.writeFile(path.join(outside, 'secret.json'), `{"k":"${ANT}"}`);
  await fs.mkdir(path.join(d, 'node_modules'));
  await fs.writeFile(path.join(d, 'node_modules', 'x.json'), `{"k":"${ANT}"}`);
  await fs.symlink(path.join(outside, 'secret.json'), path.join(d, 'link.json'));
  await fs.symlink(outside, path.join(d, 'linkdir'));
  await fs.writeFile(path.join(d, 'blob.json'), Buffer.concat([Buffer.from([0]), Buffer.from(ANT)]));
  assert.equal((await scan({ roots: [d] })).length, 0);
});

test('scan: refuses to scan the entire home directory', async () => {
  await assert.rejects(scan({ roots: [os.homedir()] }), /home directory/);
});

test('redactFile: replaces key atomically, keeps permissions, leaves no temp or backup files', async () => {
  const d = await mk();
  const file = path.join(d, '.env');
  await fs.writeFile(file, `A=${ANT}\nB=${ANT}\nC=keep\n`, { mode: 0o600 });
  assert.equal(await redactFile(file, [ANT]), 2);
  const text = await fs.readFile(file, 'utf8');
  assert.equal(text, 'A=REMOVED_BY_LLLANYARD\nB=REMOVED_BY_LLLANYARD\nC=keep\n');
  if (process.platform !== 'win32') assert.equal((await fs.stat(file)).mode & 0o777, 0o600); // Windows has no POSIX modes
  assert.deepEqual(await fs.readdir(d), ['.env']);
  assert.equal((await scan({ roots: [d] })).length, 0);
});
