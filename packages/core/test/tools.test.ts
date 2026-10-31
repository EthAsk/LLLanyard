import test from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { KeyringStore, MemoryBackend, StoreError, ToolStore, bindingsForKeys, createScrubber, neededEnv, parseKeyRef, pinFiles, pinScript, runTool, validateTool } from '../src/index.js';

const SECRET = 'ghp_' + 'S3cr3tTokenValue'.repeat(3);
const sink = () => { const chunks: Buffer[] = []; const w = new Writable({ write(c, _e, cb) { chunks.push(Buffer.from(c)); cb(); } }); return { w, text: () => Buffer.concat(chunks).toString('utf8') }; };
const store = (m: Record<string, string>) => ({ get: (p: string, l = 'default') => m[`${p}:${l}`] ?? null });
const node = (code: string) => ({ command: process.execPath, args: ['-e', code], scrub: true });

test('parseKeyRef: provider or provider:label, nothing else', () => {
  assert.deepEqual(parseKeyRef('GitHub'), { provider: 'github', label: 'default' });
  assert.deepEqual(parseKeyRef('github:Acme'), { provider: 'github', label: 'acme' });
  for (const bad of ['', 'a:b:c', 'a b', ':x']) assert.throws(() => parseKeyRef(bad), StoreError, bad);
});

test('validateTool: needs bindings, blocks code-loading env vars, bounds size', () => {
  const base = { name: 'gh', command: '/usr/bin/npx', args: ['-y', 'x'], scrub: true };
  assert.deepEqual(validateTool({ ...base, env: { GITHUB_TOKEN: 'github:default' } }).env, { GITHUB_TOKEN: 'github' });
  assert.throws(() => validateTool({ ...base, env: {} }), StoreError);
  for (const v of ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'NODE_OPTIONS', 'PATH', 'bad-name'])
    assert.throws(() => validateTool({ ...base, env: { [v]: 'github' } }), StoreError, v);
  assert.throws(() => validateTool({ ...base, args: ['x'.repeat(900), 'y'.repeat(900), 'z'.repeat(900)], env: { A: 'github' } }), StoreError);
});

test('ToolStore: round trip; tampered entries are ignored', () => {
  const b = new MemoryBackend();
  const s = new ToolStore(b);
  s.set({ name: 'GH', command: 'npx', args: [], env: { GITHUB_TOKEN: 'github' }, scrub: true });
  assert.equal(s.get('gh')!.command, 'npx');
  b.set('tool:gh', JSON.stringify({ name: 'gh', command: 'x', args: [], env: { LD_PRELOAD: 'github' }, scrub: true }));
  assert.equal(s.get('gh'), null);
  assert.equal(s.remove('gh'), true);
});

test('scrubber: redacts a secret split across chunks and emits complete lines immediately', async () => {
  const t = createScrubber([SECRET]);
  const out: string[] = [];
  t.on('data', (d) => out.push(d.toString()));
  t.write(`token=${SECRET.slice(0, 10)}`);
  t.write(`${SECRET.slice(10)}\n{"ok":1}\n`);
  await new Promise((r) => setImmediate(r));
  assert.equal(out.join(''), 'token=[REDACTED]\n{"ok":1}\n');
  t.write('Remember this location? (y/n): ');
  await new Promise((r) => setImmediate(r));
  assert.equal(out.join('').endsWith('(y/n): '), true, 'a prompt without a newline shows immediately');
  await new Promise<void>((r) => { t.end(r); });
});

test('scrubber: holds back only a tail that could start a secret', async () => {
  const t = createScrubber([SECRET]);
  const out: string[] = [];
  t.on('data', (d) => out.push(d.toString()));
  t.write(`Key: ${SECRET.slice(0, 6)}`);
  await new Promise((r) => setImmediate(r));
  assert.equal(out.join(''), 'Key: ', 'the possible start of the secret is held');
  t.write(`${SECRET.slice(6)} done`);
  await new Promise<void>((r) => { t.end(r); });
  assert.equal(out.join(''), 'Key: [REDACTED] done');
});

test('scrubber: catches secrets inside a very long line without a newline', async () => {
  const t = createScrubber([SECRET]);
  let got = '';
  t.on('data', (d) => (got += d));
  const filler = 'a'.repeat(70_000);
  t.write(filler + SECRET.slice(0, 20));
  t.write(SECRET.slice(20) + filler);
  await new Promise<void>((r) => { t.end(r); });
  assert.equal(got.includes(SECRET.slice(0, 12)), false);
  assert.equal(got.includes('[REDACTED]'), true);
  assert.equal(got.length, filler.length * 2 + '[REDACTED]'.length);
});

test('runTool: injects the key into the child only, scrubs it from output, returns the exit code', async () => {
  const out = sink(), err = sink();
  const code = await runTool(
    { ...node(`console.log('v=' + process.env.LLY_TEST_TOKEN); console.error('e=' + process.env.LLY_TEST_TOKEN); process.exit(3)`), env: { LLY_TEST_TOKEN: 'github' } },
    { store: store({ 'github:default': SECRET }), stdout: out.w, stderr: err.w }
  );
  assert.equal(code, 3);
  assert.equal(out.text(), 'v=[REDACTED]\n');
  assert.equal(err.text(), 'lllanyard: warning: this tool printed its API key (redacted). It may be misbehaving or compromised.\ne=[REDACTED]\n');
  assert.equal(process.env.LLY_TEST_TOKEN, undefined); // parent environment untouched
});

test('runTool: labelled bindings pick the right key; passEnv variables are passed through', async () => {
  const out = sink();
  await runTool(
    { ...node(`console.log(process.env.A === undefined ? 'none' : 'has-A', process.env.KEEP)`), env: { A: 'github:acme' }, passEnv: ['KEEP'] },
    { store: store({ 'github:acme': SECRET }), env: { ...process.env, KEEP: 'yes' }, stdout: out.w }
  );
  assert.equal(out.text(), 'has-A yes\n');
});

test('runTool: missing key fails before anything is spawned', async () => {
  let spawned = false;
  await assert.rejects(
    runTool({ ...node('1'), env: { T: 'github' } }, { store: store({}), spawn: ((() => { spawned = true; }) as any) }),
    /No key stored for github:default/
  );
  assert.equal(spawned, false);
});

test('runTool: unknown command gives a clear error', async () => {
  await assert.rejects(runTool({ command: '/nonexistent/definitely-not-here', args: [], env: { T: 'github' }, scrub: true }, { store: store({ 'github:default': SECRET }) }), /Command not found/);
});

test('runTool: Windows shell mode refuses arguments with shell metacharacters', async () => {
  await assert.rejects(
    runTool({ command: 'npx', args: ['-y', 'pkg & calc'], env: { T: 'github' }, scrub: true }, { store: store({ 'github:default': SECRET }), platform: 'win32', spawn: (() => { throw new Error('should not spawn'); }) as any }),
    /not allowed/
  );
});

test('runTool: without scrubbing the child writes straight to the inherited stdio', async () => {
  const code = await runTool({ command: process.execPath, args: ['-e', 'process.exit(0)'], env: { T: 'github' }, scrub: false }, { store: store({ 'github:default': SECRET }) });
  assert.equal(code, 0);
});

// ---------------------------------------------------------------- leak safeguards
import { LEAK_EXIT_CODE, minimalEnv, secretVariants } from '../src/index.js';

const mk = (len: number) => Array.from({ length: len }, (_, i) => 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/_-'[(i * 7 + 3) % 40]).join('');
const scrubText = async (secrets: string[], text: string) => {
  const t = createScrubber(secrets);
  let got = '';
  t.on('data', (d) => (got += d));
  await new Promise<void>((r) => { t.end(text, r); });
  return got;
};

test('scrubber: catches base64 at every byte alignment, base64url, hex and URL-encoded copies', async () => {
  // lengths chosen so (k + len) % 3 == 0: the whole encoded form is determined except k leading pad chars
  for (const [k, len] of [[0, 33], [1, 32], [2, 31]] as const) {
    const secret = mk(len);
    const enc = Buffer.from('x'.repeat(k) + secret).toString('base64');
    const skip = [0, 2, 3][k]!;
    assert.equal(await scrubText([secret], enc), enc.slice(0, skip) + '[REDACTED]', `base64 alignment ${k}`);
  }
  const secret = 'tok_a+b/c=d e'.replace(' ', '-') + 'ZZZZZZZZ';
  const b64url = Buffer.from(secret).toString('base64url');
  assert.equal(await scrubText([secret], `x=${b64url}\n`), 'x=[REDACTED]\n');
  assert.equal(await scrubText([secret], `x=${Buffer.from(secret).toString('hex')}\n`), 'x=[REDACTED]\n');
  assert.equal(await scrubText([secret], `x=${Buffer.from(secret).toString('hex').toUpperCase()}\n`), 'x=[REDACTED]\n');
  assert.equal(await scrubText([secret], `q=${encodeURIComponent(secret)}\n`), 'q=[REDACTED]\n');
  assert.ok(secretVariants(secret).length >= 6);
});

test('scrubber: leaves unrelated text alone and reports how many replacements it made', async () => {
  const secret = mk(33);
  const t = createScrubber([secret]);
  let n = 0, got = '';
  t.on('redacted', (c: number) => (n += c));
  t.on('data', (d) => (got += d));
  await new Promise<void>((r) => { t.end(`hello world\n${secret} and ${secret}\nbye\n`, r); });
  assert.equal(got, 'hello world\n[REDACTED] and [REDACTED]\nbye\n');
  assert.equal(n, 2);
});

test('minimalEnv: keeps the basics, drops everything else unless passed through', () => {
  const base = { PATH: '/bin', HOME: '/h', LC_ALL: 'C', OPENAI_API_KEY: 'sk-x', AWS_SECRET_ACCESS_KEY: 'y', Systemroot: 'C:\\W', EXTRA: 'e' };
  assert.deepEqual(minimalEnv(base), { PATH: '/bin', HOME: '/h', LC_ALL: 'C', Systemroot: 'C:\\W' });
  assert.equal(minimalEnv(base, ['extra']).EXTRA, 'e');
});

test('validateTool: allowHosts, passEnv and flags are validated and normalised', () => {
  const base = { name: 'gh', command: '/x', args: [], env: { A: 'github' }, scrub: true };
  const v = validateTool({ ...base, allowHosts: ['API.GitHub.com', '*.githubusercontent.com', 'api.github.com'], passEnv: ['HTTP_TIMEOUT'], killOnLeak: true });
  assert.deepEqual(v.allowHosts, ['api.github.com', '*.githubusercontent.com']);
  assert.equal(v.killOnLeak, true);
  for (const bad of ['1.2.3.4', 'localhost', 'a.com:443', 'a.com/x', '*.com.', 'ex ample.com', '*', ''])
    assert.throws(() => validateTool({ ...base, allowHosts: [bad] }), StoreError, bad);
  assert.throws(() => validateTool({ ...base, passEnv: ['LD_PRELOAD'] }), StoreError);
});

test('runTool: child gets a minimal environment, not the parent\'s other secrets', async () => {
  const out = sink();
  await runTool(
    { ...node(`console.log(JSON.stringify({ other: process.env.OTHER_SECRET ?? null, passed: process.env.PASSED ?? null, home: !!process.env.HOME, key: !!process.env.K }))`), env: { K: 'github' }, passEnv: ['PASSED'] },
    { store: store({ 'github:default': SECRET }), env: { PATH: process.env.PATH, HOME: '/h', OTHER_SECRET: 'sk-leak', PASSED: 'yes' }, stdout: out.w }
  );
  assert.deepEqual(JSON.parse(out.text()), { other: null, passed: 'yes', home: true, key: true });
});

test('runTool: inheritEnv opts back in to the full environment', async () => {
  const out = sink();
  await runTool(
    { ...node(`console.log(process.env.OTHER_SECRET)`), env: { K: 'github' }, inheritEnv: true },
    { store: store({ 'github:default': SECRET }), env: { PATH: process.env.PATH, OTHER_SECRET: 'visible' }, stdout: out.w }
  );
  assert.equal(out.text(), 'visible\n');
});

test('runTool: a leaking tool gets a warning on stderr, output stays redacted, run continues', async () => {
  const out = sink(), err = sink();
  const code = await runTool(
    { ...node(`console.log(Buffer.from(process.env.K).toString('base64'))`), env: { K: 'github' } },
    { store: store({ 'github:default': SECRET }), env: { PATH: process.env.PATH }, stdout: out.w, stderr: err.w }
  );
  assert.equal(code, 0);
  assert.equal(out.text().includes(SECRET), false);
  assert.match(out.text(), /\[REDACTED\]/);
  assert.match(err.text(), /printed its API key/);
});

test('runTool: killOnLeak stops the tool immediately and returns the leak exit code', async () => {
  const out = sink(), err = sink();
  const t0 = Date.now();
  const code = await runTool(
    { ...node(`console.log(process.env.K); setInterval(() => {}, 1000)`), env: { K: 'github' }, killOnLeak: true },
    { store: store({ 'github:default': SECRET }), env: { PATH: process.env.PATH }, stdout: out.w, stderr: err.w }
  );
  assert.equal(code, LEAK_EXIT_CODE);
  assert.ok(Date.now() - t0 < 5000, 'tool should have been killed, not left running');
  assert.equal(out.text().includes(SECRET), false);
  assert.match(err.text(), /stopping the tool/);
});

test('runTool: egress env is given to the child, and the egress proxy is closed afterwards', async () => {
  const out = sink();
  let closed = 0;
  await runTool(
    { ...node(`console.log(process.env.HTTPS_PROXY)`), env: { K: 'github' } },
    { store: store({ 'github:default': SECRET }), env: { PATH: process.env.PATH, HTTPS_PROXY: 'http://parent' }, stdout: out.w,
      egress: { env: { HTTPS_PROXY: 'http://egress' }, close: () => { closed++; } } }
  );
  assert.equal(out.text(), 'http://egress\n');
  assert.equal(closed, 1);
  // also closed when startup fails
  await assert.rejects(runTool({ ...node('1'), env: { K: 'slack' } }, { store: store({}), egress: { env: {}, close: () => { closed++; } } }));
  assert.equal(closed, 2);
});

test('pinScript/scriptOf: interpreter tools are pinned to a script file; code flags are refused for --allow-args', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-pin-'));
  writeFileSync(path.join(dir, 's.py'), 'print(1)\n');
  const p = pinScript('/usr/bin/python3', ['-u', 's.py', '--x'], dir);
  assert.deepEqual(p.args, ['-u', path.join(dir, 's.py'), '--x']);
  assert.match(p.scriptSha256!, /^[0-9a-f]{64}$/);
  assert.deepEqual(pinScript('/usr/bin/gh', ['api']), { args: ['api'] }, 'non-interpreters pass through');
  assert.throws(() => pinScript('/usr/bin/python3', ['missing.py'], dir), /not found/);

  const base = { name: 't', env: { K: 'github' }, scrub: true, allowArgs: true };
  for (const [command, args] of [['/usr/bin/python3', ['-c', 'x']], ['/usr/bin/python3', ['-m', 'http.server']], ['/bin/bash', ['-s']], ['/usr/bin/node', ['-e', '/x/']], ['/usr/bin/python3', []]] as const)
    assert.throws(() => validateTool({ ...base, command, args: [...args] }), StoreError, `${command} ${args.join(' ')}`);
  assert.throws(() => validateTool({ ...base, command: '/usr/bin/python3', args: ['rel.py'] }), /absolute/);
  for (const launcher of ['/usr/bin/env', '/usr/bin/xargs', '/usr/bin/sudo', '/usr/local/bin/npx'])
    assert.throws(() => validateTool({ ...base, command: launcher, args: ['x'] }), /not allowed/);
  assert.equal(validateTool({ ...base, command: '/usr/bin/python3', args: ['-u', '/opt/s.py'] }).allowArgs, true);
  assert.equal(validateTool({ ...base, command: '/usr/bin/pwsh', args: ['-NoProfile', '-File', '/opt/s.ps1'] }).allowArgs, true);
  assert.equal(validateTool({ ...base, command: '/usr/bin/gh', args: ['api'] }).allowArgs, true);
  assert.doesNotThrow(() => validateTool({ name: 'mcp', command: '/usr/local/bin/npx', args: ['-y', 'pkg'], env: { K: 'github' }, scrub: true }), 'existing npx tools still work without --allow-args');
});

test('runTool: a pinned script that changed (or vanished) is not started', async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-pin-'));
  const f = path.join(dir, 's.js');
  writeFileSync(f, 'console.log("ARGS=" + process.argv.slice(2).join(","))\n');
  const { args, scriptSha256 } = pinScript(process.execPath, [f]);
  const out = sink();
  const code = await runTool({ command: process.execPath, args: [...args, 'a', 'b'], env: { K: 'github' }, scrub: true, scriptSha256 }, { store: store({ 'github:default': SECRET }), stdout: out.w });
  assert.equal(code, 0);
  assert.match(out.text(), /ARGS=a,b/);

  writeFileSync(f, 'console.log(process.env.K)\n');
  let spawned = false;
  const spawn = (() => { spawned = true; throw new Error('should not spawn'); }) as any;
  await assert.rejects(runTool({ command: process.execPath, args, env: { K: 'github' }, scrub: true, scriptSha256 }, { store: store({ 'github:default': SECRET }), spawn }), /has changed/);
  rmSync(f);
  await assert.rejects(runTool({ command: process.execPath, args, env: { K: 'github' }, scrub: true, scriptSha256 }, { store: store({ 'github:default': SECRET }), spawn }), /has changed \(or is missing\)/);
  assert.equal(spawned, false);
});

test('key variable names: kept on rotation, settable, and used by bindingsForKeys', () => {
  const keys = new KeyringStore(new MemoryBackend());
  keys.set('github', 'github-key-0123456789', { envName: 'GITHUB_TOKEN' });
  keys.set('jira', 'hunt-secret-0123456789', { label: 'secret' });
  keys.set('github', 'github-key-ROTATED-0123');
  assert.equal(keys.list()[0]!.envName, 'GITHUB_TOKEN', 'rotation keeps the variable name');
  assert.throws(() => bindingsForKeys(['jira:secret'], keys), /no variable name yet.*lllanyard env jira:secret/);
  keys.setEnvName('jira', 'secret', 'JIRA_API_TOKEN');
  assert.deepEqual(bindingsForKeys(['github', 'jira:secret'], keys), { GITHUB_TOKEN: 'github', JIRA_API_TOKEN: 'jira:secret' });
  assert.throws(() => bindingsForKeys(['sendgrid'], keys), /No sendgrid:default key/);
  keys.setEnvName('jira', 'secret', 'GITHUB_TOKEN');
  assert.throws(() => bindingsForKeys(['github', 'jira:secret'], keys), /Two keys/);
  assert.throws(() => keys.setEnvName('github', 'default', 'BAD NAME'), StoreError);
  assert.equal(keys.setEnvName('github', 'default', undefined).envName, undefined, 'clearing works');
  assert.equal(keys.get('github'), 'github-key-ROTATED-0123', 'the key itself is untouched');
});

test('runTool: an extra pinned file that changed stops the run; validateTool bounds pins', async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-pin-'));
  const main = path.join(dir, 'main.js'), helper = path.join(dir, 'helper.js');
  writeFileSync(main, 'console.log("ok")\n'); writeFileSync(helper, 'module.exports = 1\n');
  const { args, scriptSha256 } = pinScript(process.execPath, [main]);
  const def = { command: process.execPath, args, env: { K: 'github' }, scrub: true, scriptSha256, pins: pinFiles([helper]) };
  assert.equal(await runTool(def, { store: store({ 'github:default': SECRET }), stdout: sink().w }), 0);
  writeFileSync(helper, 'module.exports = 2\n');
  await assert.rejects(runTool(def, { store: store({ 'github:default': SECRET }), spawn: (() => { throw new Error('spawned'); }) as any }), new RegExp(`${helper.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} has changed`));
  assert.throws(() => pinFiles([path.join(dir, 'missing.js')]), /not found/);
  assert.throws(() => validateTool({ name: 't', command: '/bin/x', args: [], env: { K: 'g' }, scrub: true, pins: { 'rel.ps1': 'a'.repeat(64) } }), /Invalid pinned file/);
});

test('neededEnv: finds variables in the script and in helper files it names, nothing else', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-need-'));
  writeFileSync(path.join(dir, 'Main.ps1'), ". (Join-Path $PSScriptRoot 'Common.ps1')\n& (Join-Path $PSScriptRoot 'Invoke-Jira.ps1')\n");
  writeFileSync(path.join(dir, 'Common.ps1'), "$k = $env:GITHUB_TOKEN\n# GITHUB_TOKENS_OLD is a different word\n");
  writeFileSync(path.join(dir, 'Invoke-Jira.ps1'), "$env:JIRA_API_TOKEN\n");
  writeFileSync(path.join(dir, 'Unrelated.ps1'), "$env:SLACK_BOT_TOKEN\n");
  writeFileSync(path.join(dir, 'tool.py'), "import helpers\nimport os\n");
  writeFileSync(path.join(dir, 'helpers.py'), "KEY = os.environ['NPM_TOKEN']\n");
  const names = ['GITHUB_TOKEN', 'JIRA_API_TOKEN', 'SLACK_BOT_TOKEN', 'NPM_TOKEN', 'SENDGRID_API_KEY'];
  const r = neededEnv(path.join(dir, 'Main.ps1'), names);
  assert.deepEqual(r.needed, ['GITHUB_TOKEN', 'JIRA_API_TOKEN']);
  assert.deepEqual(r.files.map((f) => path.basename(f)).sort(), ['Common.ps1', 'Invoke-Jira.ps1', 'Main.ps1']);
  assert.deepEqual(neededEnv(path.join(dir, 'tool.py'), names).needed, ['NPM_TOKEN'], 'python imports of sibling modules are followed');
  assert.deepEqual(neededEnv(path.join(dir, 'missing.ps1'), names).needed, []);
});

test('neededEnv: file names in comments and non-script files are not followed', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-need-'));
  writeFileSync(path.join(dir, 'A.ps1'), "<#\n  Run after B.ps1\n#>\n# see also C.ps1\n$env:GITHUB_TOKEN\nGet-Content README.md\n");
  writeFileSync(path.join(dir, 'B.ps1'), '$env:DATADOG_API_KEY\n');
  writeFileSync(path.join(dir, 'C.ps1'), '$env:SLACK_BOT_TOKEN\n');
  writeFileSync(path.join(dir, 'README.md'), 'NPM_TOKEN\n');
  assert.deepEqual(neededEnv(path.join(dir, 'A.ps1'), ['GITHUB_TOKEN', 'DATADOG_API_KEY', 'SLACK_BOT_TOKEN', 'NPM_TOKEN']).needed, ['GITHUB_TOKEN']);
});

test('neededEnv: a file named inside a message is not followed; quoted paths and source lines are', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lly-need-'));
  writeFileSync(path.join(dir, 'H.ps1'), 'Add-Action "Create the client first (Other.ps1), then re-run."\n. (Join-Path $PSScriptRoot \'Lib.ps1\')\n');
  writeFileSync(path.join(dir, 'Other.ps1'), '$env:DATADOG_API_KEY\n');
  writeFileSync(path.join(dir, 'Lib.ps1'), '$env:GITHUB_TOKEN\n');
  writeFileSync(path.join(dir, 'run.sh'), 'source ./common.sh\n');
  writeFileSync(path.join(dir, 'common.sh'), 'curl -H "X: $NPM_TOKEN"\n');
  const names = ['GITHUB_TOKEN', 'DATADOG_API_KEY', 'NPM_TOKEN'];
  assert.deepEqual(neededEnv(path.join(dir, 'H.ps1'), names).needed, ['GITHUB_TOKEN']);
  assert.deepEqual(neededEnv(path.join(dir, 'run.sh'), names).needed, ['NPM_TOKEN']);
});

test('ptyCommand wraps interactive tools in a pseudo-terminal where the system supports it', async () => {
  const { ptyCommand } = await import('../src/run.js');
  assert.deepEqual(ptyCommand('darwin', 'pwsh', ['-File', 'a b.ps1'], () => '/usr/bin/script'), { command: '/usr/bin/script', args: ['-q', '/dev/null', 'pwsh', '-File', 'a b.ps1'] });
  assert.deepEqual(ptyCommand('linux', 'pwsh', ["it's"], () => '/usr/bin/script'), { command: '/usr/bin/script', args: ['-q', '-e', '-c', `'pwsh' 'it'\\''s'`, '/dev/null'] });
  assert.equal(ptyCommand('win32', 'pwsh', [], () => '/usr/bin/script'), null);
  assert.equal(ptyCommand('darwin', 'pwsh', [], () => null), null);
});

test('interactive runs use a pseudo-terminal: output is scrubbed, keystrokes reach the tool, exit code passes through', async () => {
  const { runTool } = await import('../src/run.js');
  const { PassThrough } = await import('node:stream');
  const typed: string[] = [];
  let spawned: { file: string; args: string[]; env: Record<string, string> } | undefined;
  let exit!: (e: { exitCode: number }) => void;
  let data!: (d: string) => void;
  const fakePty = {
    spawn(file: string, args: string[], o: { env: Record<string, string> }) {
      spawned = { file, args, env: o.env };
      return { onData: (cb: any) => { data = cb; }, onExit: (cb: any) => { exit = cb; }, write: (d: any) => { typed.push(String(d)); }, resize() {}, kill() {} };
    },
  };
  const stdin = new PassThrough() as any;
  let out = '';
  const stdout = new Writable({ write(c, _e, cb) { out += c; cb(); } });
  const p = runTool({ command: 'pwsh', args: ['-File', 'x.ps1'], env: { K: 'github' }, scrub: true },
    { store: { get: () => 'ghp_secretvalue123456' }, env: { PATH: '/usr/bin' }, stdout, stdin, tty: true, loadPty: () => fakePty, spawn: (() => { throw new Error('should use the pty'); }) as any });
  await new Promise((r) => setImmediate(r));
  assert.equal(spawned?.file, 'pwsh');
  assert.equal(spawned?.env.K, 'ghp_secretvalue123456');
  stdin.write('Acme\r');
  data('Client name: ');
  data('key=ghp_secret');
  data('value123456 done');
  exit({ exitCode: 5 });
  assert.equal(await p, 5);
  assert.deepEqual(typed, ['Acme\r']);
  assert.equal(out, 'Client name: key=[REDACTED] done');
});

test('if the pseudo-terminal cannot start, the tool still runs (plain pipes)', async () => {
  const { runTool } = await import('../src/run.js');
  let spawnedWith: string | undefined;
  await assert.rejects(runTool({ command: 'pwsh', args: [], env: {}, scrub: true }, {
    store: { get: () => null }, env: { PATH: '/usr/bin' }, platform: 'win32', tty: true,
    loadPty: () => ({ spawn: () => { throw new Error('no conpty'); } }),
    spawn: ((cmd: string) => { spawnedWith = cmd; throw new Error('fallback reached'); }) as any,
  }), /fallback reached/);
  assert.equal(spawnedWith, 'pwsh');
});

test('runTool for MCP: no stdin, runs in the given folder, output captured and scrubbed, abort stops it', async () => {
  const dir = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'lly-mcp-test-')));
  const out = sink(), err = sink();
  try {
    const code = await runTool({ ...node('let n=0;process.stdin.on("data",()=>n++).on("end",()=>console.log(process.cwd(),n,process.env.K))'), env: { K: 'github' } },
      { store: store({ 'github:default': SECRET }), stdout: out.w, stderr: err.w, noStdin: true, tty: false, cwd: dir });
    assert.equal(code, 0);
    assert.equal(out.text(), `${dir} 0 [REDACTED]\n`);
    assert.match(err.text(), /printed its API key/);
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 200);
    const t0 = Date.now();
    await runTool({ ...node('setTimeout(()=>{},60000)'), env: {} }, { store: store({}), stdout: sink().w, stderr: sink().w, noStdin: true, tty: false, signal: ac.signal });
    assert.ok(Date.now() - t0 < 10_000);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
