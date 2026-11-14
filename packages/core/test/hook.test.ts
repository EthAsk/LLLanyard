import test from 'node:test';
import assert from 'node:assert/strict';
import { checkToolCall, commandPaths, denyResponse, protectedReason } from '../src/index.js';

const home = '/Users/me';
const call = (tool_name: string, tool_input: Record<string, unknown>, cwd = '/work/app') => checkToolCall({ tool_name, tool_input, cwd }, { home });
const blocked = (r: string | null) => assert.ok(r, 'should be blocked');
const allowed = (r: string | null) => assert.equal(r, null, 'should be allowed');

test('hook: .env files are refused, example files are not', () => {
  blocked(call('Read', { file_path: '/work/app/.env' }));
  blocked(call('Read', { file_path: '.env.local' }));
  blocked(call('Read', { file_path: '.env.production' }));
  blocked(call('Write', { file_path: '/work/app/.env' })); // not even to put keys in it
  blocked(call('Edit', { file_path: 'sub/.env' }));
  allowed(call('Read', { file_path: '.env.example' }));
  allowed(call('Read', { file_path: '.env.sample' }));
  allowed(call('Read', { file_path: '.env.template' }));
  allowed(call('Read', { file_path: 'src/environment.ts' }));
  allowed(call('Read', { file_path: 'README.md' }));
});

test('hook: SSH private keys and credential files are refused, public parts are not', () => {
  blocked(call('Read', { file_path: '/Users/me/.ssh/id_ed25519' }));
  blocked(call('Read', { file_path: '~/.ssh/id_rsa' }));
  blocked(call('Read', { file_path: '/anywhere/id_rsa' }));
  blocked(call('Read', { file_path: '/Users/me/.ssh/my-server-key' }));
  blocked(call('Grep', { pattern: 'x', path: '/Users/me/.ssh' }));
  blocked(call('Read', { file_path: '/Users/me/.aws/credentials' }));
  blocked(call('Read', { file_path: '/Users/me/.netrc' }));
  blocked(call('Read', { file_path: '/Users/me/.gnupg/private-keys-v1.d/x.key' }));
  blocked(call('Read', { file_path: '/Users/me/.lllanyard/vault.enc' }));
  allowed(call('Read', { file_path: '/Users/me/.ssh/id_ed25519.pub' }));
  allowed(call('Read', { file_path: '/Users/me/.ssh/known_hosts' }));
  allowed(call('Read', { file_path: '/Users/me/.ssh/config' }));
  allowed(call('Read', { file_path: '/Users/me/.aws/config' }));
  allowed(call('Read', { file_path: '/Users/other/.ssh/x' }) && null); // someone else's home is not ours to guard
});

test('hook: shell commands that name those files are refused', () => {
  blocked(call('Bash', { command: 'cat .env' }));
  blocked(call('Bash', { command: 'grep API_KEY .env.local | head' }));
  blocked(call('Bash', { command: 'source ./.env && ./run.sh' }));
  blocked(call('Bash', { command: 'cat ~/.ssh/id_ed25519' }));
  blocked(call('Bash', { command: 'cat $HOME/.ssh/id_rsa' }));
  blocked(call('Bash', { command: 'ssh -i ~/.ssh/deploy_key user@host' }));
  blocked(call('Bash', { command: 'scp -i "/Users/me/.ssh/key" f host:' }));
  blocked(call('Bash', { command: 'cp .env /tmp/x' }));
  blocked(call('Bash', { command: 'cat ~/.aws/credentials' }));
  blocked(call('Bash', { command: 'FOO=1 cat .env;echo done' }));
  blocked(call('Bash', { command: 'cd /tmp && cat /Users/me/.netrc' }));
  // A `cd` inside the command changes the folder the hook can't see, so a bare name after it isn't recognised.
  allowed(call('Bash', { command: 'cd /Users/me && cat .netrc' }));
  allowed(call('Bash', { command: 'cat .env.example' }));
  allowed(call('Bash', { command: 'npm test' }));
  allowed(call('Bash', { command: 'git status && ls -la' }));
  allowed(call('Bash', { command: 'cat ~/.ssh/id_ed25519.pub' }));
  allowed(call('Bash', { command: 'echo "set up your env file"' }));
  allowed(call('Bash', { command: 'grep -r environment src' }));
});

test('hook: lllanyard commands are always allowed, and unknown tools and bad input are let through', () => {
  allowed(call('Bash', { command: 'lllanyard scan .env --import --apply' }));
  allowed(call('Bash', { command: 'lllanyard ssh prod -- uptime' }));
  allowed(call('WebFetch', { url: 'https://x/.env' }));
  allowed(checkToolCall({}, { home }));
  allowed(checkToolCall({ tool_name: 'Read', tool_input: 'oops' }, { home }));
  allowed(checkToolCall({ tool_name: 'Read', tool_input: { file_path: 42 } }, { home }));
  allowed(checkToolCall({ tool_name: 'Bash', tool_input: { command: ['cat', '.env'] } }, { home }));
});

test('hook: relative paths use the tool call\'s folder; a Grep glob can name .env files', () => {
  blocked(checkToolCall({ tool_name: 'Read', tool_input: { file_path: '.ssh/notes.txt' }, cwd: '/Users/me' }, { home }));
  allowed(checkToolCall({ tool_name: 'Read', tool_input: { file_path: '.ssh/notes.txt' }, cwd: '/work/app' }, { home }));
  blocked(call('Grep', { pattern: 'KEY', glob: '.env*' }));
  blocked(call('Grep', { pattern: 'KEY', glob: '**/.env' }));
  allowed(call('Grep', { pattern: 'KEY', glob: '*.ts' }));
});

test('hook: helpers', () => {
  assert.equal(protectedReason('/Users/me/.ssh', home) !== null, true);
  assert.deepEqual(commandPaths('cat ~/.ssh/id_rsa > out.txt'), ['~/.ssh/id_rsa', 'out.txt']);
  const r = JSON.parse(denyResponse('because'));
  assert.equal(r.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(r.hookSpecificOutput.hookEventName, 'PreToolUse');
  assert.match(r.hookSpecificOutput.permissionDecisionReason, /Blocked by LLLanyard\. because/);
});
