import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { StoreError } from './storage/keyring-store.js';

// Sandbox profiles always describe a Linux or macOS system, so their paths follow POSIX rules on any host.
const posix = path.posix;

export type SandboxKind = 'bwrap' | 'seatbelt';

export interface SandboxSpec {
  kind: SandboxKind;
  command: string; // absolute path
  args: string[];
  cwd: string;
  home: string;
  ro: string[]; // extra read-only paths
  rw: string[]; // extra read-write paths
  network: { socketPath: string; port: number } | null; // null = no network at all
  tty: boolean;
  tmp?: string; // private temp directory for this run (macOS; required there). Linux gets a private /tmp anyway.
  // injectable for tests
  nodePath?: string;
  bridgePath?: string;
  fsLayout?: (p: string) => 'symlink' | 'dir' | 'missing';
}

/** Directories under $HOME (and system paths) that a tool may never be given, however it is configured. */
const SENSITIVE_HOME = ['.ssh', '.aws', '.gnupg', '.kube', '.docker', '.azure', '.config/gcloud', '.config/gh', '.config/op', '.local/share/keyrings', '.netrc', '.npmrc', '.pypirc', 'Library/Keychains', 'AppData'];
const SYSTEM_DENY = ['/', '/etc', '/proc', '/sys', '/dev', '/run', '/var/run', '/root', '/home', '/Users', '/var', '/private', '/boot'];

const inside = (p: string, dir: string) => p === dir || p.startsWith(dir.endsWith('/') ? dir : dir + '/');

/** Throws unless `p` is safe to expose to a sandboxed tool. */
export function assertSafeMount(p: string, home: string, what = 'path'): string {
  if (!posix.isAbsolute(p) || /[\0-\x1f"\\]/.test(p)) throw new StoreError(`Sandbox ${what} must be a plain absolute path: ${JSON.stringify(p)}`);
  const n = posix.normalize(p).replace(/\/+$/, '') || '/';
  if (SYSTEM_DENY.includes(n)) throw new StoreError(`Refusing to expose ${n} to a sandboxed tool.`);
  if (n === home || inside(home, n)) throw new StoreError(`Refusing to expose your whole home directory (${n}). Share a specific project folder instead.`);
  for (const s of SENSITIVE_HOME) {
    const bad = posix.join(home, s);
    if (inside(n, bad) || inside(bad, n)) throw new StoreError(`Refusing to expose ${n}: it contains or is inside ${bad}, which holds credentials.`);
  }
  return n;
}

const defaultLayout = (p: string): 'symlink' | 'dir' | 'missing' => {
  try { return lstatSync(p).isSymbolicLink() ? 'symlink' : 'dir'; } catch { return 'missing'; }
};

/** Linux: bubblewrap argv (without the leading "bwrap"). Pure, so it is unit-tested. */
export function bwrapArgs(s: SandboxSpec): string[] {
  const layout = s.fsLayout ?? defaultLayout;
  const home = posix.normalize(s.home);
  const cwd = assertSafeMount(s.cwd, home, 'working directory');
  const a: string[] = ['--die-with-parent', '--unshare-all', '--cap-drop', 'ALL'];
  if (!s.tty) a.push('--new-session'); // blocks TIOCSTI keystroke injection; breaks job control, so only for non-interactive runs

  // Minimal, read-only system: no /home, /root, /run (so no D-Bus/keyring sockets), no /var/run/docker.sock.
  for (const d of ['/usr', '/bin', '/sbin', '/lib', '/lib32', '/lib64']) {
    const k = layout(d);
    if (k === 'dir') a.push('--ro-bind', d, d);
    else if (k === 'symlink') a.push('--symlink', `usr${d}`, d);
  }
  for (const f of ['/etc/ssl', '/etc/ca-certificates', '/etc/pki', '/etc/alternatives', '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/ld.so.conf.d', '/etc/nsswitch.conf', '/etc/passwd', '/etc/group', '/etc/localtime', '/etc/mime.types']) a.push('--ro-bind-try', f, f);
  a.push('--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/var/tmp');
  a.push('--tmpfs', home); // an empty, throwaway home: no ~/.ssh, ~/.aws, browser profiles, shell history

  const node = s.nodePath ?? process.execPath;
  const bridge = s.bridgePath ?? posix.join(posix.dirname(fileURLToPath(import.meta.url)), 'sandbox-bridge.js');
  const roSeen = new Set<string>();
  const ro = (p: string) => { if (!inside(p, '/usr') && !roSeen.has(p)) { roSeen.add(p); a.push('--ro-bind', p, p); } };
  if (s.network) {
    ro(posix.dirname(posix.dirname(node)) === '/' ? posix.dirname(node) : posix.dirname(posix.dirname(node)));
    ro(posix.dirname(bridge));
    a.push('--bind', posix.dirname(s.network.socketPath), posix.dirname(s.network.socketPath)); // private dir holding only the egress socket
  }
  for (const p of s.ro) ro(assertSafeMount(p, home, 'read-only path'));
  const cmdDir = posix.dirname(s.command);
  if (!inside(cmdDir, '/usr') && !inside(cmdDir, '/bin') && !inside(cmdDir, '/sbin')) ro(assertSafeMount(cmdDir, home, 'command directory'));
  for (const p of [cwd, ...s.rw]) a.push('--bind', assertSafeMount(p, home, 'writable path'), p === cwd ? cwd : posix.normalize(p));
  a.push('--chdir', cwd);
  a.push('--unsetenv', 'DBUS_SESSION_BUS_ADDRESS', '--unsetenv', 'XDG_RUNTIME_DIR', '--unsetenv', 'SSH_AUTH_SOCK');
  a.push('--');
  if (s.network) a.push(node, bridge, s.network.socketPath, String(s.network.port), '--');
  a.push(s.command, ...s.args);
  return a;
}

const q = (p: string) => `"${p.replace(/[\\"]/g, '\\$&')}"`;

/** macOS: Seatbelt profile. Allow-by-default with the sensitive things denied (later rules win in SBPL). */
export function seatbeltProfile(s: SandboxSpec): string {
  const home = posix.normalize(s.home);
  const cwd = assertSafeMount(s.cwd, home, 'working directory');
  const lines = ['(version 1)', '(allow default)'];
  // Network: nothing, except loopback to the egress proxy port.
  lines.push('(deny network*)');
  if (s.network) lines.push(`(allow network-outbound (remote ip "localhost:${Number(s.network.port) | 0}"))`);
  // Files: the home directory is unreadable except the project, explicit shares and the tool's own directory.
  lines.push(`(deny file-read* (subpath ${q(home)}))`);
  const allowRead = new Set<string>([cwd, ...s.ro.map((p) => assertSafeMount(p, home, 'read-only path')), ...s.rw.map((p) => assertSafeMount(p, home, 'writable path'))]);
  const cmdDir = posix.dirname(s.command);
  if (inside(cmdDir, home)) allowRead.add(assertSafeMount(cmdDir, home, 'command directory'));
  for (const p of allowRead) lines.push(`(allow file-read* (subpath ${q(p)}))`);
  // Writes: only the project, explicit shares and this run's own temp directory (not the shared temp folders,
  // where it could tamper with other programs' files).
  if (!s.tmp || !posix.isAbsolute(s.tmp)) throw new StoreError('Sandbox needs a private temp directory; refusing to start.');
  lines.push('(deny file-write*)');
  for (const p of [cwd, ...s.rw.map((p) => assertSafeMount(p, home, 'writable path'))]) lines.push(`(allow file-write* (subpath ${q(p)}))`);
  lines.push(`(allow file-write* (subpath ${q(posix.normalize(s.tmp))}))`);
  for (const p of ['/dev/null', '/dev/tty']) lines.push(`(allow file-write* (literal ${q(p)}))`);
  // Keychain access via system services.
  lines.push('(deny mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd") (global-name "com.apple.secd") (global-name "com.apple.security.agent"))');
  lines.push('(deny file-read* (subpath "/Library/Keychains") (subpath "/private/var/db/mds"))');
  return lines.join('\n') + '\n';
}

/** The command line to actually spawn (sandbox launcher + its arguments). */
export function sandboxCommand(s: SandboxSpec): { command: string; args: string[] } {
  if (s.kind === 'bwrap') return { command: 'bwrap', args: [...bwrapArgs(s)] };
  return { command: '/usr/bin/sandbox-exec', args: ['-p', seatbeltProfile(s), s.command, ...s.args] };
}

export function sandboxKindFor(platform: NodeJS.Platform): SandboxKind | undefined {
  return platform === 'linux' ? 'bwrap' : platform === 'darwin' ? 'seatbelt' : undefined;
}

export interface SelfTest { ok: boolean; kind?: SandboxKind; reason?: string }

/** Actually starts a throwaway sandbox. Used before every sandboxed run: if it fails we refuse, never run unprotected. */
export function sandboxSelfTest(platform: NodeJS.Platform = process.platform, run: typeof spawnSync = spawnSync): SelfTest {
  const kind = sandboxKindFor(platform);
  if (!kind) return { ok: false, reason: platform === 'win32' ? 'Sandboxing is not available on Windows yet (use WSL2 with Debian/Ubuntu). Run without --sandbox only if you accept the limits in the README.' : `No sandbox backend for ${platform}.` };
  const probe = kind === 'bwrap'
    ? run('bwrap', ['--unshare-all', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--', '/usr/bin/true'], { encoding: 'utf8', timeout: 10_000 })
    : run('/usr/bin/sandbox-exec', ['-p', '(version 1)(allow default)(deny network*)', '/usr/bin/true'], { encoding: 'utf8', timeout: 10_000 });
  if (probe.error) return { ok: false, kind, reason: kind === 'bwrap' ? 'bubblewrap is not installed. Install it: sudo apt install bubblewrap' : `sandbox-exec could not run: ${probe.error.message}` };
  if (probe.status !== 0) {
    const err = String(probe.stderr ?? '').trim();
    const hint = /namespace|permitted|EPERM|Operation not/i.test(err) ? ' (Ubuntu 24.04+ restricts unprivileged namespaces: allow bwrap via an AppArmor profile or `sysctl kernel.apparmor_restrict_unprivileged_userns=0`.)' : '';
    return { ok: false, kind, reason: `The sandbox could not start: ${err.split('\n')[0] ?? 'unknown error'}${hint}` };
  }
  return { ok: true, kind };
}

/** Resolve a bare command name via PATH to an absolute real path (sandboxes need one). */
export function resolveCommand(command: string, pathVar: string | undefined = process.env.PATH, cwd = process.cwd()): string {
  const cands = path.isAbsolute(command) ? [command] : command.includes('/') ? [path.resolve(cwd, command)] : (pathVar ?? '').split(path.delimiter).filter(Boolean).map((d) => path.join(d, command));
  for (const c of cands) if (existsSync(c)) return realpathSync(c);
  throw new StoreError(`Command not found: ${command}`);
}

export const defaultHome = () => os.homedir();

/** Proxy variables that make well-behaved tools send HTTPS through the egress proxy at `url`. */
export function proxyEnv(url: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) env[k] = url;
  env.NO_PROXY = ''; env.no_proxy = '';
  env.NODE_USE_ENV_PROXY = '1'; // makes recent Node versions honour the variables above
  return env;
}

export const isLoopbackHost = (h: string) => ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(h.toLowerCase());
