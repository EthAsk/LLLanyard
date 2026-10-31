import { spawn as nodeSpawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import type { Writable } from 'node:stream';
import { chmodSync, existsSync, mkdtempSync, realpathSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import { createRequire } from 'node:module';
import path from 'node:path';
import { createScrubber } from './scrub.js';
import { defaultHome, proxyEnv, resolveCommand, sandboxCommand, sandboxKindFor, sandboxSelfTest, type SelfTest } from './sandbox.js';
import { StoreError } from './storage/keyring-store.js';
import type { SecureStore } from './storage/types.js';
import { assertEnvName, changedPins, parseKeyRef, type ToolDef } from './tools.js';

export type RunnableTool = Pick<ToolDef, 'command' | 'args' | 'env' | 'scrub'> & Partial<Pick<ToolDef, 'killOnLeak' | 'inheritEnv' | 'passEnv' | 'allowHosts' | 'sandbox' | 'shareRo' | 'shareRw' | 'scriptSha256' | 'pins'>>;

export interface RunDeps {
  store: Pick<SecureStore, 'get'>;
  env?: NodeJS.ProcessEnv; // base environment (default: process.env)
  stdout?: Writable;
  stderr?: Writable;
  spawn?: typeof nodeSpawn;
  platform?: NodeJS.Platform;
  egress?: { env: Record<string, string>; close: () => void; socketPath?: string; password?: string }; // from the egress allowlist proxy, if enabled
  cwd?: string;
  home?: string;
  selfTest?: () => SelfTest; // test hook
  tty?: boolean; // run in a pseudo-terminal (default: when our stdin and stdout are a terminal)
  loadPty?: () => PtyModule | null; // test hook
  stdin?: NodeJS.ReadStream; // test hook (default: process.stdin)
  noStdin?: boolean; // give the tool no input (an MCP server's stdin is its protocol channel, which the tool must not read)
  signal?: AbortSignal; // aborting stops the tool (e.g. a time limit)
}

/** What a tool may inherit by default. Everything else (other API keys, cloud credentials, tokens) stays behind. */
const BASE_ENV = new Set([
  'PATH', 'PATHEXT', 'HOME', 'USER', 'USERNAME', 'LOGNAME', 'SHELL', 'LANG', 'LANGUAGE', 'TERM', 'TZ',
  'TMPDIR', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)',
  'SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR', 'COMSPEC', 'OS',
  'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR',
  'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE',
]);

export function minimalEnv(base: NodeJS.ProcessEnv, pass: string[] = []): NodeJS.ProcessEnv {
  const extra = new Set(pass.map((n) => n.toUpperCase()));
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(base)) {
    const u = k.toUpperCase();
    if (v !== undefined && (BASE_ENV.has(u) || u.startsWith('LC_') || extra.has(u))) out[k] = v;
  }
  return out;
}

/**
 * Interactive programs (PowerShell's Read-Host, prompts, colour) need a real terminal, but scrubbing needs the output
 * piped through us. The system `script` command gives the tool its own pseudo-terminal, sized like ours, and we
 * scrub what comes out of it. Returns null where that isn't available, so the tool runs with plain pipes.
 */
export function ptyCommand(platform: NodeJS.Platform, command: string, args: string[], findScript = () => findOnPath('script')): { command: string; args: string[] } | null {
  if (platform !== 'darwin' && platform !== 'linux') return null;
  const script = findScript();
  if (!script) return null;
  if (platform === 'darwin') return { command: script, args: ['-q', '/dev/null', command, ...args] };
  const q = (a: string) => `'${a.replace(/'/g, `'\\''`)}'`;
  return { command: script, args: ['-q', '-e', '-c', [command, ...args].map(q).join(' '), '/dev/null'] };
}

function findOnPath(name: string): string | null {
  for (const dir of ['/usr/bin', '/bin']) if (existsSync(path.join(dir, name))) return path.join(dir, name);
  return null;
}

/** The parts of node-pty we use (declared here so node-pty stays an optional dependency). */
export interface Pty {
  onData(cb: (data: string) => void): unknown;
  onExit(cb: (e: { exitCode: number; signal?: number }) => void): unknown;
  write(data: string | Buffer): void;
  resize(cols: number, rows: number): void;
  kill(signal?: string): void;
}
export interface PtyModule {
  spawn(file: string, args: string[], opts: { name: string; cols: number; rows: number; cwd: string; env: Record<string, string> }): Pty;
}

let cachedPty: PtyModule | null | undefined;
/** Loads node-pty if it's installed and has a build for this system; otherwise null (we fall back). */
export function loadPty(): PtyModule | null {
  if (cachedPty !== undefined) return cachedPty;
  cachedPty = null;
  try {
    const req = createRequire(import.meta.url);
    const mod = req('node-pty') as PtyModule;
    // node-pty's macOS helper must be executable. Its install script sets that, but recent npm versions skip
    // install scripts by default, so set it here (it's our own dependency's file; failure just means fallback).
    try {
      const dir = path.dirname(req.resolve('node-pty/package.json'));
      for (const sub of [`prebuilds/${process.platform}-${process.arch}`, 'build/Release']) {
        const helper = path.join(dir, sub, 'spawn-helper');
        if (existsSync(helper)) { const mode = statSync(helper).mode; if (!(mode & 0o111)) chmodSync(helper, mode | 0o755); }
      }
    } catch { /* not fatal */ }
    cachedPty = mod;
  } catch { /* not installed or no build for this system */ }
  return cachedPty;
}

/** Starts the tool in a node-pty terminal. Returns null if it couldn't start (the caller then falls back). */
function startInPty(
  pty: PtyModule, launch: { command: string; args: string[] }, env: NodeJS.ProcessEnv, secrets: string[],
  onRedacted: (n: number) => void, deps: RunDeps, platform: NodeJS.Platform,
): { done: Promise<number>; kill: () => void } | null {
  const out = deps.stdout ?? process.stdout;
  const stdin = deps.stdin ?? process.stdin;
  const cleanEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) if (v !== undefined) cleanEnv[k] = v;
  let term: Pty;
  try {
    term = pty.spawn(launch.command, launch.args, {
      name: cleanEnv.TERM || 'xterm-256color', cols: process.stdout.columns || 80, rows: process.stdout.rows || 24,
      cwd: deps.cwd ?? process.cwd(), env: cleanEnv,
    });
  } catch {
    return null;
  }
  const kill = (sig: NodeJS.Signals = 'SIGKILL') => { try { platform === 'win32' ? term.kill() : term.kill(sig); } catch { /* already gone */ } };

  // Everything the tool prints (stdout and stderr share the terminal) goes through the scrubber.
  const so = createScrubber(secrets);
  so.on('redacted', onRedacted);
  so.pipe(out, { end: false });
  term.onData((d) => so.write(d));

  // Keystrokes go to the tool unchanged; Ctrl+C reaches it as a keystroke, as in a normal terminal.
  const wasRaw = Boolean(stdin.isRaw);
  const onInput = (d: Buffer) => term.write(d);
  if (stdin.isTTY) stdin.setRawMode(true);
  stdin.on('data', onInput);
  stdin.resume();
  const onResize = () => { try { term.resize(process.stdout.columns || 80, process.stdout.rows || 24); } catch { /* exited */ } };
  process.stdout.on('resize', onResize);
  const handlers = (['SIGTERM', 'SIGHUP'] as const).map((s) => [s, () => kill(s)] as const);
  for (const [s, h] of handlers) process.on(s, h);
  const onExit = () => kill();
  process.on('exit', onExit);

  const done = new Promise<number>((resolve) => {
    term.onExit(({ exitCode, signal }) => {
      // On Windows node-pty keeps a reader thread alive until kill(), which would stop us from ever exiting.
      if (platform === 'win32') kill();
      stdin.off('data', onInput);
      if (stdin.isTTY) stdin.setRawMode(wasRaw);
      stdin.pause();
      process.stdout.off('resize', onResize);
      for (const [s, h] of handlers) process.off(s, h);
      process.off('exit', onExit);
      const code = signal ? 128 + signal : exitCode;
      so.once('end', () => resolve(code));
      so.end();
      so.resume();
    });
  });
  return { done, kill: () => kill() };
}

const WIN_SAFE_ARG = /^[A-Za-z0-9@%+=:,./\\_-]+$/;
const SIGNALS: Record<string, number> = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGKILL: 9, SIGTERM: 15 };
export const LEAK_EXIT_CODE = 70;

/**
 * Resolves bindings, starts the command with the keys in ITS environment only, and returns its exit code.
 * Safeguards: minimal inherited environment, output scrubbing (incl. base64/hex/URL forms), leak warning or kill,
 * optional egress allowlist (via deps.egress), and the child is stopped if this process exits.
 */
export async function runTool(def: RunnableTool, deps: RunDeps): Promise<number> {
  const secrets: Record<string, string> = {};
  let runTmp: string | undefined;
  try {
    const changed = changedPins(def);
    if (changed.length) throw new StoreError(`${changed.join(', ')} ${changed.length > 1 ? 'have' : 'has'} changed (or is missing) since this tool was approved, so it was NOT started. Review the change, then approve it again with: lllanyard tool add`);
    for (const [name, ref] of Object.entries(def.env)) {
      assertEnvName(name);
      const { provider, label } = parseKeyRef(ref);
      const v = deps.store.get(provider, label);
      if (!v) throw new StoreError(`No key stored for ${provider}:${label} (needed for ${name}). Add it with: lllanyard add ${provider}${label === 'default' ? '' : ` --label ${label}`}`);
      secrets[name] = v;
    }

    const platform = deps.platform ?? process.platform;
    const base = deps.env ?? process.env;
    const env: NodeJS.ProcessEnv = { ...(def.inheritEnv ? base : minimalEnv(base, def.passEnv)), ...(deps.egress?.env ?? {}), ...secrets };

    // Sandbox: fail closed. If we can't actually start one, we do not run the tool without it.
    let launch = { command: def.command, args: def.args };
    if (def.sandbox) {
      const test = (deps.selfTest ?? (() => sandboxSelfTest(platform)))();
      const kind = sandboxKindFor(platform);
      if (!test.ok || !kind) throw new StoreError(`Sandbox requested but unavailable, so the tool was NOT started. ${test.reason ?? ''}`.trim());
      let network: { socketPath: string; port: number } | null = null;
      if (def.allowHosts?.length) {
        const eg = deps.egress;
        if (!eg) throw new StoreError('Sandboxed tool needs its egress proxy, which is not running; refusing to start.');
        if (kind === 'bwrap') {
          if (!eg.socketPath || !eg.password) throw new StoreError('Sandboxed tool needs a unix-socket egress proxy; refusing to start.');
          network = { socketPath: eg.socketPath, port: 20000 + Math.floor(Math.random() * 40000) };
          Object.assign(env, proxyEnv(`http://lly:${eg.password}@127.0.0.1:${network.port}`));
        } else {
          const m = /:(\d+)$/.exec(String(eg.env.HTTPS_PROXY ?? ''));
          if (!m) throw new StoreError('Sandboxed tool needs a TCP egress proxy; refusing to start.');
          network = { socketPath: '', port: Number(m[1]) };
        }
      }
      for (const k of ['XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'SSH_AUTH_SOCK']) delete env[k];
      const home = deps.home ?? defaultHome();
      if (kind === 'seatbelt') {
        // macOS: the tool may only write to its own temp directory, removed afterwards (Linux gets a private /tmp).
        runTmp = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'lllanyard-run-')));
        env.TMPDIR = env.TMP = env.TEMP = runTmp + path.sep;
      }
      launch = sandboxCommand({
        kind, command: resolveCommand(def.command, env.PATH ?? base.PATH), args: def.args, cwd: deps.cwd ?? process.cwd(), home,
        ro: def.shareRo ?? [], rw: def.shareRw ?? [], network, tty: Boolean(process.stdin.isTTY), tmp: runTmp,
      });
    }

    // Windows can't spawn .cmd/.bat shims (npx, npm) without a shell, so those get a shell but only with plain-looking args.
    const winShell = platform === 'win32' && /\.(cmd|bat)$|^(npx|npm|pnpm|yarn)$/i.test(def.command);
    if (winShell) for (const a of [def.command, ...def.args]) if (!WIN_SAFE_ARG.test(a)) throw new StoreError(`Argument "${a}" is not allowed when running through the Windows shell.`);

    const scrub = def.scrub !== false;
    const errOut = deps.stderr ?? process.stderr;
    let leaks = 0;
    let leakKilled = false;
    let stop = () => {};
    deps.signal?.addEventListener('abort', () => stop(), { once: true });
    const onRedacted = (n: number) => {
      const first = leaks === 0;
      leaks += n;
      if (first) errOut.write('lllanyard: warning: this tool printed its API key (redacted). It may be misbehaving or compromised.\n');
      if (def.killOnLeak && !leakKilled) {
        leakKilled = true;
        errOut.write('lllanyard: stopping the tool (kill-on-leak is on).\n');
        stop();
      }
    };

    // Interactive use: give the tool a real terminal (prompts, colour, window size) and still scrub what it prints.
    // node-pty works on macOS, Linux and Windows (ConPTY); the system `script` command is the fallback on macOS/Linux.
    const tty = deps.tty ?? (!deps.stdout && !deps.noStdin && Boolean(process.stdin.isTTY && process.stdout.isTTY));
    if (scrub && tty && !winShell) {
      const pty = (deps.loadPty ?? loadPty)();
      const viaPty = pty && startInPty(pty, launch, env, Object.values(secrets), onRedacted, deps, platform);
      if (viaPty) {
        stop = viaPty.kill;
        const code = await viaPty.done;
        return leakKilled ? LEAK_EXIT_CODE : code;
      }
      launch = ptyCommand(platform, launch.command, launch.args) ?? launch;
    }

    const opts: SpawnOptions = { env, cwd: deps.cwd, shell: winShell, stdio: [deps.noStdin ? 'ignore' : 'inherit', scrub ? 'pipe' : 'inherit', scrub ? 'pipe' : 'inherit'] };
    const child: ChildProcess = (deps.spawn ?? nodeSpawn)(launch.command, launch.args, opts);
    stop = () => { child.kill('SIGKILL'); };
    if (scrub) {
      const values = Object.values(secrets);
      const so = createScrubber(values), se = createScrubber(values);
      so.on('redacted', onRedacted);
      se.on('redacted', onRedacted);
      child.stdout?.pipe(so).pipe(deps.stdout ?? process.stdout);
      child.stderr?.pipe(se).pipe(errOut);
    }

    // The tool must not outlive us, and signals must reach it.
    const forward = (sig: NodeJS.Signals) => () => { child.kill(sig); };
    const handlers = (['SIGINT', 'SIGTERM', 'SIGHUP'] as const).map((s) => [s, forward(s)] as const);
    for (const [s, h] of handlers) process.on(s, h);
    const onExit = () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); };
    process.on('exit', onExit);

    try {
      return await new Promise<number>((resolve, reject) => {
        child.once('error', (e: NodeJS.ErrnoException) =>
          reject(new Error(e.code === 'ENOENT' ? `Command not found: ${def.command}` : `Could not start ${def.command}: ${e.message}`)));
        // 'close' fires after stdio has drained, so no scrubbed output is lost.
        child.once('close', (code, signal) => resolve(leakKilled ? LEAK_EXIT_CODE : code ?? (signal ? 128 + (SIGNALS[signal] ?? 15) : 1)));
      });
    } finally {
      for (const [s, h] of handlers) process.off(s, h);
      process.off('exit', onExit);
    }
  } finally {
    deps.egress?.close();
    if (runTmp) rmSync(runTmp, { recursive: true, force: true });
  }
}
