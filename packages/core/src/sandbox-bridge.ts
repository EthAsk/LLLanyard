import { spawn } from 'node:child_process';
import net from 'node:net';

/**
 * Runs INSIDE the sandbox. The sandbox has no network at all except its own loopback, so this listens on
 * 127.0.0.1:<port> and forwards every connection to the host's egress proxy over a unix socket. That proxy is the
 * only way out, and it only allows approved hosts.
 */
export function startBridge(socketPath: string, port: number): Promise<net.Server> {
  const server = net.createServer((c) => {
    const up = net.connect(socketPath);
    c.on('error', () => up.destroy());
    up.on('error', () => c.destroy());
    c.pipe(up);
    up.pipe(c);
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

async function main() {
  const argv = process.argv.slice(2);
  const dd = argv.indexOf('--');
  const [socket, portStr] = argv.slice(0, dd);
  const cmd = argv.slice(dd + 1);
  const port = Number(portStr);
  if (dd < 0 || !socket || !Number.isInteger(port) || !cmd.length) {
    process.stderr.write('lllanyard-bridge: internal use only\n');
    process.exit(2);
  }
  await startBridge(socket, port);
  const child = spawn(cmd[0]!, cmd.slice(1), { stdio: 'inherit' });
  for (const s of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) process.on(s, () => child.kill(s));
  child.once('error', (e) => { process.stderr.write(`lllanyard: could not start tool: ${e.message}\n`); process.exit(127); });
  child.once('close', (code, sig) => process.exit(code ?? (sig ? 128 + 15 : 1)));
}

// Only run as a program, never when imported (tests import startBridge).
if (process.argv[1] && /sandbox-bridge\.[cm]?[jt]s$/.test(process.argv[1])) void main();
