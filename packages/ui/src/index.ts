import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  AgentStore, FREE_LIMITS, KeyringStore, LicenseStore, ProviderStore, StoreError, allProviders, askLocalModel, assertLocalEndpoint, backendKind,
  buildFacts, defaultBackend, readUsage, rotationStatus, ruleBasedReview, sandboxSelfTest, summarize, usageLogPath, DEFAULT_ASSISTANT,
  type AssistantConfig, type Launch, withClaudeDesktopClosed, claudeDesktopRunning, canRestartClaudeDesktop, claudeCodeStatus, claudeDesktopStatus, connectClaudeCode, connectClaudeDesktop, disconnectClaudeCode, disconnectClaudeDesktop, ToolStore, createBackup, describeItem, findCommand, pinScript, pinFiles, bindingsForKeys, readBackup, restoreBackup,
} from '@lllanyard/core';
import { startProxy } from '@lllanyard/proxy';
import { createUiServer, type UiDeps } from './server.js';

export { createUiServer } from './server.js';
export type { UiDeps } from './server.js';

const CONFIG_SLOT = '__assistant__';

/** Wires the UI server to the real key stores. */
export function realDeps(opts: { proxyPort: number; launch?: Launch }): UiDeps {
  const backend = () => defaultBackend();
  const keys = () => new KeyringStore(undefined, { maxKeys: new LicenseStore().limits().maxKeys });
  const loadCfg = (): AssistantConfig => { try { const v = backend().get(CONFIG_SLOT); return v ? { ...DEFAULT_ASSISTANT, ...JSON.parse(v) } : DEFAULT_ASSISTANT; } catch { return DEFAULT_ASSISTANT; } };
  let proxy: { close: () => void; port: number } | undefined;
  let sandbox: ReturnType<typeof sandboxSelfTest> | undefined;

  const usage = (days: number) => { const since = Date.now() - days * 86400_000; return summarize(readUsage(usageLogPath(), since), since); };

  return {
    state: () => {
      const lic = new LicenseStore();
      const st = lic.status();
      const list = keys().list();
      sandbox ??= sandboxSelfTest();
      return {
        keys: list.map((m) => { const r = rotationStatus(m); return { provider: m.provider, label: m.label, last4: m.last4, envName: m.envName, state: r.state, dueInDays: r.dueInDays, rotateUrl: r.rotateUrl }; }),
        agents: new AgentStore().list(),
        providers: Object.keys(allProviders(new ProviderStore())),
        customProviders: new ProviderStore().list(),
        tools: new ToolStore().list().map((t) => ({
          name: t.name, command: t.command, args: t.args, env: t.env, allowArgs: Boolean(t.allowArgs), pinned: (t.scriptSha256 ? 1 : 0) + Object.keys(t.pins ?? {}).length,
          passEnv: t.passEnv ?? [], allowHosts: t.allowHosts ?? [], sandbox: Boolean(t.sandbox),
        })),
        license: { tier: st.tier, payload: st.payload ? { seats: st.payload.seats, exp: st.payload.exp } : undefined, problem: st.problem },
        limits: { maxKeys: lic.limits().maxKeys, maxAgents: lic.maxAgents() },
        usage: usage(7),
        proxy: { running: Boolean(proxy), port: proxy?.port ?? opts.proxyPort },
        backend: backendKind(),
        sandbox,
        assistant: loadCfg(),
        freeLimits: FREE_LIMITS,
        apps: { claudeDesktop: { ...claudeDesktopStatus(), running: claudeDesktopRunning(), canRestart: canRestartClaudeDesktop() }, claudeCode: claudeCodeStatus(), canConnect: Boolean(opts.launch) },
      };
    },
    addKey: (b) => { keys().set(b.provider, b.secret, { label: b.label, rotateAfterDays: b.rotateDays, envName: b.envName }); },
    removeKey: (p, l) => keys().remove(p, l),
    createAgent: (b) => {
      const lic = new LicenseStore(), agents = new AgentStore();
      if (!agents.list().some((a) => a.name === b.name.toLowerCase()) && agents.list().length >= lic.maxAgents())
        throw new StoreError(`${lic.status().tier === 'free' ? 'Free tier allows' : 'Your license allows'} ${lic.maxAgents()} agents. Revoke one or upgrade.`);
      const prov = b.providers?.map((p) => p.trim().toLowerCase()).filter(Boolean);
      return agents.create(b.name, b.client, prov?.length ? prov : undefined, b.expiresDays ? { expiresAt: new Date(Date.now() + b.expiresDays * 86400_000) } : {});
    },
    revokeAgent: (n) => new AgentStore().revoke(n),
    activateLicense: (k) => { const p = new LicenseStore().activate(k); return { tier: p.tier, seats: p.seats, exp: p.exp }; },
    removeLicense: () => new LicenseStore().remove(),
    review: async ({ question, useModel }) => {
      const facts = buildFacts(keys().list(), usage(7));
      if (!useModel) return { text: ruleBasedReview(facts), source: 'rules' };
      try { return { text: await askLocalModel(loadCfg(), facts, question), source: 'model' }; }
      catch (e) { return { text: ruleBasedReview(facts), source: 'rules', note: `Local model unavailable: ${(e as Error).message}` }; }
    },
    setAssistant: (b) => { assertLocalEndpoint(b.endpoint); backend().set(CONFIG_SLOT, JSON.stringify({ endpoint: b.endpoint, model: b.model, kind: b.kind })); },
    proxy: async (action) => {
      if (action === 'start' && !proxy) { const s = await startProxy({ port: opts.proxyPort }); proxy = { close: s.close, port: s.port }; }
      if (action === 'stop' && proxy) { proxy.close(); proxy = undefined; }
      return { running: Boolean(proxy) };
    },
    addProvider: (b) => {
      if (b.auth === 'header' && !b.header) throw new StoreError('Header auth needs a header name (e.g. X-API-KEY).');
      new ProviderStore().set({ id: b.id, upstream: b.upstream, auth: b.auth === 'header' ? { type: 'header', name: b.header!, ...(b.prefix ? { prefix: b.prefix } : {}) } : { type: 'bearer' } });
    },
    removeProvider: (id) => new ProviderStore().remove(id),
    addTool: (b) => {
      // Same as `tool add`: the command is pinned to one binary and a script to its current contents. Relative paths
      // would depend on where the UI was started, so scripts are resolved from the home folder.
      const command = findCommand(b.command);
      const { args, scriptSha256 } = pinScript(command, b.args, os.homedir());
      const env = { ...bindingsForKeys(b.keys, keys()), ...b.env };
      const pins = b.pins.length ? pinFiles(b.pins, os.homedir()) : undefined;
      const t = new ToolStore().set({ name: b.name, command, args, scriptSha256, pins, env, scrub: true, allowArgs: b.allowArgs,
        passEnv: b.passEnv.length ? b.passEnv : undefined, allowHosts: b.allowHosts.length ? b.allowHosts : undefined });
      return { name: t.name, command: t.command, args: t.args };
    },
    removeTool: (n) => new ToolStore().remove(n),
    setup: async (b) => {
      if (b.app === 'claude-code') return b.remove ? disconnectClaudeCode() : connectClaudeCode();
      if (b.remove) return withClaudeDesktopClosed(() => disconnectClaudeDesktop(), { restart: b.restart });
      const launch = opts.launch;
      if (!launch) throw new StoreError('Start the app with `lllanyard ui` to connect Claude Desktop.');
      return withClaudeDesktopClosed(() => connectClaudeDesktop(launch, b.scriptDirs), { restart: b.restart });
    },
    setKeyEnv: (b) => { keys().setEnvName(b.provider, b.label, b.envName); },
    backup: (passphrase) => {
      const { text, items } = createBackup(passphrase);
      if (!items.length) throw new StoreError('Nothing to back up yet.');
      const file = path.join(os.homedir(), `lllanyard-backup-${new Date().toISOString().slice(0, 19).replace(/[-:]/g, '').replace('T', '-')}.enc`);
      mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      try { writeFileSync(file, text, { mode: 0o600, flag: 'wx' }); }
      catch (e: any) { throw e.code === 'EEXIST' ? new StoreError(`${file} already exists; try again in a second.`) : e; }
      return { file, items: items.map(describeItem) };
    },
    restore: (b) => {
      const payload = readBackup(b.text, b.passphrase);
      const r = restoreBackup(payload, undefined, { overwrite: b.overwrite, dryRun: b.dryRun, maxKeys: new LicenseStore().limits().maxKeys });
      return {
        createdAt: payload.createdAt, dryRun: b.dryRun,
        added: r.added.map(describeItem), replaced: r.replaced.map(describeItem), kept: r.kept.map(describeItem),
        invalid: r.invalid.map((x) => ({ item: describeItem(x.item), reason: x.reason })),
      };
    },
    isUserError: (e) => e instanceof StoreError || (e instanceof Error && /^(Port \d+ is already|Not a LLLanyard|Signature|License|The assistant only|Assistant endpoint|This build has no license)/.test(e.message)),
    log: (m) => process.stderr.write(`lllanyard-ui: ${m}\n`),
  };
}

/** Starts the UI on loopback. Returns the private URL (it contains the session secret in the fragment). */
export function startUi(opts: { port?: number; proxyPort: number; deps?: UiDeps; launch?: Launch }): Promise<{ url: string; port: number; close: () => void }> {
  const { server, token } = createUiServer(opts.deps ?? realDeps({ proxyPort: opts.proxyPort, launch: opts.launch }));
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port ?? 0, '127.0.0.1', () => {
      const port = (server.address() as import('node:net').AddressInfo).port;
      resolve({ url: `http://127.0.0.1:${port}/#s=${token}`, port, close: () => server.close() });
    });
  });
}

/** Opens the default browser with a fixed command per OS (the URL is the only argument; no shell). */
export function openBrowser(url: string, platform = process.platform) {
  const [cmd, args] = platform === 'darwin' ? ['open', [url]] : platform === 'win32' ? ['rundll32', ['url.dll,FileProtocolHandler', url]] : ['xdg-open', [url]];
  try { spawn(cmd as string, args as string[], { stdio: 'ignore', detached: true }).on('error', () => {}).unref(); } catch { /* user can paste the URL */ }
}
