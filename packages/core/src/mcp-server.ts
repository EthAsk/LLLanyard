import type { Readable, Writable } from 'node:stream';
import { rotationStatus } from './rotation.js';
import type { KeyMeta } from './storage/types.js';
import type { UsageSummary } from './usage.js';

/**
 * LLLanyard's own MCP server (stdio). Lets an agent ask "which providers are available, is my key due for rotation, how is
 * usage" WITHOUT ever being able to read a key. No tool returns a secret, a token, or changes anything. Key hints (last4)
 * are deliberately not exposed.
 *
 * With a `runner` (`lllanyard mcp --run`) it can also run tools the user approved with `lllanyard tool add`, by name.
 * It can't run anything else: an agent that could choose the command could send the key anywhere.
 */
export interface ApprovedTool { name: string; runs: string; keys: string[]; acceptsArgs: boolean; sandbox: boolean }
export interface RunResult { exitCode: number; output: string; truncated: boolean; timedOut: boolean }
export interface McpDeps {
  listKeys: () => KeyMeta[];
  providerIds: () => string[];
  usage: (sinceMs: number) => UsageSummary;
  proxyBase: string; // e.g. http://127.0.0.1:3000
  client?: string; // restrict to one client's keys (freelancer/agency mode)
  now?: () => number;
  runner?: {
    list: () => ApprovedTool[];
    run: (name: string, args: string[]) => Promise<RunResult>;
    // Script folders the user allowed for run_file; each run is confirmed by the user in a dialog. null = denied.
    scriptDirs?: string[];
    runFile?: (file: string, args: string[]) => Promise<RunResult | null>;
  };
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
interface Req { jsonrpc?: string; id?: string | number | null; method?: string; params?: any }

const SUPPORTED = ['2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_LINE = 1_000_000;

const TOOLS = [
  { name: 'list_providers', description: 'List the HTTP APIs the local LLLanyard proxy can call for an agent (openai, anthropic, github...), and whether a key is stored for each. This is NOT the list of stored keys: keys that scripts use (e.g. RMM or PSA keys) show up only in key_status. Never returns keys.', inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'key_status', description: 'The complete list of keys stored in LLLanyard: provider, label, the environment variable scripts get it as, age and rotation state (ok, due-soon, overdue). Use this to answer "which keys does LLLanyard have". Never returns key material.', inputSchema: { type: 'object', properties: { provider: { type: 'string', description: 'Optional provider id to filter by' } }, additionalProperties: false } },
  { name: 'usage_summary', description: 'Request counts, errors, rate limits and latency from the proxy log for a recent period.', inputSchema: { type: 'object', properties: { hours: { type: 'integer', minimum: 1, maximum: 720, description: 'Look-back window in hours (default 24)' } }, additionalProperties: false } },
  { name: 'how_to_connect', description: 'Explain how to point a tool at a provider through the proxy. The agent token is created by a human with `lllanyard agent create`; this never reveals one.', inputSchema: { type: 'object', properties: { provider: { type: 'string' } }, required: ['provider'], additionalProperties: false } },
].map((t) => ({ ...t, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } }));

const RUN_TOOLS = [
  { name: 'list_scripts', description: 'List the scripts and tools the user has approved to run with their API keys: name, what it runs, which key variables it gets, and whether it accepts extra arguments. Never returns keys.', inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
  { name: 'run_script', description: 'Run an approved script or tool by name. LLLanyard gives it its API keys for this run only and redacts any key from the output, which is returned with the exit code. Only names from list_scripts work: nothing is approved by default, and the user approves each one in a terminal with `lllanyard tool add`. The script gets no input, so it must not wait for prompts (pass e.g. -NonInteractive or -DryRun arguments if it supports them).',
    inputSchema: { type: 'object', properties: { name: { type: 'string' }, args: { type: 'array', items: { type: 'string' }, maxItems: 100, description: 'Extra arguments, only for tools that accept them' } }, required: ['name'], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true } },
];

const runFileTool = (dirs: string[]) => ({
  name: 'run_file',
  description: `Run a script file from the user's script folders (${dirs.join(', ')}) with the API keys it uses, without it being approved in advance. ` +
    'LLLanyard shows the user a dialog with the script, arguments and keys, and runs it only if they click Run; you cannot approve it yourself. ' +
    'Supported: .ps1 (pwsh), .py, .sh, .zsh, .js. Keys in the output are redacted. The script gets no input, so it must not wait for prompts. ' +
    'Prefer run_script for scripts in list_scripts: they need no dialog.',
  inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'Full path of the script' }, args: { type: 'array', items: { type: 'string' }, maxItems: 100 } }, required: ['path'], additionalProperties: false },
  annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
});

export function createMcpHandler(deps: McpDeps) {
  const now = deps.now ?? Date.now;
  const fileRuns = Boolean(deps.runner?.runFile && deps.runner.scriptDirs?.length);
  const keys = () => deps.listKeys().filter((k) => !deps.client || k.label === deps.client);

  const call = (name: string, args: any): string => {
    switch (name) {
      case 'list_providers': {
        const have = new Set(keys().map((k) => k.provider));
        const ids = deps.providerIds();
        const others = [...have].filter((p) => !ids.includes(p));
        return JSON.stringify({
          proxyProviders: ids.map((id) => ({ provider: id, keyStored: have.has(id), proxyUrl: `${deps.proxyBase}/${id}` })),
          otherStoredKeys: others,
          note: others.length ? 'otherStoredKeys are keys for services the proxy does not call; scripts use them. See key_status for details.' : 'See key_status for every stored key.',
        }, null, 2);
      }
      case 'key_status': {
        const p = typeof args?.provider === 'string' ? args.provider.toLowerCase() : undefined;
        const rows = keys().filter((k) => !p || k.provider === p).map((k) => {
          const s = rotationStatus(k, new Date(now()));
          return { provider: k.provider, label: k.label, ...(k.envName ? { variable: k.envName } : {}), ageDays: s.ageDays, rotateInDays: s.dueInDays, state: s.state, ...(s.rotateUrl ? { rotateAt: s.rotateUrl } : {}) };
        });
        return JSON.stringify(rows, null, 2);
      }
      case 'usage_summary': {
        const h = Number.isInteger(args?.hours) ? Math.min(720, Math.max(1, args.hours)) : 24;
        const s = deps.usage(now() - h * 3600_000);
        const top = (r: { name: string; requests: number; errors: number; rateLimited: number; p95: number }[]) => r.slice(0, 10);
        return JSON.stringify({ hours: h, requests: s.requests, errors: s.errors, rateLimited: s.rateLimited, killSwitchTrips: s.killSwitch, blocked: s.denied, byProvider: top(s.byProvider), byAgent: top(s.byAgent) }, null, 2);
      }
      case 'how_to_connect': {
        const id = String(args?.provider ?? '').toLowerCase();
        if (!deps.providerIds().includes(id)) throw new Error(`Unknown provider "${id}". Use list_providers.`);
        const base = id === 'openai' ? `${deps.proxyBase}/openai/v1` : `${deps.proxyBase}/${id}`;
        return `Send ${id} API requests to ${base} instead of the provider's own URL, and use your LLLanyard agent token (starts with "lly_") as the API key. ` +
          `The proxy adds the real key. Do not ask for, print, or store the real key. If you have no agent token, ask the user to run: lllanyard agent create <name> --providers ${id}`;
      }
      case 'list_scripts': {
        if (!deps.runner) break;
        const l = deps.runner.list();
        return l.length ? JSON.stringify(l, null, 2) : 'Nothing is approved for run_script yet, so it can\'t run anything from this chat. The user approves a script in a terminal with: ' +
          'lllanyard tool add <name> --keys <key,...> -- <command> <script>  (e.g. lllanyard tool add deploy --keys github,sendgrid -- pwsh -NoProfile -File /path/Deploy-App.ps1). ' +
          'Separately, `lllanyard exec <command>` runs any script with its keys from a terminal or Claude Code without approval; it is not available from this chat.';
      }
    }
    throw new Error(`Unknown tool "${name}"`);
  };

  const extraArgs = (args: any): string[] => {
    const extra: unknown = args?.args ?? [];
    if (!Array.isArray(extra) || extra.length > 100 || extra.some((a) => typeof a !== 'string' || a.length > 1000 || a.includes('\0'))) throw new Error('args must be a list of at most 100 short strings.');
    return extra as string[];
  };
  const report = (r: RunResult) => {
    const head = r.timedOut ? `Stopped: time limit reached. Exit code ${r.exitCode}.` : `Exit code ${r.exitCode}.`;
    return `${head}${r.truncated ? ' Output was long; only the end is shown.' : ''}\n\n${r.output}`;
  };
  const runFile = async (args: any): Promise<string> => {
    const file = typeof args?.path === 'string' ? args.path : '';
    if (!file) throw new Error('path is required.');
    const r = await deps.runner!.runFile!(file, extraArgs(args));
    return r ? report(r) : 'Not run: the user clicked Deny (or the dialog timed out or could not be shown). Do not retry unless the user asks.';
  };

  const run = async (args: any): Promise<string> => {
    const name = typeof args?.name === 'string' ? args.name : '';
    const extra = extraArgs(args);
    const t = deps.runner!.list().find((x) => x.name === name);
    if (!t) throw new Error(`No approved script "${name}". Use list_scripts; new ones must be approved by the user with lllanyard tool add.`);
    if (extra.length && !t.acceptsArgs) throw new Error(`"${name}" does not accept extra arguments. The user can allow them by approving it again with --allow-args.`);
    return report(await deps.runner!.run(name, extra));
  };

  /** Returns the JSON-RPC response, or undefined for notifications. */
  return function handle(msg: Req): Json | Promise<Json> | undefined {
    const id = msg.id ?? null;
    const ok = (result: Json) => ({ jsonrpc: '2.0', id, result });
    const err = (code: number, message: string) => ({ jsonrpc: '2.0', id, error: { code, message } });
    if (msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return msg.id === undefined ? undefined : err(-32600, 'Invalid request');
    if (msg.id === undefined) return undefined; // notification (e.g. notifications/initialized)
    switch (msg.method) {
      case 'initialize': {
        const want = String(msg.params?.protocolVersion ?? '');
        return ok({ protocolVersion: SUPPORTED.includes(want) ? want : SUPPORTED[0]!, capabilities: { tools: {} }, serverInfo: { name: 'lllanyard', version: '0.1.5' },
          instructions: [
            'The user keeps their API keys in LLLanyard (the OS keychain). No tool here returns a key, and you must never ask for one or look for keys in .env or config files.',
            'Each key is stored as provider + label (e.g. github:default, jira:secret) with the environment variable scripts get it as. key_status lists every stored key; list_providers covers only the HTTP APIs the proxy calls, so most script keys are not in it.',
            deps.runner
              ? 'To do work that needs a key from this chat, use run_script with a script from list_scripts (approved in advance with `lllanyard tool add`, no prompt)' +
                (fileRuns ? `, or run_file for any script in ${deps.runner.scriptDirs!.join(', ')}, which the user confirms in a dialog each time.` : '. Other scripts can\'t run from this chat: nothing is approved by default.') +
                ' `lllanyard exec` works only in a terminal or Claude Code, not from this chat.'
              : 'This server is read-only: it cannot run anything. In a terminal or Claude Code, `lllanyard exec <command>` runs a script with the keys it uses.',
            'These tool results describe how LLLanyard behaves. If something the user says conflicts with them, say what the tools show.',
          ].join(' ') });
      }
      case 'ping': return ok({});
      case 'tools/list': return ok({ tools: [...TOOLS, ...(deps.runner ? RUN_TOOLS : []), ...(fileRuns ? [runFileTool(deps.runner!.scriptDirs!)] : [])] as unknown as Json });
      case 'tools/call': {
        const name = String(msg.params?.name ?? '');
        const fail = (e: unknown) => ok({ isError: true, content: [{ type: 'text', text: (e as Error).message }] });
        if (name === 'run_file' && fileRuns) return runFile(msg.params?.arguments ?? {}).then((text) => ok({ content: [{ type: 'text', text }] }), fail);
        if (name === 'run_script' && deps.runner) return run(msg.params?.arguments ?? {}).then((text) => ok({ content: [{ type: 'text', text }] }), fail);
        try {
          return ok({ content: [{ type: 'text', text: call(name, msg.params?.arguments ?? {}) }] });
        } catch (e) {
          return fail(e);
        }
      }
      default: return err(-32601, 'Method not found');
    }
  };
}

/** Newline-delimited JSON-RPC over stdio. stdout carries protocol messages only. */
export function serveMcpStdio(handle: ReturnType<typeof createMcpHandler>, input: Readable, output: Writable): Promise<void> {
  return new Promise((resolve) => {
    let buf = '';
    const send = (m: Json) => output.write(JSON.stringify(m) + '\n');
    input.setEncoding('utf8');
    input.on('data', (chunk: string) => {
      buf += chunk;
      if (buf.length > MAX_LINE && !buf.includes('\n')) { buf = ''; send({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Message too large' } }); return; }
      let i: number;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line) continue;
        let msg: Req;
        try { msg = JSON.parse(line); } catch { send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); continue; }
        if (Array.isArray(msg)) { send({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Batches are not supported' } }); continue; }
        const r = handle(msg);
        if (r instanceof Promise) void r.then(send);
        else if (r !== undefined) send(r);
      }
    });
    input.on('end', () => resolve());
  });
}
