export type Verdict = 'ok' | 'limited' | 'killed';

/**
 * Fixed-window limiter with a kill switch: exceed `limit` requests/minute and you get 429s;
 * exceed limit x killMultiplier and the agent is blocked outright for killMs (or until restart).
 */
export class RateLimiter {
  private windows = new Map<string, { start: number; n: number }>();
  private killed = new Map<string, number>();
  constructor(
    private limit: number,
    private opts: { killMultiplier?: number; killMs?: number; now?: () => number } = {}
  ) {}

  hit(id: string): Verdict {
    const now = (this.opts.now ?? Date.now)();
    const until = this.killed.get(id);
    if (until !== undefined) {
      if (now < until) return 'killed';
      this.killed.delete(id);
    }
    let w = this.windows.get(id);
    if (!w || now - w.start >= 60_000) { w = { start: now, n: 0 }; this.windows.set(id, w); }
    w.n++;
    if (w.n > this.limit * (this.opts.killMultiplier ?? 3)) {
      this.killed.set(id, now + (this.opts.killMs ?? 15 * 60_000));
      return 'killed';
    }
    return w.n > this.limit ? 'limited' : 'ok';
  }
}

/** Locks out a remote address after repeated failed logins, so tokens can't be guessed at network speed. */
export class AuthGuard {
  private m = new Map<string, { n: number; start: number; lockedUntil: number }>();
  constructor(private max = 10, private windowMs = 10 * 60_000, private lockMs = 15 * 60_000, private now: () => number = Date.now) {}
  blocked(ip: string): boolean { const e = this.m.get(ip); return !!e && e.lockedUntil > this.now(); }
  fail(ip: string) {
    const t = this.now();
    if (this.m.size > 10_000) {
      for (const [k, v] of this.m) if (v.lockedUntil <= t && t - v.start > this.windowMs) this.m.delete(k);
      if (this.m.size > 10_000) this.m.clear();
    }
    let e = this.m.get(ip);
    if (!e || t - e.start > this.windowMs) { e = { n: 0, start: t, lockedUntil: 0 }; this.m.set(ip, e); }
    if (++e.n >= this.max) e.lockedUntil = t + this.lockMs;
  }
  ok(ip: string) { this.m.delete(ip); }
}
