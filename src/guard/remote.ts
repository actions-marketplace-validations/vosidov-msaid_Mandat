// Guard <-> control plane clients. The data plane keeps working on its last snapshot when the
// control plane is down (policy from cache file; revocations marked stale -> high-risk tools fail closed).

import { existsSync, watchFile } from "node:fs";
import { compilePolicy, type CompiledPolicy, type PolicyDocument } from "../policy/engine.ts";
import { matchRevocation, type Revocation } from "../sts/revocation.ts";
import type { JwtPayload } from "../sts/jwt.ts";
import type { ApprovalRequest, NewApproval } from "../approvals/approvals.ts";
import type { ActionRecord, LedgerSink, RecordInput } from "../ledger/ledger.ts";
import type { ApprovalBroker, PolicySource, RevocationSource } from "./guard.ts";
import { readJson, writeJsonAtomic } from "../util.ts";

export interface ControlPlaneClientOptions {
  url: string;
  /** API key with the `service` role. */
  apiKey: string;
}

async function call<T>(o: ControlPlaneClientOptions, method: string, path: string, body?: unknown, timeoutMs = 5000): Promise<T> {
  const res = await fetch(o.url.replace(/\/$/, "") + path, {
    method,
    headers: { authorization: `Bearer ${o.apiKey}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${data.error_description ?? data.error ?? text}`);
  return data as T;
}

/** Polls the control plane for revocations (default every 2 s, so revocation lands in <= ~3 s). */
export class RemoteRevocations implements RevocationSource {
  private list: Revocation[] = [];
  private lastOk = 0;
  private timer: NodeJS.Timeout;
  private o: ControlPlaneClientOptions;
  private staleAfterMs: number;

  constructor(o: ControlPlaneClientOptions, intervalMs = 2000, staleAfterMs = 15_000) {
    this.o = o;
    this.staleAfterMs = staleAfterMs;
    this.timer = setInterval(() => void this.refresh(), intervalMs);
    this.timer.unref();
  }

  async refresh(): Promise<void> {
    try {
      const r = await call<{ revocations: Revocation[] }>(this.o, "GET", "/api/revocations", undefined, 3000);
      this.list = r.revocations;
      this.lastOk = Date.now();
    } catch { /* keep last snapshot; stale() reports it */ }
  }

  check(claims: JwtPayload): Revocation | null { return matchRevocation(claims, this.list); }
  stale(): boolean { return Date.now() - this.lastOk > this.staleAfterMs; }
  close(): void { clearInterval(this.timer); }
}

/** Policy pulled from the control plane (ETag polling) with an on-disk snapshot for cold starts offline. */
export class RemotePolicy implements PolicySource {
  private compiled: CompiledPolicy | null = null;
  private etag: string | null = null;
  private timer: NodeJS.Timeout;
  private o: ControlPlaneClientOptions;
  private snapshotPath: string | null;
  onChange?: (p: CompiledPolicy) => void;

  constructor(o: ControlPlaneClientOptions, opts: { snapshotPath?: string; intervalMs?: number } = {}) {
    this.o = o;
    this.snapshotPath = opts.snapshotPath ?? null;
    if (this.snapshotPath && existsSync(this.snapshotPath)) {
      try { this.compiled = compilePolicy(readJson<PolicyDocument>(this.snapshotPath)); } catch { /* ignore bad snapshot */ }
    }
    this.timer = setInterval(() => void this.refresh(), opts.intervalMs ?? 5000);
    this.timer.unref();
  }

  async refresh(): Promise<void> {
    try {
      const res = await fetch(this.o.url.replace(/\/$/, "") + "/api/policy", {
        headers: { authorization: `Bearer ${this.o.apiKey}`, ...(this.etag ? { "if-none-match": this.etag } : {}) },
        signal: AbortSignal.timeout(3000),
      });
      if (res.status === 304 || !res.ok) return;
      const body = (await res.json()) as { policy: PolicyDocument };
      const next = compilePolicy(body.policy);
      this.compiled = next;
      this.etag = res.headers.get("etag");
      if (this.snapshotPath) writeJsonAtomic(this.snapshotPath, body.policy);
      this.onChange?.(next);
    } catch { /* keep last snapshot */ }
  }

  current(): CompiledPolicy {
    if (!this.compiled) throw new Error("No policy available yet (control plane unreachable and no snapshot)");
    return this.compiled;
  }

  close(): void { clearInterval(this.timer); }
}

/** Local policy file, hot-reloaded on change. An invalid edit keeps the previous policy. */
export class FilePolicy implements PolicySource {
  private compiled: CompiledPolicy;
  readonly path: string;
  onChange?: (p: CompiledPolicy) => void;
  onError?: (e: Error) => void;

  constructor(path: string, watch = true) {
    this.path = path;
    this.compiled = compilePolicy(readJson<PolicyDocument>(path));
    if (watch) {
      watchFile(path, { interval: 1000, persistent: false }, () => {
        try {
          this.compiled = compilePolicy(readJson<PolicyDocument>(path));
          this.onChange?.(this.compiled);
        } catch (e) {
          (this.onError ?? ((err: Error) => console.error(`[mandat] policy reload failed, keeping previous version: ${err.message}`)))(e as Error);
        }
      });
    }
  }

  current(): CompiledPolicy { return this.compiled; }
}

export class RemoteApprovalBroker implements ApprovalBroker {
  private o: ControlPlaneClientOptions;
  constructor(o: ControlPlaneClientOptions) { this.o = o; }

  request(n: NewApproval): Promise<ApprovalRequest> {
    return call<ApprovalRequest>(this.o, "POST", "/api/approvals", n);
  }

  /** Long-polls in <= 25 s slices until decided or `timeoutMs` elapses. */
  async wait(id: string, timeoutMs: number): Promise<ApprovalRequest | undefined> {
    const deadline = Date.now() + timeoutMs;
    let cur: ApprovalRequest | undefined;
    do {
      const slice = Math.max(0, Math.min(25_000, deadline - Date.now()));
      cur = await call<ApprovalRequest>(this.o, "GET", `/api/approvals/${encodeURIComponent(id)}?wait=${slice}`, undefined, slice + 5000);
    } while (cur.status === "pending" && Date.now() < deadline);
    return cur;
  }

  async consume(id: string): Promise<boolean> {
    const r = await call<{ consumed: boolean }>(this.o, "POST", `/api/approvals/${encodeURIComponent(id)}/consume`, {});
    return r.consumed;
  }
}

/**
 * Ships records to the control plane ledger. Asynchronous and batched (off the critical path), with
 * at-least-once delivery: a batch stays queued until acknowledged. Records carry a client id, so the
 * control plane de-duplicates retries.
 */
export class HttpLedgerSink implements LedgerSink {
  private queue: RecordInput[] = [];
  private timer: NodeJS.Timeout;
  private flushing: Promise<void> | null = null;
  private o: ControlPlaneClientOptions;
  private local?: LedgerSink;
  lastError: string | null = null;

  constructor(o: ControlPlaneClientOptions, opts: { flushIntervalMs?: number; local?: LedgerSink } = {}) {
    this.o = o;
    this.local = opts.local;
    this.timer = setInterval(() => void this.flush(), opts.flushIntervalMs ?? 500);
    this.timer.unref();
  }

  append(rec: RecordInput): ActionRecord | void {
    const withId = { ...rec, id: rec.id ?? `rec_${crypto.randomUUID()}`, ts: rec.ts ?? new Date().toISOString() };
    this.queue.push(withId);
    if (this.queue.length > 100_000) this.queue.shift();
    return this.local?.append(withId);
  }

  flush(): Promise<void> {
    if (this.flushing) return this.flushing;
    if (!this.queue.length) return Promise.resolve();
    const run = async () => {
      try {
        while (this.queue.length) {
          const batch = this.queue.slice(0, 200);
          await call(this.o, "POST", "/api/ledger/ingest", { records: batch });
          this.queue.splice(0, batch.length);
        }
        this.lastError = null;
      } catch (e) {
        this.lastError = (e as Error).message; // retried on the next tick
      }
    };
    this.flushing = run().finally(() => { this.flushing = null; });
    return this.flushing;
  }

  get pending(): number { return this.queue.length; }

  async close(): Promise<void> {
    clearInterval(this.timer);
    await this.flush();
  }
}

