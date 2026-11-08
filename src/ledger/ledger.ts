// Append-only, hash-chained audit ledger ("Action Records").
//
//   hash_n = sha256( hash_{n-1} || "\n" || canonical_json(record_n without `hash`) )
//
// Any edit, deletion or reordering of a past line breaks every later hash; `verifyLedger`
// pinpoints the first broken record. One JSON object per line (JSONL).

import { appendFileSync, closeSync, createReadStream, existsSync, fstatSync, mkdirSync, openSync, readSync, truncateSync } from "node:fs";
import { dirname } from "node:path";
import { createInterface } from "node:readline";
import { canonicalJson, randomId, sha256 } from "../util.ts";
import type { Effect, Obligation, Risk } from "../policy/engine.ts";

export const GENESIS_HASH = "0".repeat(64);

export type RecordType =
  | "agent.tool_call"
  | "approval.requested"
  | "approval.decided"
  | "token.issued"
  | "revocation.created"
  | "revocation.lifted"
  | "policy.changed"
  | "tool.drift"
  | "agent.registered"
  | "agent.updated"
  | "agent.secret_rotated"
  | "agent.removed"
  | "user.granted"
  | "user.revoked"
  /** A guard refused a bearer token (invalid, expired, wrong audience, revoked). */
  | "auth.rejected"
  /** The STS refused a token exchange (bad agent secret, untrusted user token, blocked issuance). */
  | "token.denied"
  /** The control plane API refused credentials. */
  | "api.auth_rejected";

/** Record types counted as rejected authentication; `type=@rejected` in queries selects all of them. */
export const REJECTED_AUTH_TYPES: RecordType[] = ["auth.rejected", "token.denied", "api.auth_rejected"];

export interface ActionRecord {
  id: string;
  seq: number;
  ts: string;
  type: RecordType;
  prev_hash: string;
  hash: string;
  /** Where the record was produced (guard instance / control plane). */
  source?: string;
  principal?: { sub: string; tenant?: string | null; email?: string | null };
  agent?: { id: string; version?: string | null; prompt_hash?: string | null };
  /** Outermost actor first: [current agent, delegating agent, ...]. The human is `principal`. */
  actor_chain?: string[];
  task_id?: string | null;
  token_jti?: string | null;
  session?: { id?: string | null; tainted?: boolean; taint_sources?: string[] };
  tool?: { name: string; server?: string | null; risk?: Risk | null; definition_hash?: string | null };
  args?: unknown;
  decision?: {
    effect: Effect;
    final: "allow" | "deny" | "pending";
    rules: string[];
    reasons: string[];
    obligations?: Obligation[];
    policy_version?: string;
    latency_us?: number;
    mode?: "enforce" | "shadow";
  };
  approval?: { id: string; status: string; approvers?: string[]; required?: number; decided_at?: string | null };
  outcome?: { status: "success" | "error" | "blocked" | "pending"; error?: string; duration_ms?: number };
  tags?: string[];
  /** Free-form details for non tool-call events (revocations, policy changes, drift). */
  details?: Record<string, unknown>;
}

export type RecordInput = Omit<ActionRecord, "id" | "seq" | "ts" | "prev_hash" | "hash"> & { ts?: string; id?: string };

export interface LedgerSink {
  append(rec: RecordInput): ActionRecord | void;
  /** Deliver buffered records now (asynchronous sinks). */
  flush?(): Promise<void>;
  close?(): Promise<void> | void;
}

export function computeHash(rec: Omit<ActionRecord, "hash">): string {
  return sha256(rec.prev_hash + "\n" + canonicalJson(rec));
}

export class FileLedger implements LedgerSink {
  readonly path: string;
  private head = GENESIS_HASH;
  private seq = 0;
  private listeners = new Set<(r: ActionRecord) => void>();

  constructor(path: string) {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
    moveTornTailAside(path);
    const last = readLastLine(path);
    if (last) {
      const rec = JSON.parse(last) as ActionRecord;
      this.head = rec.hash;
      this.seq = rec.seq;
    }
  }

  get headHash(): string { return this.head; }
  get length(): number { return this.seq; }

  append(input: RecordInput): ActionRecord {
    const base = { ...input, id: input.id ?? randomId("rec_"), seq: this.seq + 1, ts: input.ts ?? new Date().toISOString(), prev_hash: this.head };
    const clean = JSON.parse(JSON.stringify(base)) as Omit<ActionRecord, "hash">; // drop undefined
    const rec: ActionRecord = { ...clean, hash: computeHash(clean) };
    appendFileSync(this.path, JSON.stringify(rec) + "\n");
    this.head = rec.hash;
    this.seq = rec.seq;
    for (const l of this.listeners) { try { l(rec); } catch { /* listener errors never break the ledger */ } }
    return rec;
  }

  onAppend(fn: (r: ActionRecord) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  read(): ActionRecord[] {
    return readLedger(this.path);
  }
}

/** In-memory sink, handy in tests. */
export class MemoryLedger implements LedgerSink {
  records: ActionRecord[] = [];
  append(input: RecordInput): ActionRecord {
    const prev = this.records.at(-1);
    const base = { ...input, id: input.id ?? randomId("rec_"), seq: (prev?.seq ?? 0) + 1, ts: input.ts ?? new Date().toISOString(), prev_hash: prev?.hash ?? GENESIS_HASH };
    const clean = JSON.parse(JSON.stringify(base)) as Omit<ActionRecord, "hash">;
    const rec = { ...clean, hash: computeHash(clean) };
    this.records.push(rec);
    return rec;
  }
}

/** Reads line by line: one string cannot hold a ledger over about 512 MB. */
export function* ledgerLines(path: string): Generator<string> {
  if (!existsSync(path)) return;
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.allocUnsafe(1 << 20);
    let tail = Buffer.alloc(0);
    for (let n = readSync(fd, buf, 0, buf.length, null); n > 0; n = readSync(fd, buf, 0, buf.length, null)) {
      const chunk = Buffer.concat([tail, buf.subarray(0, n)]);
      let start = 0;
      for (let nl = chunk.indexOf(10); nl >= 0; start = nl + 1, nl = chunk.indexOf(10, start)) {
        if (nl > start) yield chunk.toString("utf8", start, nl);
      }
      tail = chunk.subarray(start);
    }
    if (tail.length) yield tail.toString("utf8");
  } finally {
    closeSync(fd);
  }
}

export function readLedger(path: string): ActionRecord[] {
  return Array.from(ledgerLines(path), (l) => JSON.parse(l) as ActionRecord);
}

/** Like `ledgerLines`, but gives other requests a turn while it reads. */
async function* streamLines(path: string): AsyncGenerator<string> {
  if (!existsSync(path)) return;
  const input = createReadStream(path);
  try {
    for await (const line of createInterface({ input, crlfDelay: Infinity })) if (line) yield line;
  } finally {
    input.destroy();
  }
}

export async function* streamLedger(path: string): AsyncGenerator<ActionRecord> {
  for await (const line of streamLines(path)) yield JSON.parse(line) as ActionRecord;
}

export interface VerifyResult {
  ok: boolean;
  count: number;
  head: string;
  first_ts?: string;
  last_ts?: string;
  broken_at?: number;
  error?: string;
}

/** Checks one record at a time: `next` returns a failed result at the first broken record, otherwise null. */
function chainVerifier() {
  let prev = GENESIS_HASH;
  let count = 0;
  let first_ts: string | undefined;
  let last_ts: string | undefined;
  return {
    next(item: ActionRecord | string): VerifyResult | null {
      count++;
      let rec: ActionRecord;
      try {
        rec = typeof item === "string" ? JSON.parse(item) : item;
      } catch {
        return { ok: false, count, head: prev, broken_at: count, error: `Line ${count} is not valid JSON` };
      }
      const { hash, ...rest } = rec;
      if (rec.seq !== count) return { ok: false, count, head: prev, broken_at: count, error: `Record ${count} has seq ${rec.seq} (records missing or reordered)` };
      if (rec.prev_hash !== prev) return { ok: false, count, head: prev, broken_at: count, error: `Record ${count} prev_hash does not match previous record (chain broken)` };
      if (computeHash(rest) !== hash) return { ok: false, count, head: prev, broken_at: count, error: `Record ${count} content does not match its hash (tampered)` };
      prev = hash;
      first_ts ??= rec.ts;
      last_ts = rec.ts;
      return null;
    },
    result: (): VerifyResult => ({ ok: true, count, head: prev, first_ts, last_ts }),
  };
}

export function verifyRecords(records: Iterable<ActionRecord | string>): VerifyResult {
  const v = chainVerifier();
  for (const item of records) {
    const broken = v.next(item);
    if (broken) return broken;
  }
  return v.result();
}

export function verifyLedger(path: string): VerifyResult {
  return verifyRecords(ledgerLines(path));
}

/** `verifyLedger` for a running server: other requests keep being served during the check. */
export async function verifyLedgerStream(path: string): Promise<VerifyResult> {
  const v = chainVerifier();
  for await (const line of streamLines(path)) {
    const broken = v.next(line);
    if (broken) return broken;
  }
  return v.result();
}

export interface LedgerQuery {
  type?: string;
  agent?: string;
  sub?: string;
  tool?: string;
  task?: string;
  effect?: string;
  since?: string;
  until?: string;
  limit?: number;
  order?: "asc" | "desc";
}

export function matchesQuery(r: ActionRecord, q: LedgerQuery): boolean {
  return (!q.type || r.type === q.type || (q.type === "@rejected" && REJECTED_AUTH_TYPES.includes(r.type)) ||
      (q.type.endsWith("*") && r.type.startsWith(q.type.slice(0, -1)))) &&
    (!q.agent || r.agent?.id === q.agent || r.actor_chain?.includes(q.agent) === true) &&
    (!q.sub || r.principal?.sub === q.sub) &&
    (!q.tool || r.tool?.name === q.tool) &&
    (!q.task || r.task_id === q.task) &&
    (!q.effect || r.decision?.effect === q.effect || r.decision?.final === q.effect) &&
    (!q.since || r.ts >= q.since) &&
    (!q.until || r.ts <= q.until);
}

export function queryRecords(records: ActionRecord[], q: LedgerQuery): ActionRecord[] {
  let out = records.filter((r) => matchesQuery(r, q));
  if (q.order !== "asc") out = out.reverse();
  return q.limit ? out.slice(0, q.limit) : out;
}

/** Runs a query over the whole file, holding at most `limit` records in memory. */
export async function queryLedger(path: string, q: LedgerQuery): Promise<ActionRecord[]> {
  const out: ActionRecord[] = [];
  for await (const r of streamLedger(path)) {
    if (!matchesQuery(r, q)) continue;
    out.push(r);
    if (q.limit && out.length > q.limit) {
      if (q.order === "asc") break;
      out.shift();
    }
  }
  return queryRecords(out, q);
}

const WINDOW_RECORDS = 20_000;
const HOUR_MS = 3_600_000;
const MAX_HOURLY_LATENCIES = 10_000;

interface HourStats { calls: number; allowed: number; denied: number; pending: number; latencies: number[] }

/** What the control plane keeps in memory so that polling and retries never re-read the ledger file. */
export class LedgerWindow {
  /** Between one and two times WINDOW_RECORDS of the newest records, oldest first. */
  records: ActionRecord[] = [];
  private ids = new Set<string>();
  private hours = new Map<number, HourStats>();

  add(r: ActionRecord): void {
    this.ids.add(r.id);
    this.records.push(r);
    if (this.records.length >= 2 * WINDOW_RECORDS) for (const old of this.records.splice(0, WINDOW_RECORDS)) this.ids.delete(old.id);
    if (r.type !== "agent.tool_call") return;
    const hour = Math.floor(Date.parse(r.ts) / HOUR_MS);
    const first = Math.floor(Date.now() / HOUR_MS) - 23;
    if (!(hour >= first)) return;
    for (const h of this.hours.keys()) if (h < first) this.hours.delete(h);
    const s = this.hours.get(hour) ?? { calls: 0, allowed: 0, denied: 0, pending: 0, latencies: [] };
    this.hours.set(hour, s);
    s.calls++;
    if (r.decision?.final === "allow") s.allowed++;
    if (r.decision?.final === "deny") s.denied++;
    if (r.decision?.final === "pending") s.pending++;
    if (s.latencies.length < MAX_HOURLY_LATENCIES) s.latencies.push(r.decision?.latency_us ?? 0);
  }

  has(id: string): boolean { return this.ids.has(id); }

  /** Tool calls of the current hour and the 23 before it. */
  last24h(): Omit<HourStats, "latencies"> & { p99_decision_us: number } {
    const first = Math.floor(Date.now() / HOUR_MS) - 23;
    const out = { calls: 0, allowed: 0, denied: 0, pending: 0, p99_decision_us: 0 };
    const latencies: number[] = [];
    for (const [hour, s] of this.hours) {
      if (hour < first) continue;
      out.calls += s.calls; out.allowed += s.allowed; out.denied += s.denied; out.pending += s.pending;
      latencies.push(...s.latencies);
    }
    latencies.sort((a, b) => a - b);
    out.p99_decision_us = latencies[Math.min(latencies.length - 1, Math.floor(0.99 * latencies.length))] ?? 0;
    return out;
  }
}

/**
 * Every complete record ends in a newline, so bytes after the last one are a write cut short by a crash.
 * They move to `<ledger>.torn` for inspection. A complete line that fails to parse still stops startup: that is tampering.
 */
function moveTornTailAside(path: string): void {
  if (!existsSync(path)) return;
  const fd = openSync(path, "r");
  let size: number, cut = 0;
  try {
    size = fstatSync(fd).size;
    for (let end = size; end > 0;) {
      const start = Math.max(0, end - 65_536);
      const buf = Buffer.alloc(end - start);
      readSync(fd, buf, 0, buf.length, start);
      const nl = buf.lastIndexOf(10);
      if (nl >= 0) { cut = start + nl + 1; break; }
      end = start;
    }
    if (cut === size) return;
    const torn = Buffer.alloc(size - cut);
    readSync(fd, torn, 0, torn.length, cut);
    appendFileSync(`${path}.torn`, Buffer.concat([torn, Buffer.from("\n")]));
  } finally {
    closeSync(fd);
  }
  truncateSync(path, cut);
  console.error(`[mandat] ${path}: moved ${size - cut} bytes of an unfinished write to ${path}.torn`);
}

function readLastLine(path: string): string | null {
  if (!existsSync(path)) return null;
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return null;
    let chunk = 64 * 1024;
    for (;;) {
      const start = Math.max(0, size - chunk);
      const buf = Buffer.alloc(size - start);
      readSync(fd, buf, 0, buf.length, start);
      const text = buf.toString("utf8").replace(/\n+$/, "");
      const idx = text.lastIndexOf("\n");
      if (idx >= 0 || start === 0) return text.slice(idx + 1) || null;
      chunk *= 4;
    }
  } finally {
    closeSync(fd);
  }
}
