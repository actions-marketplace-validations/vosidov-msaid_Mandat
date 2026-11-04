// Append-only, hash-chained audit ledger ("Action Records").
//
//   hash_n = sha256( hash_{n-1} || "\n" || canonical_json(record_n without `hash`) )
//
// Any edit, deletion or reordering of a past line breaks every later hash; `verifyLedger`
// pinpoints the first broken record. One JSON object per line (JSONL).

import { appendFileSync, closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync } from "node:fs";
import { dirname } from "node:path";
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

export function readLedger(path: string): ActionRecord[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as ActionRecord);
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

export function verifyRecords(records: Iterable<ActionRecord | string>): VerifyResult {
  let prev = GENESIS_HASH;
  let count = 0;
  let first_ts: string | undefined;
  let last_ts: string | undefined;
  for (const item of records) {
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
  }
  return { ok: true, count, head: prev, first_ts, last_ts };
}

export function verifyLedger(path: string): VerifyResult {
  if (!existsSync(path)) return { ok: true, count: 0, head: GENESIS_HASH };
  return verifyRecords(readFileSync(path, "utf8").split("\n").filter(Boolean));
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

export function queryRecords(records: ActionRecord[], q: LedgerQuery): ActionRecord[] {
  let out = records.filter((r) =>
    (!q.type || r.type === q.type || (q.type === "@rejected" && REJECTED_AUTH_TYPES.includes(r.type)) ||
      (q.type.endsWith("*") && r.type.startsWith(q.type.slice(0, -1)))) &&
    (!q.agent || r.agent?.id === q.agent || r.actor_chain?.includes(q.agent)) &&
    (!q.sub || r.principal?.sub === q.sub) &&
    (!q.tool || r.tool?.name === q.tool) &&
    (!q.task || r.task_id === q.task) &&
    (!q.effect || r.decision?.effect === q.effect || r.decision?.final === q.effect) &&
    (!q.since || r.ts >= q.since) &&
    (!q.until || r.ts <= q.until),
  );
  if (q.order !== "asc") out = out.reverse();
  return q.limit ? out.slice(0, q.limit) : out;
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
