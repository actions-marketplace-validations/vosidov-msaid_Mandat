import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileLedger, LedgerWindow, MemoryLedger, queryLedger, readLedger, verifyLedger, verifyLedgerStream, verifyRecords, type ActionRecord } from "../src/ledger/ledger.ts";
import { redact } from "../src/ledger/redact.ts";
import { toOcsf, toOtelSpan } from "../src/ledger/export.ts";
import { buildReport, reportToMarkdown } from "../src/ledger/report.ts";

const call = (n: number) => ({
  type: "agent.tool_call" as const,
  principal: { sub: "user:maria" },
  agent: { id: "bot" },
  actor_chain: ["bot"],
  task_id: "t1",
  tool: { name: "refund", risk: "financial" as const },
  args: { amount: n },
  decision: { effect: "allow" as const, final: "allow" as const, rules: ["r"], reasons: [] },
  outcome: { status: "success" as const, duration_ms: 3 },
});

test("ledger: hash chain survives reopen and detects edits, deletions and reordering", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandat-ledger-"));
  const path = join(dir, "l.jsonl");
  const l = new FileLedger(path);
  for (let i = 1; i <= 5; i++) l.append(call(i));
  const reopened = new FileLedger(path);
  assert.equal(reopened.length, 5);
  reopened.append(call(6));
  assert.deepEqual(verifyLedger(path).ok, true);
  assert.equal(verifyLedger(path).count, 6);

  const lines = readFileSync(path, "utf8").trim().split("\n");
  const edited = [...lines];
  edited[2] = edited[2]!.replace('"amount":3', '"amount":300');
  assert.match(verifyRecords(edited).error!, /Record 3 content does not match/);

  const deleted = lines.filter((_, i) => i !== 1);
  assert.equal(verifyRecords(deleted).ok, false);
  const swapped = [lines[0]!, lines[2]!, lines[1]!, ...lines.slice(3)];
  assert.equal(verifyRecords(swapped).ok, false);

  // Recomputing one record's hash does not help: the next record's prev_hash breaks.
  writeFileSync(path, edited.join("\n") + "\n");
  assert.equal(verifyLedger(path).ok, false);
});

test("ledger: files larger than the read chunk stay readable, verifiable and queryable", async () => {
  const path = join(mkdtempSync(join(tmpdir(), "mandat-ledger-")), "ledger.jsonl");
  const l = new FileLedger(path);
  // Multi-byte text, so that some records straddle a chunk boundary inside a character.
  for (let i = 0; i < 2500; i++) l.append({ type: "agent.tool_call", tool: { name: "t" }, details: { i, text: "é€".repeat(300) } });
  assert.ok(statSync(path).size > 2 * (1 << 20));
  const all = readLedger(path);
  assert.equal(all.length, 2500);
  assert.equal(all[2499]!.details!.text, "é€".repeat(300));
  assert.equal(verifyLedger(path).ok, true);
  assert.equal((await verifyLedgerStream(path)).count, 2500);
  assert.deepEqual((await queryLedger(path, { limit: 2 })).map((r) => r.seq), [2500, 2499]);
  assert.deepEqual((await queryLedger(path, { limit: 2, order: "asc" })).map((r) => r.seq), [1, 2]);
  writeFileSync(path, readFileSync(path, "utf8").replace('"i":7,', '"i":8,'));
  assert.equal((await verifyLedgerStream(path)).ok, false);
});

test("ledger: a write cut short by a crash is moved aside; the chain continues", () => {
  const path = join(mkdtempSync(join(tmpdir(), "mandat-ledger-")), "ledger.jsonl");
  const first = new FileLedger(path);
  first.append(call(1));
  first.append(call(2));
  appendFileSync(path, '{"id":"rec_torn","seq":3,"text":"é'.slice(0, -1) + "\xc3");
  const reopened = new FileLedger(path);
  assert.equal(reopened.length, 2);
  reopened.append(call(3));
  assert.deepEqual(verifyLedger(path).ok, true);
  assert.equal(verifyLedger(path).count, 3);
  assert.match(readFileSync(`${path}.torn`, "utf8"), /rec_torn/);
});

test("ledger: a complete line that does not parse still stops startup", () => {
  const path = join(mkdtempSync(join(tmpdir(), "mandat-ledger-")), "ledger.jsonl");
  new FileLedger(path).append(call(1));
  appendFileSync(path, "not json\n");
  assert.throws(() => new FileLedger(path), SyntaxError);
});

test("ledger window: bounded memory, recent ids, 24-hour counts", () => {
  const w = new LedgerWindow();
  const rec = (id: string, ts: string, final: "allow" | "deny") => ({ id, ts, type: "agent.tool_call", decision: { final, latency_us: 5 } }) as ActionRecord;
  const now = new Date().toISOString();
  w.add(rec("old", new Date(Date.now() - 48 * 3_600_000).toISOString(), "allow"));
  w.add(rec("a", now, "allow"));
  w.add(rec("b", now, "deny"));
  assert.deepEqual(w.last24h(), { calls: 2, allowed: 1, denied: 1, pending: 0, p99_decision_us: 5 });
  assert.equal(w.has("a"), true);
  for (let i = 0; i < 50_000; i++) w.add({ id: `n${i}`, ts: now, type: "policy.changed" } as ActionRecord);
  assert.ok(w.records.length < 40_000);
  assert.equal(w.has("a"), false);
  assert.equal(w.has("n49999"), true);
});

test("redaction: secrets by key, PII patterns, explicit fields, metadata-only", () => {
  const r = redact({
    api_key: "abc", password: "p", pinned: true, note: "mail jane.doe@corp.test or +49 151 23456789, card 4111 1111 1111 1111, order 1234567890123",
    nested: { authorization: "Bearer x", iban: "DE89 3704 0044 0532 0130 00" }, body: "secret letter",
  }, { fields: ["body"] }) as any;
  assert.equal(r.api_key, "[REDACTED]");
  assert.equal(r.password, "[REDACTED]");
  assert.equal(r.pinned, true);
  assert.match(r.note, /j\*\*\*@corp\.test/);
  assert.match(r.note, /\[PHONE\]/);
  assert.match(r.note, /\[CARD \*\*\*\*1111\]/);
  assert.match(r.note, /1234567890123/, "non-Luhn digit runs are kept");
  assert.equal(r.nested.authorization, "[REDACTED]");
  assert.equal(r.nested.iban, "[IBAN]");
  assert.match(r.body, /^\[REDACTED sha256:[0-9a-f]{16}\]$/);
  const m = redact({ a: "x", b: 5 }, { metadataOnly: true }) as any;
  assert.match(m.a, /^\[string sha256:/);
});

test("exports: OCSF API Activity and OTel GenAI execute_tool span", () => {
  const rec = new MemoryLedger().append(call(42));
  const o = toOcsf(rec) as any;
  assert.equal(o.class_uid, 6003);
  assert.equal(o.actor.user.uid, "user:maria");
  assert.equal(o.api.operation, "refund");
  assert.equal(o.unmapped.mandat.record_hash, rec.hash);
  const s = toOtelSpan(rec) as any;
  assert.equal(s.name, "execute_tool refund");
  assert.equal(s.traceId.length, 32);
  const attr = Object.fromEntries(s.attributes.map((a: any) => [a.key, Object.values(a.value)[0]]));
  assert.equal(attr["gen_ai.operation.name"], "execute_tool");
  assert.equal(attr["gen_ai.tool.name"], "refund");
  assert.equal(attr["mandat.decision.final"], "allow");
});

test("report: integrity, approvals, denials, retention", () => {
  const l = new MemoryLedger();
  l.append(call(1));
  l.append({ ...call(900), decision: { effect: "deny", final: "deny", rules: ["refund-limit"], reasons: ["too much"] }, outcome: { status: "blocked" } });
  l.append({ type: "approval.requested", principal: { sub: "user:maria" }, agent: { id: "bot" }, tool: { name: "refund" }, approval: { id: "apr_1", status: "pending" } });
  l.append({ type: "approval.decided", approval: { id: "apr_1", status: "approved", approvers: ["alice"] } });
  const d = buildReport(l.records, { retentionDays: 90 });
  assert.equal(d.integrity.ok, true);
  assert.equal(d.totals.tool_calls, 2);
  assert.equal(d.totals.denied, 1);
  assert.deepEqual(d.approvals[0]!.approvers, ["alice"]);
  assert.equal(d.retention.meets_ai_act_minimum, false);
  const md = reportToMarkdown(d);
  assert.match(md, /VERIFIED/);
  assert.match(md, /refund-limit/);
});
