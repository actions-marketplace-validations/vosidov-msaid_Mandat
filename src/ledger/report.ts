// Compliance / DPO evidence report built from the hash chain.
// Technical evidence only: qualification of a concrete system remains the operator's responsibility.

import { REJECTED_AUTH_TYPES, verifyRecords, type ActionRecord, type VerifyResult } from "./ledger.ts";

export interface ReportOptions { from?: string; to?: string; retentionDays?: number; title?: string }

export interface ReportData {
  generated_at: string;
  period: { from: string | null; to: string | null };
  integrity: VerifyResult;
  retention: { configured_days: number | null; oldest_record: string | null; meets_ai_act_minimum: boolean | null };
  totals: { records: number; tool_calls: number; allowed: number; denied: number; pending: number; shadow_would_deny: number };
  by_agent: Array<{ agent: string; calls: number; denied: number; approvals: number }>;
  by_tool: Array<{ tool: string; risk: string | null; calls: number; denied: number }>;
  principals: number;
  approvals: Array<{ id: string; tool: string | null; agent: string | null; principal: string | null; status: string; approvers: string[]; requested_at: string; decided_at: string | null; wait_s: number | null }>;
  denials: Array<{ ts: string; agent: string | null; principal: string | null; tool: string | null; rules: string[]; reasons: string[] }>;
  rejected_auth: { total: number; by_reason: Array<{ type: string; reason: string; count: number }> };
  admin_events: Array<{ ts: string; type: string; details: unknown }>;
  drift_events: Array<{ ts: string; details: unknown }>;
}

const AI_ACT_MIN_RETENTION_DAYS = 183; // Art. 19 / 26(6): at least six months
const ADMIN_TYPES = new Set(["policy.changed", "revocation.created", "revocation.lifted", "agent.registered", "agent.updated",
  "agent.secret_rotated", "agent.removed", "user.granted", "user.revoked"]);

export function buildReport(all: ActionRecord[], opts: ReportOptions = {}): ReportData {
  const integrity = verifyRecords(all);
  const recs = all.filter((r) => (!opts.from || r.ts >= opts.from) && (!opts.to || r.ts <= opts.to));
  const calls = recs.filter((r) => r.type === "agent.tool_call");
  const byAgent = new Map<string, { agent: string; calls: number; denied: number; approvals: number }>();
  const byTool = new Map<string, { tool: string; risk: string | null; calls: number; denied: number }>();
  for (const c of calls) {
    const a = c.agent?.id ?? "?";
    const t = c.tool?.name ?? "?";
    const ae = byAgent.get(a) ?? { agent: a, calls: 0, denied: 0, approvals: 0 };
    const te = byTool.get(t) ?? { tool: t, risk: c.tool?.risk ?? null, calls: 0, denied: 0 };
    ae.calls++; te.calls++;
    if (c.decision?.final === "deny") { ae.denied++; te.denied++; }
    if (c.approval) ae.approvals++;
    byAgent.set(a, ae); byTool.set(t, te);
  }
  const requested = new Map(recs.filter((r) => r.type === "approval.requested").map((r) => [r.approval!.id, r]));
  const decided = recs.filter((r) => r.type === "approval.decided");
  const approvals = [...requested.values()].map((req) => {
    const d = decided.find((x) => x.approval?.id === req.approval!.id);
    return {
      id: req.approval!.id,
      tool: req.tool?.name ?? null,
      agent: req.agent?.id ?? null,
      principal: req.principal?.sub ?? null,
      status: d?.approval?.status ?? "pending",
      approvers: d?.approval?.approvers ?? [],
      requested_at: req.ts,
      decided_at: d?.ts ?? null,
      wait_s: d ? Math.round((Date.parse(d.ts) - Date.parse(req.ts)) / 1000) : null,
    };
  });
  const oldest = all[0]?.ts ?? null;
  return {
    generated_at: new Date().toISOString(),
    period: { from: opts.from ?? recs[0]?.ts ?? null, to: opts.to ?? recs.at(-1)?.ts ?? null },
    integrity,
    retention: {
      configured_days: opts.retentionDays ?? null,
      oldest_record: oldest,
      meets_ai_act_minimum: opts.retentionDays === undefined ? null : opts.retentionDays >= AI_ACT_MIN_RETENTION_DAYS,
    },
    totals: {
      records: recs.length,
      tool_calls: calls.length,
      allowed: calls.filter((c) => c.decision?.final === "allow").length,
      denied: calls.filter((c) => c.decision?.final === "deny").length,
      pending: calls.filter((c) => c.decision?.final === "pending").length,
      shadow_would_deny: calls.filter((c) => c.decision?.mode === "shadow" && (c.decision.effect === "deny" || c.decision.effect === "require_approval")).length,
    },
    by_agent: [...byAgent.values()].sort((a, b) => b.calls - a.calls),
    by_tool: [...byTool.values()].sort((a, b) => b.calls - a.calls),
    principals: new Set(calls.map((c) => c.principal?.sub)).size,
    approvals,
    denials: calls.filter((c) => c.decision?.final === "deny").slice(-100).map((c) => ({
      ts: c.ts, agent: c.agent?.id ?? null, principal: c.principal?.sub ?? null, tool: c.tool?.name ?? null,
      rules: c.decision?.rules ?? [], reasons: c.decision?.reasons ?? [],
    })),
    rejected_auth: rejectedAuth(recs),
    admin_events: recs.filter((r) => ADMIN_TYPES.has(r.type)).map((r) => ({ ts: r.ts, type: r.type, details: r.details })),
    drift_events: recs.filter((r) => r.type === "tool.drift").map((r) => ({ ts: r.ts, details: r.details })),
  };
}

export function reportToMarkdown(d: ReportData, title = "Mandat — AI agent activity & oversight report"): string {
  const L: string[] = [];
  const row = (...c: unknown[]) => L.push("| " + c.map((x) => String(x ?? "—").replace(/\|/g, "\\|")).join(" | ") + " |");
  L.push(`# ${title}`, "");
  L.push(`Generated: ${d.generated_at}  `, `Period: ${d.period.from ?? "—"} → ${d.period.to ?? "—"}`, "");
  L.push("## 1. Log integrity (hash chain)", "");
  L.push(d.integrity.ok
    ? `**VERIFIED** — ${d.integrity.count} records, chain head \`${d.integrity.head}\`.`
    : `**BROKEN** at record ${d.integrity.broken_at}: ${d.integrity.error}`);
  L.push("", "## 2. Retention", "");
  L.push(`Configured retention: ${d.retention.configured_days ?? "not configured"} days; oldest record: ${d.retention.oldest_record ?? "—"}.`);
  if (d.retention.meets_ai_act_minimum !== null)
    L.push(d.retention.meets_ai_act_minimum ? "Meets the ≥ 6 months log retention expectation (EU AI Act Art. 19/26)." : "**Below** the ≥ 6 months log retention expectation (EU AI Act Art. 19/26).");
  L.push("", "## 3. Activity summary", "");
  const t = d.totals;
  L.push(`Tool calls: **${t.tool_calls}** (allowed ${t.allowed}, denied ${t.denied}, pending ${t.pending}); distinct principals: ${d.principals}.`);
  if (t.shadow_would_deny) L.push(`Shadow mode: ${t.shadow_would_deny} calls would have been blocked or escalated under enforcement.`);
  L.push("", "| Agent | Calls | Denied | With approval |", "|---|---|---|---|");
  for (const a of d.by_agent) row(a.agent, a.calls, a.denied, a.approvals);
  L.push("", "| Tool | Risk | Calls | Denied |", "|---|---|---|---|");
  for (const x of d.by_tool) row(x.tool, x.risk, x.calls, x.denied);
  L.push("", "## 4. Human oversight (approvals)", "");
  if (!d.approvals.length) L.push("No approval requests in period.");
  else {
    L.push("| Approval | Tool | Agent | On behalf of | Status | Approvers | Requested | Wait (s) |", "|---|---|---|---|---|---|---|---|");
    for (const a of d.approvals) row(a.id, a.tool, a.agent, a.principal, a.status, a.approvers.join(", "), a.requested_at, a.wait_s);
  }
  L.push("", "## 5. Blocked actions", "");
  if (!d.denials.length) L.push("No denied calls in period.");
  else {
    L.push("| Time | Agent | On behalf of | Tool | Rules | Reason |", "|---|---|---|---|---|---|");
    for (const x of d.denials) row(x.ts, x.agent, x.principal, x.tool, x.rules.join(", "), x.reasons.join("; "));
  }
  L.push("", "## 6. Rejected authentication", "");
  if (!d.rejected_auth.total) L.push("None.");
  else {
    L.push(`${d.rejected_auth.total} rejected attempts (invalid, expired or revoked tokens, failed agent or API logins).`, "", "| Event | Reason | Count |", "|---|---|---|");
    for (const x of d.rejected_auth.by_reason) row(x.type, x.reason, x.count);
  }
  L.push("", "## 7. Administrative changes (policies, revocations, agents, users)", "");
  if (!d.admin_events.length) L.push("None.");
  else for (const e of d.admin_events) L.push(`- ${e.ts} — \`${e.type}\` ${JSON.stringify(e.details)}`);
  L.push("", "## 8. Tool definition drift", "");
  if (!d.drift_events.length) L.push("None detected.");
  else for (const e of d.drift_events) L.push(`- ${e.ts} — ${JSON.stringify(e.details)}`);
  L.push("", "---", "_Technical evidence produced by Mandat. Classification of the AI system under the EU AI Act, GDPR, DORA, SOC 2 or ISO/IEC 42001 is the operator's responsibility._", "");
  return L.join("\n");
}

/** Counts rejected-authentication records, including attempts folded into a record by rate limiting. */
function rejectedAuth(recs: ActionRecord[]): ReportData["rejected_auth"] {
  const counts = new Map<string, { type: string; reason: string; count: number }>();
  let total = 0;
  for (const r of recs) {
    if (!REJECTED_AUTH_TYPES.includes(r.type)) continue;
    const d = (r.details ?? {}) as { code?: string; error?: string; reason?: string; suppressed_before?: number };
    const reason = d.code ?? d.error ?? d.reason ?? "unknown";
    const n = 1 + (d.suppressed_before ?? 0);
    total += n;
    const k = `${r.type}|${reason}`;
    const e = counts.get(k) ?? { type: r.type, reason, count: 0 };
    e.count += n;
    counts.set(k, e);
  }
  return { total, by_reason: [...counts.values()].sort((a, b) => b.count - a.count) };
}
