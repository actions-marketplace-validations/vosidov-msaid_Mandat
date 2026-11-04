// Human-in-the-loop approvals.
//
// An approval is bound to the exact call (sha256 over principal, agent, tool, server, args), so approving
// "refund €120 to order 42" can never authorise a different refund. Approved requests are single-use.
// Self-approval is forbidden; `required: 2` gives four-eyes. Timeout => expired => deny.

import { EventEmitter } from "node:events";
import { createHmac } from "node:crypto";
import { JsonCollection } from "../store.ts";
import { canonicalJson, randomId, safeEqual, sha256 } from "../util.ts";
import type { LedgerSink } from "../ledger/ledger.ts";
import type { Risk } from "../policy/engine.ts";

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface ApprovalContext {
  tool: string;
  server?: string | null;
  risk?: Risk | null;
  /** Already redacted. */
  args: unknown;
  principal: { sub: string; tenant?: string | null; email?: string | null };
  agent: { id: string; version?: string | null };
  actor_chain?: string[];
  task_id?: string | null;
  rule: string;
  reasons: string[];
  session_tainted?: boolean;
}

export interface ApprovalRequest {
  id: string;
  binding: string;
  status: ApprovalStatus;
  required: number;
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  consumed_at: string | null;
  votes: Array<{ by: string; decision: "approve" | "deny"; at: string; via: string; comment?: string; identities?: string[] }>;
  channels: string[];
  context: ApprovalContext;
}

export interface NewApproval {
  binding: string;
  required: number;
  timeoutMs: number;
  channels: string[];
  context: ApprovalContext;
}

export function approvalBinding(p: { sub: string; agent: string; tool: string; server?: string | null; args: unknown }): string {
  return sha256(canonicalJson({ sub: p.sub, agent: p.agent, tool: p.tool, server: p.server ?? null, args: p.args ?? {} }));
}

export interface Notifier {
  name: string;
  notify(req: ApprovalRequest): Promise<void>;
  /** Called after a decision so channels can update their message. */
  decided?(req: ApprovalRequest): Promise<void>;
}

export class ApprovalError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export class ApprovalService {
  private store: JsonCollection<ApprovalRequest>;
  private events = new EventEmitter();
  private notifiers: Notifier[];
  private ledger?: LedgerSink;
  private sweeper: NodeJS.Timeout;

  constructor(opts: { path: string | null; notifiers?: Notifier[]; ledger?: LedgerSink }) {
    this.store = new JsonCollection<ApprovalRequest>(opts.path);
    this.notifiers = opts.notifiers ?? [];
    this.ledger = opts.ledger;
    this.events.setMaxListeners(0);
    this.sweeper = setInterval(() => this.expireDue(), 1000);
    this.sweeper.unref();
  }

  close(): void { clearInterval(this.sweeper); }

  get(id: string): ApprovalRequest | undefined {
    this.expireDue();
    return this.store.get(id);
  }

  list(status?: ApprovalStatus): ApprovalRequest[] {
    this.expireDue();
    return this.store.filter((a) => !status || a.status === status).sort((a, b) => b.created_at.localeCompare(a.created_at));
  }

  /** Creates a request, or returns the live one with the same binding (pending, or approved and unused). */
  async create(n: NewApproval): Promise<ApprovalRequest> {
    this.expireDue();
    const existing = this.store.filter((a) => a.binding === n.binding && !a.consumed_at && (a.status === "pending" || a.status === "approved"))[0];
    if (existing) return existing;
    const now = Date.now();
    const req: ApprovalRequest = {
      id: randomId("apr_", 9),
      binding: n.binding,
      status: "pending",
      required: Math.max(1, Math.min(n.required, 5)),
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + n.timeoutMs).toISOString(),
      decided_at: null,
      consumed_at: null,
      votes: [],
      channels: n.channels,
      context: n.context,
    };
    this.store.put(req);
    this.ledger?.append({
      type: "approval.requested",
      principal: n.context.principal,
      agent: n.context.agent,
      actor_chain: n.context.actor_chain,
      task_id: n.context.task_id,
      tool: { name: n.context.tool, server: n.context.server, risk: n.context.risk },
      args: n.context.args,
      approval: { id: req.id, status: "pending", required: req.required },
      details: { rule: n.context.rule, reasons: n.context.reasons, expires_at: req.expires_at },
    });
    const targets = n.channels.length ? this.notifiers.filter((x) => n.channels.includes(x.name)) : this.notifiers;
    await Promise.allSettled(targets.map((x) => x.notify(req)));
    return req;
  }

  /**
   * Records a vote. `identities` are every verified identifier of the approver (IdP sub, e-mail, key id):
   * all are checked against the requesting principal (no self-approval) and against earlier voters.
   */
  decide(id: string, vote: { by: string; decision: "approve" | "deny"; via: string; comment?: string; identities?: string[] }): ApprovalRequest {
    const req = this.get(id);
    if (!req) throw new ApprovalError(404, "Approval request not found");
    if (req.status !== "pending") throw new ApprovalError(409, `Approval is already ${req.status}`);
    if (!vote.by) throw new ApprovalError(400, "Approver identity is required");
    const norm = (x: string) => x.toLowerCase();
    const mine = new Set([vote.by, ...(vote.identities ?? [])].filter(Boolean).map(norm));
    const requester = [req.context.principal.sub, req.context.principal.email].filter((x): x is string => Boolean(x)).map(norm);
    if (requester.some((x) => mine.has(x)))
      throw new ApprovalError(403, "Self-approval is not allowed: the requesting principal cannot approve their own agent's action");
    if (req.votes.some((v) => [v.by, ...(v.identities ?? [])].some((x) => mine.has(norm(x))))) throw new ApprovalError(409, `${vote.by} has already voted`);
    const votes = [...req.votes, { ...vote, at: new Date().toISOString() }];
    const approvals = votes.filter((v) => v.decision === "approve").length;
    const status: ApprovalStatus = vote.decision === "deny" ? "denied" : approvals >= req.required ? "approved" : "pending";
    const next = this.store.update(id, (r) => ({ ...r, votes, status, decided_at: status === "pending" ? null : new Date().toISOString() }))!;
    if (status !== "pending") this.finalised(next);
    return next;
  }

  /** Marks an approved request as used. Returns false if it was already used (replay). */
  consume(id: string): boolean {
    const req = this.get(id);
    if (!req || req.status !== "approved" || req.consumed_at) return false;
    this.store.update(id, (r) => ({ ...r, consumed_at: new Date().toISOString() }));
    return true;
  }

  /** Resolves when the request leaves `pending` or after `timeoutMs` (returning the current state). */
  wait(id: string, timeoutMs: number): Promise<ApprovalRequest | undefined> {
    const cur = this.get(id);
    if (!cur || cur.status !== "pending" || timeoutMs <= 0) return Promise.resolve(cur);
    return new Promise((resolve) => {
      const done = () => { clearTimeout(t); this.events.off(id, done); resolve(this.store.get(id)); };
      const t = setTimeout(done, Math.min(timeoutMs, Date.parse(cur.expires_at) - Date.now() + 50));
      this.events.on(id, done);
    });
  }

  private expireDue(): void {
    const now = new Date().toISOString();
    for (const r of this.store.filter((a) => a.status === "pending" && a.expires_at <= now)) {
      const next = this.store.update(r.id, (x) => ({ ...x, status: "expired", decided_at: now }))!;
      this.finalised(next);
    }
  }

  private finalised(req: ApprovalRequest): void {
    this.ledger?.append({
      type: "approval.decided",
      principal: req.context.principal,
      agent: req.context.agent,
      actor_chain: req.context.actor_chain,
      task_id: req.context.task_id,
      tool: { name: req.context.tool, server: req.context.server, risk: req.context.risk },
      approval: {
        id: req.id, status: req.status, required: req.required, decided_at: req.decided_at,
        approvers: req.votes.filter((v) => v.decision === "approve").map((v) => v.by),
      },
      details: { votes: req.votes },
    });
    this.events.emit(req.id);
    for (const n of this.notifiers) void n.decided?.(req).catch(() => {});
  }
}

// ---------- channels ----------

function summary(req: ApprovalRequest): string {
  const c = req.context;
  return `${c.agent.id} wants to call ${c.tool} on behalf of ${c.principal.email ?? c.principal.sub}`;
}

/** Generic signed webhook: POST JSON, `X-Mandat-Signature: sha256=<hmac(timestamp + "." + body)>`. */
export class WebhookNotifier implements Notifier {
  name: string;
  private url: string;
  private secret: string;
  private consoleUrl: string;

  constructor(opts: { url: string; secret: string; consoleUrl: string; name?: string }) {
    this.name = opts.name ?? "webhook";
    this.url = opts.url;
    this.secret = opts.secret;
    this.consoleUrl = opts.consoleUrl;
  }

  async notify(req: ApprovalRequest): Promise<void> {
    await this.post({ event: "approval.requested", summary: summary(req), approval: req, console_url: `${this.consoleUrl}#${req.id}` });
  }

  async decided(req: ApprovalRequest): Promise<void> {
    await this.post({ event: "approval.decided", summary: `${summary(req)}: ${req.status}`, approval: req });
  }

  private async post(payload: unknown): Promise<void> {
    const body = JSON.stringify(payload);
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = createHmac("sha256", this.secret).update(`${ts}.${body}`).digest("hex");
    await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandat-timestamp": ts, "x-mandat-signature": `sha256=${sig}` },
      body,
      signal: AbortSignal.timeout(5000),
    });
  }
}

/** Slack via an app's Incoming Webhook; buttons are handled by `handleSlackInteraction`. */
export class SlackNotifier implements Notifier {
  name = "slack";
  private webhookUrl: string;
  private consoleUrl: string;

  constructor(opts: { webhookUrl: string; consoleUrl: string }) {
    this.webhookUrl = opts.webhookUrl;
    this.consoleUrl = opts.consoleUrl;
  }

  async notify(req: ApprovalRequest): Promise<void> {
    await fetch(this.webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: `Approval needed: ${summary(req)}`, blocks: slackBlocks(req, this.consoleUrl) }),
      signal: AbortSignal.timeout(5000),
    });
  }
}

export function slackBlocks(req: ApprovalRequest, consoleUrl: string): unknown[] {
  const c = req.context;
  const args = JSON.stringify(c.args, null, 2);
  const blocks: unknown[] = [
    { type: "header", text: { type: "plain_text", text: req.status === "pending" ? "🛂 Agent action needs approval" : `Agent action ${req.status}` } },
    { type: "section", text: { type: "mrkdwn", text: `*${c.agent.id}*${c.agent.version ? ` (v${c.agent.version})` : ""} wants to call \`${c.tool}\` on behalf of *${c.principal.email ?? c.principal.sub}*` } },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Risk*\n${c.risk ?? "unclassified"}` },
        { type: "mrkdwn", text: `*Rule*\n${c.rule}` },
        { type: "mrkdwn", text: `*Delegation*\n${[c.principal.sub, ...(c.actor_chain ?? []).slice().reverse()].join(" → ")}` },
        { type: "mrkdwn", text: `*Expires*\n<!date^${Math.floor(Date.parse(req.expires_at) / 1000)}^{time}|${req.expires_at}>` },
      ],
    },
    { type: "section", text: { type: "mrkdwn", text: "```" + args.slice(0, 2500) + "```" } },
  ];
  if (c.session_tainted) blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: "⚠️ Session has processed untrusted content (possible prompt injection)." }] });
  if (req.status === "pending") {
    blocks.push({
      type: "actions",
      block_id: `mandat_${req.id}`,
      elements: [
        { type: "button", style: "primary", text: { type: "plain_text", text: "Approve" }, action_id: "mandat_approve", value: req.id },
        { type: "button", style: "danger", text: { type: "plain_text", text: "Deny" }, action_id: "mandat_deny", value: req.id },
        { type: "button", text: { type: "plain_text", text: "Open in console" }, url: `${consoleUrl}#${req.id}`, action_id: "mandat_open" },
      ],
    });
  } else {
    const who = req.votes.map((v) => `${v.decision === "approve" ? "✅" : "⛔"} ${v.by}`).join(", ");
    blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: `${req.status.toUpperCase()} ${who}` }] });
  }
  return blocks;
}

/** Verifies Slack's request signature (v0 HMAC-SHA256, 5 minute replay window). */
export function verifySlackSignature(rawBody: string, timestamp: string | undefined, signature: string | undefined, signingSecret: string): boolean {
  if (!timestamp || !signature) return false;
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;
  const expected = "v0=" + createHmac("sha256", signingSecret).update(`v0:${timestamp}:${rawBody}`).digest("hex");
  return safeEqual(expected, signature);
}

export function handleSlackInteraction(service: ApprovalService, rawBody: string, consoleUrl: string): { replace_original: boolean; blocks?: unknown[]; text: string } {
  const payload = JSON.parse(new URLSearchParams(rawBody).get("payload") ?? "{}");
  const action = payload.actions?.[0];
  if (!action || (action.action_id !== "mandat_approve" && action.action_id !== "mandat_deny")) return { replace_original: false, text: "ignored" };
  const by = `slack:${payload.user?.username ?? payload.user?.id}`;
  try {
    const req = service.decide(action.value, { by, decision: action.action_id === "mandat_approve" ? "approve" : "deny", via: "slack" });
    return { replace_original: true, text: `Approval ${req.status}`, blocks: slackBlocks(req, consoleUrl) };
  } catch (e) {
    return { replace_original: false, text: `⚠️ ${(e as Error).message}` };
  }
}

/** Dev channel: prints a hint to the control plane's stdout. */
export class ConsoleLogNotifier implements Notifier {
  name = "log";
  async notify(req: ApprovalRequest): Promise<void> {
    console.log(`[approval] ${req.id}: ${summary(req)} — approve with: mandat approvals approve ${req.id}`);
  }
}
