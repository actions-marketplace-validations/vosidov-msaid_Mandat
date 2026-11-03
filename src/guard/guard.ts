// Mandat Guard: the Policy Enforcement Point embedded in an MCP server (or any tool-executing service).
//
// For every tool call:
//   1. verify the per-task bearer token (iss, aud = this resource, exp, typ at+jwt, signature via JWKS)
//   2. reject revoked tokens / agents / versions / users
//   3. reject tools whose definitions drifted from the pinned lockfile (block mode)
//   4. evaluate policy (PDP, in-process) with args, delegation chain, capability and session taint
//   5. require_approval -> create/await a human approval bound to this exact call
//   6. run the handler, then write ONE hash-chained Action Record with decision + outcome

import type { KeyObject } from "node:crypto";
import { JwksClient, JwtError, verifyJwt, type JwtPayload } from "../sts/jwt.ts";
import { actorChain, matchRevocation, type MandatClaim, type Revocation } from "../sts/revocation.ts";
import { HIGH_RISK, type AuthorizationDetail, type CompiledPolicy, type Decision, type Obligation } from "../policy/engine.ts";
import { approvalBinding, type ApprovalRequest, type ApprovalService, type NewApproval } from "../approvals/approvals.ts";
import { redact, type RedactionOptions } from "../ledger/redact.ts";
import type { ActionRecord, LedgerSink, RecordInput } from "../ledger/ledger.ts";
import { checkPins, toolHash, type DriftReport, type ToolDefinition } from "./pinning.ts";

// ---------- pluggable sources (local or remote control plane) ----------

export interface PolicySource { current(): CompiledPolicy }
export interface RevocationSource {
  check(claims: JwtPayload): Revocation | null;
  /** True when the revocation list could not be refreshed recently (control plane unreachable). */
  stale(): boolean;
}
export interface ApprovalBroker {
  request(n: NewApproval): Promise<ApprovalRequest>;
  wait(id: string, timeoutMs: number): Promise<ApprovalRequest | undefined>;
  consume(id: string): Promise<boolean>;
}

export class StaticPolicy implements PolicySource {
  private p: CompiledPolicy;
  constructor(p: CompiledPolicy) { this.p = p; }
  current(): CompiledPolicy { return this.p; }
  set(p: CompiledPolicy): void { this.p = p; }
}

export class LocalRevocations implements RevocationSource {
  private list: () => Iterable<Revocation>;
  constructor(list: () => Iterable<Revocation>) { this.list = list; }
  check(claims: JwtPayload): Revocation | null { return matchRevocation(claims, this.list()); }
  stale(): boolean { return false; }
}

export class LocalApprovalBroker implements ApprovalBroker {
  private svc: ApprovalService;
  constructor(svc: ApprovalService) { this.svc = svc; }
  request(n: NewApproval) { return this.svc.create(n); }
  wait(id: string, ms: number) { return this.svc.wait(id, ms); }
  async consume(id: string) { return this.svc.consume(id); }
}

// ---------- types ----------

export interface VerifiedAuth {
  token: string;
  claims: JwtPayload;
  principal: { sub: string; tenant: string | null; email: string | null };
  agent: { id: string; version: string | null; prompt_hash: string | null };
  actor_chain: string[];
  task_id: string | null;
  session_id: string | null;
  authorization_details: AuthorizationDetail[] | null;
}

export interface GuardOptions {
  /** Canonical URL of this MCP server; tokens must carry it in `aud`. */
  resource: string;
  /** Mandat issuer (control plane URL). */
  issuer: string;
  /** JWKS of the issuer. Default `${issuer}/.well-known/jwks.json`. Ignored if `publicKey` is set. */
  jwksUri?: string;
  publicKey?: KeyObject;
  policy: PolicySource;
  revocations: RevocationSource;
  approvals: ApprovalBroker;
  ledger: LedgerSink;
  /** "shadow": decide and log, but never block (for rolling out new policies). */
  mode?: "enforce" | "shadow";
  /** How long a tool call blocks waiting for a human before returning "pending". Default 20 s. */
  approvalWaitMs?: number;
  pinning?: { lockfile: string; mode?: "warn" | "block"; frozen?: boolean };
  redaction?: RedactionOptions;
  /** Name of this guard instance in ledger records. */
  source?: string;
  /** Called on drift, denials etc. Default: console.warn. */
  log?: (msg: string) => void;
}

export interface CallContext {
  auth: VerifiedAuth;
  tool: string;
  args: Record<string, unknown>;
  /** Transport-level session (e.g. Mcp-Session-Id). Falls back to token session / task id. */
  sessionId?: string | null;
}

export class AuthError extends Error {
  status: number;
  code: string;
  constructor(code: string, message: string, status = 401) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export class GuardDenied extends Error {
  code: "denied" | "approval_pending" | "approval_denied" | "revoked" | "drift" | "fail_closed";
  decision: Decision | null;
  record: ActionRecord | void;
  approvalId?: string;
  constructor(code: GuardDenied["code"], message: string, decision: Decision | null, record: ActionRecord | void, approvalId?: string) {
    super(message);
    this.code = code;
    this.decision = decision;
    this.record = record;
    this.approvalId = approvalId;
  }
}

interface SessionState { tainted: boolean; taint_sources: string[]; calls: number; touched: number }

const SESSION_TTL_MS = 6 * 3_600_000;

export class Guard {
  readonly opts: GuardOptions;
  private jwks: JwksClient | null;
  private sessions = new Map<string, SessionState>();
  private toolDefs = new Map<string, string>();
  private blockedTools = new Set<string>();
  private log: (m: string) => void;

  constructor(opts: GuardOptions) {
    this.opts = { mode: "enforce", approvalWaitMs: 20_000, ...opts };
    this.jwks = opts.publicKey ? null : new JwksClient(opts.jwksUri ?? `${opts.issuer.replace(/\/$/, "")}/.well-known/jwks.json`);
    this.log = opts.log ?? ((m) => console.warn(`[mandat] ${m}`));
  }

  /** RFC 9728 Protected Resource Metadata for this server. */
  protectedResourceMetadata(extra: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      resource: this.opts.resource,
      authorization_servers: [this.opts.issuer],
      bearer_methods_supported: ["header"],
      resource_signing_alg_values_supported: ["ES256"],
      authorization_details_types_supported: ["mandat_tool_call"],
      resource_name: this.opts.source ?? "MCP server protected by Mandat",
      ...extra,
    };
  }

  /** Verifies a bearer token. Throws AuthError (map to HTTP 401/403 + WWW-Authenticate). */
  async verify(token: string | undefined): Promise<VerifiedAuth> {
    if (!token) throw new AuthError("invalid_token", "Bearer token required");
    let claims: JwtPayload;
    try {
      claims = await verifyJwt(
        token,
        this.opts.publicKey ? () => this.opts.publicKey! : (h) => this.jwks!.getKey(h.kid),
        { issuer: this.opts.issuer, audience: this.opts.resource, typ: "at+jwt", requireExp: true },
      );
    } catch (e) {
      if (e instanceof JwtError) throw new AuthError("invalid_token", e.message);
      throw new AuthError("invalid_token", `Token verification failed: ${(e as Error).message}`);
    }
    const chain = actorChain(claims);
    if (!chain.length) throw new AuthError("invalid_token", "Token has no `act` claim: not a delegated agent token");
    const m = (claims.mandat ?? {}) as MandatClaim;
    const revoked = this.opts.revocations.check(claims);
    if (revoked) throw new AuthError("invalid_token", `Token revoked (${revoked.type}: ${revoked.value}${revoked.reason ? ` - ${revoked.reason}` : ""})`);
    return {
      token,
      claims,
      principal: { sub: String(claims.sub), tenant: m.tenant ?? null, email: (claims.email as string) ?? null },
      agent: { id: chain[0]!.sub, version: m.agent_version ?? chain[0]!.mandat_agent_version ?? null, prompt_hash: m.prompt_hash ?? null },
      actor_chain: chain.map((a) => a.sub),
      task_id: m.task_id ?? null,
      session_id: m.session_id ?? null,
      authorization_details: (claims.authorization_details as AuthorizationDetail[] | undefined) ?? null,
    };
  }

  /**
   * OAuthTokenVerifier for the official MCP SDK's `requireBearerAuth`. Pass the SDK's InvalidTokenError
   * so failures become proper 401 responses.
   */
  sdkTokenVerifier(errors: { InvalidTokenError?: new (msg: string) => Error } = {}) {
    return {
      verifyAccessToken: async (token: string) => {
        try {
          const auth = await this.verify(token);
          return {
            token,
            clientId: auth.agent.id,
            scopes: typeof auth.claims.scope === "string" ? auth.claims.scope.split(" ") : [],
            expiresAt: auth.claims.exp,
            resource: new URL(this.opts.resource),
            extra: { mandat: auth },
          };
        } catch (e) {
          throw errors.InvalidTokenError ? new errors.InvalidTokenError((e as Error).message) : e;
        }
      },
    };
  }

  /** Register the server's tool definitions: computes hashes and checks them against the pin lockfile. */
  registerTools(defs: ToolDefinition[]): DriftReport | null {
    for (const d of defs) this.toolDefs.set(d.name, toolHash(d));
    if (!this.opts.pinning) return null;
    const res = checkPins(this.opts.pinning.lockfile, defs, { mode: this.opts.pinning.mode ?? "warn", frozen: this.opts.pinning.frozen, server: this.opts.resource });
    this.blockedTools = res.blocked;
    if (!res.drift.clean) {
      const msg = `Tool definition drift: changed=[${res.drift.changed.map((c) => c.name)}] added=[${res.drift.added}] removed=[${res.drift.removed}]` +
        (res.blocked.size ? ` — blocked until re-pinned: ${[...res.blocked].join(", ")}` : "");
      this.log(msg);
      this.append({ type: "tool.drift", tool: { name: "*", server: this.opts.resource }, details: { ...res.drift, mode: this.opts.pinning.mode ?? "warn" } });
    }
    return res.drift;
  }

  /**
   * Authorises and executes one tool call. Returns the handler's result, or throws GuardDenied.
   * Exactly one `agent.tool_call` record is written per invocation.
   */
  async execute<T>(ctx: CallContext, handler: () => Promise<T> | T): Promise<T> {
    const started = Date.now();
    const policy = this.opts.policy.current();
    const meta = policy.toolMeta(ctx.tool);
    const sessionKey = ctx.sessionId ?? ctx.auth.session_id ?? ctx.auth.task_id ?? ctx.auth.claims.jti ?? "anonymous";
    const session = this.session(sessionKey);
    const shadow = this.opts.mode === "shadow";

    const base = (decision: Decision | null, final: "allow" | "deny" | "pending"): RecordInput => ({
      type: "agent.tool_call",
      source: this.opts.source,
      principal: ctx.auth.principal,
      agent: ctx.auth.agent,
      actor_chain: ctx.auth.actor_chain,
      task_id: ctx.auth.task_id,
      token_jti: (ctx.auth.claims.jti as string) ?? null,
      session: { id: sessionKey, tainted: session.tainted, taint_sources: session.taint_sources },
      tool: { name: ctx.tool, server: this.opts.resource, risk: meta.risk ?? null, definition_hash: this.toolDefs.get(ctx.tool) ?? null },
      args: this.redactArgs(ctx.args, [...(decision?.obligations ?? [])]),
      decision: decision
        ? { effect: decision.effect, final, rules: decision.matched, reasons: decision.reasons, obligations: decision.obligations, policy_version: decision.policy_version, latency_us: Math.round(decision.latency_us), mode: this.opts.mode }
        : { effect: "deny", final, rules: [], reasons: [], mode: this.opts.mode },
      tags: decision?.obligations.filter((o) => o.type === "annotate").flatMap((o) => o.tags ?? []),
    });
    const deny = (code: GuardDenied["code"], reason: string, decision: Decision | null, extra: Partial<RecordInput> = {}): never => {
      const rec = this.append({ ...base(decision, "deny"), ...extra, outcome: { status: "blocked", error: reason, duration_ms: Date.now() - started } });
      throw new GuardDenied(code, reason, decision, rec, extra.approval?.id);
    };

    // Re-check revocation on every call (token may have been revoked after verify).
    const revoked = this.opts.revocations.check(ctx.auth.claims);
    if (revoked) deny("revoked", `Token revoked (${revoked.type}: ${revoked.value})`, null);

    if (this.blockedTools.has(ctx.tool) && !shadow)
      deny("drift", `Tool '${ctx.tool}' changed since it was pinned; re-approve its definition with \`mandat pin\``, null);

    const decision = policy.evaluate({
      principal: { ...ctx.auth.principal, ...pickClaims(ctx.auth.claims) },
      agent: ctx.auth.agent,
      actor_chain: ctx.auth.actor_chain.map((sub) => ({ sub })),
      tool: { name: ctx.tool, server: this.opts.resource },
      args: ctx.args,
      session: { id: sessionKey, tainted: session.tainted, taint_sources: session.taint_sources, calls: session.calls },
      task: { id: ctx.auth.task_id, authorization_details: ctx.auth.authorization_details },
    });

    // Fail closed for high-risk tools when the control plane (revocations) is unreachable.
    if (this.opts.revocations.stale() && meta.risk && HIGH_RISK.includes(meta.risk) && !shadow)
      deny("fail_closed", `Control plane unreachable: '${meta.risk}' tools fail closed`, decision);

    let approvalInfo: RecordInput["approval"];
    if (!shadow && decision.effect === "deny") deny("denied", decision.reasons.join("; "), decision);
    if (!shadow && decision.effect === "require_approval") {
      const a = decision.approval!;
      let req: ApprovalRequest | undefined;
      try {
        req = await this.opts.approvals.request({
          binding: approvalBinding({ sub: ctx.auth.principal.sub, agent: ctx.auth.agent.id, tool: ctx.tool, server: this.opts.resource, args: ctx.args }),
          required: a.approvers,
          timeoutMs: a.timeoutMs,
          channels: a.channels,
          context: {
            tool: ctx.tool, server: this.opts.resource, risk: meta.risk ?? null,
            args: this.redactArgs(ctx.args, decision.obligations),
            principal: ctx.auth.principal, agent: ctx.auth.agent, actor_chain: ctx.auth.actor_chain,
            task_id: ctx.auth.task_id, rule: a.rule, reasons: decision.reasons, session_tainted: session.tainted,
          },
        });
        if (req.status === "pending") req = await this.opts.approvals.wait(req.id, this.opts.approvalWaitMs!);
      } catch (e) {
        deny("fail_closed", `Approval service unavailable: ${(e as Error).message}`, decision);
      }
      const r = req!;
      approvalInfo = { id: r.id, status: r.status, required: r.required, approvers: r.votes.filter((v) => v.decision === "approve").map((v) => v.by) };
      if (r.status === "pending") {
        const rec = this.append({ ...base(decision, "pending"), approval: approvalInfo, outcome: { status: "pending", duration_ms: Date.now() - started } });
        throw new GuardDenied("approval_pending", `Human approval required (request ${r.id}, expires ${r.expires_at}). Retry the same call once it is approved.`, decision, rec, r.id);
      }
      if (r.status !== "approved") deny("approval_denied", `Approval ${r.id} was ${r.status}`, decision, { approval: approvalInfo });
      if (!(await this.opts.approvals.consume(r.id))) deny("approval_denied", `Approval ${r.id} was already used`, decision, { approval: approvalInfo });
    }

    session.calls++;
    try {
      const result = await handler();
      if (meta.taints && !session.tainted) {
        session.tainted = true;
        session.taint_sources.push(ctx.tool);
      }
      this.append({ ...base(decision, "allow"), approval: approvalInfo, outcome: { status: "success", duration_ms: Date.now() - started } });
      return result;
    } catch (e) {
      this.append({ ...base(decision, "allow"), approval: approvalInfo, outcome: { status: "error", error: (e as Error).message?.slice(0, 500), duration_ms: Date.now() - started } });
      throw e;
    }
  }

  /** Session taint state (for tests / introspection). */
  sessionState(key: string): SessionState | undefined { return this.sessions.get(key); }

  private session(key: string): SessionState {
    const now = Date.now();
    let s = this.sessions.get(key);
    if (!s) {
      if (this.sessions.size > 10_000) {
        for (const [k, v] of this.sessions) if (now - v.touched > SESSION_TTL_MS) this.sessions.delete(k);
      }
      s = { tainted: false, taint_sources: [], calls: 0, touched: now };
      this.sessions.set(key, s);
    }
    s.touched = now;
    return s;
  }

  private redactArgs(args: Record<string, unknown>, obligations: Obligation[]): unknown {
    const fields = obligations.filter((o) => o.type === "redact").flatMap((o) => o.fields ?? []);
    return redact(args, { ...this.opts.redaction, fields: [...(this.opts.redaction?.fields ?? []), ...fields] });
  }

  private append(rec: RecordInput): ActionRecord | void {
    try {
      return this.opts.ledger.append({ source: this.opts.source, ...rec });
    } catch (e) {
      this.log(`Ledger append failed: ${(e as Error).message}`);
    }
  }
}

/** Selected token claims exposed to policies as principal.* (never the raw token). */
function pickClaims(c: JwtPayload): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of ["scope", "client_id", "email"]) if (c[k] !== undefined) out[k] = c[k];
  return out;
}
