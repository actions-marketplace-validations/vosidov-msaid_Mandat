// Policy Decision Point (PDP). Pure, synchronous, in-process: no I/O on the decision path.
//
// Combining algorithm is order-independent "deny overrides":
//   any matching `deny`  -> deny
//   else any `require_approval` -> require_approval
//   else any `allow` / `allow_with_obligations` -> allow (obligations merged)
//   else policy `default` (deny unless configured otherwise)
//
// A condition that fails to evaluate (type error, missing data) counts as a MATCH for
// deny / require_approval rules and as NO MATCH for allow rules: errors always fail closed.

import { compileExpr, type CompiledExpr } from "./expr.ts";
import { canonicalJson, getPath, globMatch, parseDuration, sha256 } from "../util.ts";

export type Effect = "allow" | "deny" | "require_approval" | "allow_with_obligations";
export type Risk = "read" | "write" | "external_comm" | "financial" | "destructive";
export const HIGH_RISK: readonly Risk[] = ["financial", "destructive"];

export interface Obligation {
  /** redact: hide `fields` (arg paths) in the ledger. annotate: attach `tags` to the record. */
  type: "redact" | "annotate";
  fields?: string[];
  tags?: string[];
}

export interface ApprovalSpec {
  /** Number of distinct human approvers required (four-eyes = 2). */
  approvers?: number;
  /** e.g. "10m". After timeout the request is denied. */
  timeout?: string;
  /** Channel names configured on the control plane, e.g. ["slack", "webhook"]. */
  channels?: string[];
}

export interface Rule {
  id: string;
  description?: string;
  /** Tool name or glob ("crm.*"); list = any of. Omitted = every tool. */
  tool?: string | string[];
  /** Agent id or glob; list = any of. Omitted = every agent. */
  agent?: string | string[];
  /** Condition in the Mandat expression language. Omitted = always. */
  when?: string;
  effect: Effect;
  reason?: string;
  approval?: ApprovalSpec;
  obligations?: Obligation[];
}

export interface ToolMeta {
  risk?: Risk;
  /** Output of this tool is untrusted (e-mail, web pages, tickets): taints the session. */
  taints?: boolean;
  /** Arg paths always redacted in the ledger. */
  redact?: string[];
  description?: string;
}

export interface PolicyDocument {
  version: 1;
  /** Decision when no rule matches. Default: "deny". */
  default?: "deny" | "allow" | "require_approval";
  tools?: Record<string, ToolMeta>;
  rules: Rule[];
}

export interface PolicyInput {
  principal: { sub: string; tenant?: string | null; [k: string]: unknown };
  agent: { id: string; version?: string | null; prompt_hash?: string | null; [k: string]: unknown };
  actor_chain?: Array<{ sub: string; [k: string]: unknown }>;
  tool: { name: string; server?: string | null };
  args: Record<string, unknown>;
  session?: { id?: string; tainted?: boolean; taint_sources?: string[]; calls?: number };
  task?: { id?: string | null; authorization_details?: AuthorizationDetail[] | null };
  env?: Record<string, unknown>;
}

/** RFC 9396 authorization_details entry understood by Mandat. */
export interface AuthorizationDetail {
  type: "mandat_tool_call" | string;
  tools?: string[];
  locations?: string[];
  /** Per-argument limits: { amount: { max: 100 }, currency: { enum: ["EUR"] } } */
  limits?: Record<string, { max?: number; min?: number; enum?: unknown[]; equals?: unknown }>;
  [k: string]: unknown;
}

export interface Decision {
  effect: Effect;
  reasons: string[];
  matched: string[];
  obligations: Obligation[];
  approval?: Required<Pick<ApprovalSpec, "approvers">> & { timeoutMs: number; channels: string[]; rule: string };
  risk: Risk | null;
  errors: string[];
  policy_version: string;
  latency_us: number;
}

interface CompiledRule extends Rule {
  cond?: CompiledExpr;
  tools: string[] | null;
  agents: string[] | null;
}

export interface CompiledPolicy {
  doc: PolicyDocument;
  version: string;
  evaluate(input: PolicyInput): Decision;
  toolMeta(name: string): ToolMeta;
}

const EFFECTS: Effect[] = ["allow", "deny", "require_approval", "allow_with_obligations"];
const RISKS: Risk[] = ["read", "write", "external_comm", "financial", "destructive"];
const DEFAULT_APPROVAL_TIMEOUT_MS = 10 * 60_000;

export class PolicyError extends Error {}

/** Validates and compiles a policy. Throws PolicyError listing every problem found. */
export function compilePolicy(doc: PolicyDocument): CompiledPolicy {
  const problems: string[] = [];
  if (!doc || typeof doc !== "object") throw new PolicyError("Policy must be an object");
  if (doc.version !== 1) problems.push(`Unsupported policy version ${String(doc.version)} (expected 1)`);
  if (!Array.isArray(doc.rules)) problems.push("`rules` must be an array");
  if (doc.default && !["deny", "allow", "require_approval"].includes(doc.default)) problems.push(`Invalid default '${doc.default}'`);
  for (const [name, meta] of Object.entries(doc.tools ?? {})) {
    if (meta.risk && !RISKS.includes(meta.risk)) problems.push(`tools.${name}.risk: unknown risk '${meta.risk}' (use ${RISKS.join(", ")})`);
  }
  const ids = new Set<string>();
  const rules: CompiledRule[] = [];
  for (const [i, r] of (doc.rules ?? []).entries()) {
    const where = `rules[${i}]${r?.id ? ` (${r.id})` : ""}`;
    if (!r.id) problems.push(`${where}: missing id`);
    else if (ids.has(r.id)) problems.push(`${where}: duplicate id`);
    ids.add(r.id);
    if (!EFFECTS.includes(r.effect)) problems.push(`${where}: invalid effect '${r.effect}'`);
    let cond: CompiledExpr | undefined;
    if (r.when !== undefined) {
      try { cond = compileExpr(r.when); } catch (e) { problems.push(`${where}: ${(e as Error).message}`); }
    }
    if (r.approval?.timeout) {
      try { parseDuration(r.approval.timeout); } catch (e) { problems.push(`${where}: ${(e as Error).message}`); }
    }
    for (const o of r.obligations ?? []) {
      if (o.type !== "redact" && o.type !== "annotate") problems.push(`${where}: unsupported obligation '${(o as Obligation).type}'`);
    }
    rules.push({
      ...r,
      cond,
      tools: r.tool === undefined ? null : Array.isArray(r.tool) ? r.tool : [r.tool],
      agents: r.agent === undefined ? null : Array.isArray(r.agent) ? r.agent : [r.agent],
    });
  }
  if (problems.length) throw new PolicyError("Invalid policy:\n  - " + problems.join("\n  - "));

  const version = sha256(canonicalJson(doc)).slice(0, 16);
  const tools = doc.tools ?? {};
  const toolMeta = (name: string): ToolMeta => {
    if (tools[name]) return tools[name]!;
    const glob = Object.keys(tools).find((k) => k.includes("*") && globMatch(k, name));
    return glob ? tools[glob]! : {};
  };

  return {
    doc,
    version,
    toolMeta,
    evaluate(input: PolicyInput): Decision {
      const t0 = process.hrtime.bigint();
      const meta = toolMeta(input.tool.name);
      const risk = meta.risk ?? null;
      const ctx = buildContext(input, meta);
      const errors: string[] = [];
      const finish = (d: Omit<Decision, "latency_us" | "policy_version" | "risk" | "errors">): Decision => ({
        ...d,
        risk,
        errors,
        policy_version: version,
        latency_us: Number(process.hrtime.bigint() - t0) / 1000,
      });

      // 1. Capability bound by the task token (RFC 9396 authorization_details).
      const cap = checkCapability(input);
      if (cap) return finish({ effect: "deny", reasons: [cap], matched: ["@capability"], obligations: [] });

      // 2. Policy rules.
      const hits: Record<"deny" | "approval" | "allow", CompiledRule[]> = { deny: [], approval: [], allow: [] };
      for (const r of rules) {
        if (r.tools && !r.tools.some((p) => globMatch(p, input.tool.name))) continue;
        if (r.agents && !r.agents.some((p) => globMatch(p, input.agent.id))) continue;
        let match = true;
        if (r.cond) {
          try {
            const v = r.cond.eval(ctx);
            if (typeof v !== "boolean") throw new Error(`condition returned ${typeof v}, expected boolean`);
            match = v;
          } catch (e) {
            errors.push(`${r.id}: ${(e as Error).message}`);
            match = r.effect === "deny" || r.effect === "require_approval";
          }
        }
        if (!match) continue;
        if (r.effect === "deny") hits.deny.push(r);
        else if (r.effect === "require_approval") hits.approval.push(r);
        else hits.allow.push(r);
      }

      const baseObligations: Obligation[] = meta.redact?.length ? [{ type: "redact", fields: meta.redact }] : [];
      if (hits.deny.length) {
        return finish({
          effect: "deny",
          reasons: hits.deny.map((r) => r.reason ?? `Denied by rule ${r.id}`),
          matched: hits.deny.map((r) => r.id),
          obligations: baseObligations,
        });
      }
      if (hits.approval.length) {
        const approvers = Math.max(...hits.approval.map((r) => r.approval?.approvers ?? 1));
        const timeoutMs = Math.min(...hits.approval.map((r) => (r.approval?.timeout ? parseDuration(r.approval.timeout) : DEFAULT_APPROVAL_TIMEOUT_MS)));
        const channels = [...new Set(hits.approval.flatMap((r) => r.approval?.channels ?? []))];
        return finish({
          effect: "require_approval",
          reasons: hits.approval.map((r) => r.reason ?? `Approval required by rule ${r.id}`),
          matched: hits.approval.map((r) => r.id),
          obligations: [...baseObligations, ...hits.allow.flatMap((r) => r.obligations ?? [])],
          approval: { approvers, timeoutMs, channels, rule: hits.approval[0]!.id },
        });
      }
      if (hits.allow.length) {
        const obligations = [...baseObligations, ...hits.allow.flatMap((r) => r.obligations ?? [])];
        return finish({
          effect: obligations.length ? "allow_with_obligations" : "allow",
          reasons: hits.allow.map((r) => r.reason ?? `Allowed by rule ${r.id}`),
          matched: hits.allow.map((r) => r.id),
          obligations,
        });
      }
      const def = doc.default ?? "deny";
      if (def === "require_approval") {
        return finish({
          effect: "require_approval",
          reasons: ["No rule matched; policy default requires approval"],
          matched: ["@default"],
          obligations: baseObligations,
          approval: { approvers: 1, timeoutMs: DEFAULT_APPROVAL_TIMEOUT_MS, channels: [], rule: "@default" },
        });
      }
      return finish({
        effect: def === "allow" ? "allow" : "deny",
        reasons: [def === "allow" ? "No rule matched; policy default allows" : "No rule matched; default deny"],
        matched: ["@default"],
        obligations: baseObligations,
      });
    },
  };
}

function buildContext(input: PolicyInput, meta: ToolMeta): Record<string, unknown> {
  return {
    principal: input.principal,
    agent: input.agent,
    actor_chain: input.actor_chain ?? [],
    tool: { ...input.tool, risk: meta.risk ?? null, taints: meta.taints ?? false },
    args: input.args ?? {},
    session: { tainted: false, taint_sources: [], calls: 0, ...input.session },
    task: input.task ?? {},
    env: { hour_utc: new Date().getUTCHours(), weekday_utc: new Date().getUTCDay(), ...input.env },
  };
}

/** Returns a deny reason if the call exceeds the capability carried in the task token, else null. */
export function checkCapability(input: PolicyInput): string | null {
  const details = input.task?.authorization_details;
  if (!details || !details.length) return null;
  const relevant = details.filter((d) => d.type === "mandat_tool_call");
  if (!relevant.length) return "Task token carries no mandat_tool_call authorization_details";
  const covering = relevant.filter(
    (d) =>
      (!d.tools || d.tools.some((p) => globMatch(p, input.tool.name))) &&
      (!d.locations || !input.tool.server || d.locations.includes(input.tool.server)),
  );
  if (!covering.length) return `Tool '${input.tool.name}' is outside the task's delegated capability`;
  // The call must satisfy the limits of at least one covering grant.
  const violations: string[] = [];
  for (const d of covering) {
    const v = limitViolation(d, input.args);
    if (!v) return null;
    violations.push(v);
  }
  return `Delegated capability limit exceeded: ${violations[0]}`;
}

function limitViolation(d: AuthorizationDetail, args: Record<string, unknown>): string | null {
  for (const [path, lim] of Object.entries(d.limits ?? {})) {
    const v = getPath(args, path);
    if (lim.max !== undefined && !(typeof v === "number" && v <= lim.max)) return `${path} must be <= ${lim.max}`;
    if (lim.min !== undefined && !(typeof v === "number" && v >= lim.min)) return `${path} must be >= ${lim.min}`;
    if (lim.enum !== undefined && !lim.enum.some((e) => e === v)) return `${path} must be one of ${JSON.stringify(lim.enum)}`;
    if (lim.equals !== undefined && v !== lim.equals) return `${path} must equal ${JSON.stringify(lim.equals)}`;
  }
  return null;
}

// ---------- policy tests (`mandat policy test`) ----------

export interface PolicyTestCase {
  name: string;
  input: Partial<PolicyInput> & { tool: PolicyInput["tool"] | string };
  expect: Effect | "allow*";
}

export interface PolicyTestResult { name: string; pass: boolean; expected: string; actual: Effect; reasons: string[] }

export function runPolicyTests(policy: CompiledPolicy, cases: PolicyTestCase[]): PolicyTestResult[] {
  return cases.map((c) => {
    const input: PolicyInput = {
      principal: { sub: "test-user" },
      agent: { id: "test-agent" },
      args: {},
      ...c.input,
      tool: typeof c.input.tool === "string" ? { name: c.input.tool } : c.input.tool,
    } as PolicyInput;
    const d = policy.evaluate(input);
    const pass = c.expect === "allow*" ? d.effect === "allow" || d.effect === "allow_with_obligations" : d.effect === c.expect;
    return { name: c.name, pass, expected: c.expect, actual: d.effect, reasons: d.reasons };
  });
}
