// Ledger -> SIEM / observability formats:
//   - OCSF 1.x "API Activity" (class 6003) events, type `agent.tool_call` in `metadata.labels`
//   - OpenTelemetry spans following the GenAI semantic conventions (`execute_tool`) + `mandat.*` attributes,
//     shipped over OTLP/HTTP JSON. Delivery is asynchronous, batched and retried (at-least-once).

import type { ActionRecord } from "./ledger.ts";
import { sha256 } from "../util.ts";

const OCSF_VERSION = "1.3.0";

export function toOcsf(r: ActionRecord): Record<string, unknown> {
  const activity = r.tool?.risk === "read" ? 2 : r.tool?.risk === "destructive" ? 4 : r.tool?.risk === "write" ? 3 : 99;
  const failed = r.outcome?.status === "error" || r.outcome?.status === "blocked";
  const severity = r.decision?.final === "deny" ? 3 : r.tool?.risk === "destructive" || r.tool?.risk === "financial" ? 2 : 1;
  return {
    class_uid: 6003,
    class_name: "API Activity",
    category_uid: 6,
    category_name: "Application Activity",
    activity_id: activity,
    type_uid: 6003 * 100 + activity,
    time: Date.parse(r.ts),
    severity_id: severity,
    status_id: failed ? 2 : 1,
    status: r.outcome?.status ?? r.decision?.final,
    status_detail: r.outcome?.error ?? r.decision?.reasons?.join("; "),
    message: describe(r),
    metadata: {
      version: OCSF_VERSION,
      uid: r.id,
      correlation_uid: r.task_id ?? undefined,
      labels: [r.type, ...(r.tags ?? [])],
      product: { name: "Mandat", vendor_name: "Mandat", version: "0.1.0" },
      sequence: r.seq,
    },
    actor: {
      user: r.principal ? { uid: r.principal.sub, email_addr: r.principal.email ?? undefined, org: r.principal.tenant ? { uid: r.principal.tenant } : undefined } : undefined,
      app_name: r.agent?.id,
      invoked_by: r.actor_chain?.join(" <- "),
      authorizations: r.decision ? [{ decision: r.decision.final, policy: { uid: r.decision.policy_version, name: r.decision.rules.join(",") } }] : undefined,
    },
    api: r.tool ? { operation: r.tool.name, service: { name: r.tool.server ?? "unknown" }, request: { uid: r.id } } : undefined,
    unmapped: {
      mandat: {
        record_hash: r.hash,
        prev_hash: r.prev_hash,
        effect: r.decision?.effect,
        args: r.args,
        approval: r.approval,
        session: r.session,
        token_jti: r.token_jti,
        agent_version: r.agent?.version,
        prompt_hash: r.agent?.prompt_hash,
        details: r.details,
      },
    },
  };
}

export function describe(r: ActionRecord): string {
  if (r.type === "agent.tool_call") {
    const who = r.principal?.sub ?? "?";
    return `${r.agent?.id ?? "?"} on behalf of ${who} called ${r.tool?.name} -> ${r.decision?.final ?? "?"} (${r.decision?.rules.join(",")})`;
  }
  return `${r.type}${r.details ? " " + JSON.stringify(r.details) : ""}`;
}

type OtlpValue = { stringValue: string } | { intValue: string } | { boolValue: boolean } | { doubleValue: number };
function attr(key: string, v: unknown): { key: string; value: OtlpValue } | null {
  if (v === undefined || v === null) return null;
  if (typeof v === "boolean") return { key, value: { boolValue: v } };
  if (typeof v === "number") return { key, value: Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v } };
  return { key, value: { stringValue: typeof v === "string" ? v : JSON.stringify(v) } };
}

export function toOtelSpan(r: ActionRecord): Record<string, unknown> {
  const endNs = BigInt(Date.parse(r.ts)) * 1_000_000n;
  const durNs = BigInt(Math.round((r.outcome?.duration_ms ?? 0) * 1e6));
  const isTool = r.type === "agent.tool_call";
  const attributes = [
    attr("gen_ai.operation.name", isTool ? "execute_tool" : r.type),
    attr("gen_ai.tool.name", r.tool?.name),
    attr("gen_ai.agent.id", r.agent?.id),
    attr("gen_ai.agent.name", r.agent?.id),
    attr("gen_ai.agent.version", r.agent?.version),
    attr("mcp.server.url", r.tool?.server),
    attr("enduser.id", r.principal?.sub),
    attr("mandat.record.id", r.id),
    attr("mandat.record.hash", r.hash),
    attr("mandat.record.type", r.type),
    attr("mandat.decision.effect", r.decision?.effect),
    attr("mandat.decision.final", r.decision?.final),
    attr("mandat.decision.rules", r.decision?.rules?.join(",")),
    attr("mandat.decision.latency_us", r.decision?.latency_us),
    attr("mandat.policy.version", r.decision?.policy_version),
    attr("mandat.principal.tenant", r.principal?.tenant),
    attr("mandat.actor_chain", r.actor_chain?.join(",")),
    attr("mandat.task.id", r.task_id),
    attr("mandat.token.jti", r.token_jti),
    attr("mandat.tool.risk", r.tool?.risk),
    attr("mandat.session.tainted", r.session?.tainted),
    attr("mandat.approval.id", r.approval?.id),
    attr("mandat.approval.status", r.approval?.status),
    attr("mandat.prompt.hash", r.agent?.prompt_hash),
  ].filter(Boolean);
  return {
    traceId: sha256(r.task_id ?? r.id).slice(0, 32),
    spanId: sha256(r.id).slice(0, 16),
    name: isTool ? `execute_tool ${r.tool?.name}` : r.type,
    kind: isTool ? 3 /* CLIENT */ : 1 /* INTERNAL */,
    startTimeUnixNano: String(endNs - durNs),
    endTimeUnixNano: String(endNs),
    attributes,
    status: r.outcome?.status === "error" || r.decision?.final === "deny" ? { code: 2, message: r.outcome?.error ?? r.decision?.reasons?.join("; ") } : { code: 1 },
  };
}

export interface OtlpExporterOptions {
  /** Base OTLP/HTTP endpoint, e.g. http://localhost:4318 (".../v1/traces" is appended). */
  endpoint: string;
  headers?: Record<string, string>;
  serviceName?: string;
  batchSize?: number;
  flushIntervalMs?: number;
  maxQueue?: number;
}

/** Off the critical path: `push` only enqueues; a timer flushes. Failed batches are re-queued with backoff. */
export class OtlpExporter {
  private queue: ActionRecord[] = [];
  private timer: NodeJS.Timeout;
  private flushing = false;
  private failures = 0;
  private opts: Required<Omit<OtlpExporterOptions, "headers">> & { headers: Record<string, string> };
  dropped = 0;

  constructor(opts: OtlpExporterOptions) {
    this.opts = { serviceName: "mandat", batchSize: 200, flushIntervalMs: 1000, maxQueue: 50_000, headers: {}, ...opts };
    this.timer = setInterval(() => void this.flush(), this.opts.flushIntervalMs);
    this.timer.unref();
  }

  push(r: ActionRecord): void {
    if (this.queue.length >= this.opts.maxQueue) { this.queue.shift(); this.dropped++; }
    this.queue.push(r);
  }

  async flush(): Promise<void> {
    if (this.flushing || !this.queue.length) return;
    this.flushing = true;
    try {
      while (this.queue.length) {
        const batch = this.queue.slice(0, this.opts.batchSize);
        const body = {
          resourceSpans: [{
            resource: { attributes: [attr("service.name", this.opts.serviceName)] },
            scopeSpans: [{ scope: { name: "mandat", version: "0.1.0" }, spans: batch.map(toOtelSpan) }],
          }],
        };
        const res = await fetch(this.opts.endpoint.replace(/\/$/, "") + "/v1/traces", {
          method: "POST",
          headers: { "content-type": "application/json", ...this.opts.headers },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) throw new Error(`OTLP export failed: ${res.status}`);
        this.queue.splice(0, batch.length);
        this.failures = 0;
      }
    } catch {
      this.failures++;
    } finally {
      this.flushing = false;
    }
  }

  get backoffActive(): boolean { return this.failures > 0; }

  async close(): Promise<void> {
    clearInterval(this.timer);
    await this.flush();
  }
}
