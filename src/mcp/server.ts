// Minimal MCP server (Streamable HTTP transport, JSON responses) with Mandat Guard on every tools/call.
// Implements what an authorization-aware MCP server must do:
//   - 401 + `WWW-Authenticate: Bearer resource_metadata=...` for missing/invalid tokens (incl. on tools/list)
//   - RFC 9728 Protected Resource Metadata at /.well-known/oauth-protected-resource[/path]
//   - audience-bound tokens only; the inbound token is never forwarded downstream
//   - Origin validation (DNS rebinding), loopback bind by default

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { AuthError, Guard, GuardDenied, type VerifiedAuth } from "../guard/guard.ts";
import type { ToolDefinition } from "../guard/pinning.ts";
import { bearerToken, randomId, readBody, sendJson } from "../util.ts";

export const SUPPORTED_PROTOCOL_VERSIONS = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];

export interface ToolContext { auth: VerifiedAuth; sessionId: string | null }

export interface CallToolResult {
  content: Array<{ type: "text"; text: string } | Record<string, unknown>>;
  structuredContent?: unknown;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

export interface ToolSpec extends ToolDefinition {
  handler: (args: Record<string, unknown>, ctx: ToolContext) => unknown | Promise<unknown>;
}

export interface McpServerOptions {
  name: string;
  version: string;
  guard: Guard;
  tools: ToolSpec[];
  instructions?: string;
  /** Allowed browser origins. Requests with any other Origin header are rejected (403). */
  allowedOrigins?: string[];
  /** Path of the MCP endpoint. Default "/mcp". */
  path?: string;
}

type JsonRpcRequest = { jsonrpc: "2.0"; id?: string | number | null; method: string; params?: Record<string, unknown> };

export class McpHttpServer {
  readonly opts: McpServerOptions;
  readonly path: string;
  private tools: Map<string, ToolSpec>;
  private sessions = new Set<string>();
  server: Server | null = null;

  constructor(opts: McpServerOptions) {
    this.opts = opts;
    this.path = opts.path ?? "/mcp";
    this.tools = new Map(opts.tools.map((t) => [t.name, t]));
    opts.guard.registerTools(opts.tools.map(({ handler: _h, ...def }) => def));
  }

  private get prmUrl(): string {
    const r = new URL(this.opts.guard.opts.resource);
    return `${r.origin}/.well-known/oauth-protected-resource${r.pathname === "/" ? "" : r.pathname}`;
  }

  handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (req.method === "GET" && url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
        return sendJson(res, 200, this.opts.guard.protectedResourceMetadata({ resource_name: this.opts.name }));
      }
      if (url.pathname !== this.path) return sendJson(res, 404, { error: "not_found" });

      const origin = req.headers.origin;
      if (origin && !(this.opts.allowedOrigins ?? []).includes(origin)) return sendJson(res, 403, { error: "forbidden_origin" });

      // Authenticate before anything else: tools/list is protected too.
      let auth: VerifiedAuth;
      try {
        auth = await this.opts.guard.verify(bearerToken(req));
      } catch (e) {
        const err = e instanceof AuthError ? e : new AuthError("invalid_token", "Unauthorized");
        const hadToken = Boolean(bearerToken(req));
        const challenge = `Bearer resource_metadata="${this.prmUrl}"` + (hadToken ? `, error="${err.code}", error_description="${headerSafe(err.message)}"` : "");
        return sendJson(res, err.status, { error: err.code, error_description: err.message }, { "www-authenticate": challenge });
      }

      if (req.method === "DELETE") {
        const sid = req.headers["mcp-session-id"];
        if (typeof sid === "string") this.sessions.delete(sid);
        res.writeHead(204).end();
        return;
      }
      if (req.method !== "POST") return sendJson(res, 405, { error: "method_not_allowed" }, { allow: "POST, DELETE" });

      let body: unknown;
      try { body = JSON.parse(await readBody(req)); } catch {
        return sendJson(res, 400, rpcError(null, -32700, "Parse error"));
      }
      const sessionHeader = req.headers["mcp-session-id"];
      let sessionId = typeof sessionHeader === "string" ? sessionHeader : null;
      const batch = Array.isArray(body) ? body : [body];
      const headers: Record<string, string> = {};
      const out: unknown[] = [];
      for (const msg of batch as JsonRpcRequest[]) {
        if (msg?.method === "initialize") {
          sessionId = randomId("mcp_");
          this.sessions.add(sessionId);
          headers["mcp-session-id"] = sessionId;
        }
        const r = await this.dispatch(msg, auth, sessionId);
        if (r !== undefined) out.push(r);
      }
      if (!out.length) { res.writeHead(202, headers).end(); return; }
      return sendJson(res, 200, Array.isArray(body) ? out : out[0], headers);
    } catch (e) {
      return sendJson(res, 500, rpcError(null, -32603, `Internal error: ${(e as Error).message}`));
    }
  };

  private async dispatch(msg: JsonRpcRequest, auth: VerifiedAuth, sessionId: string | null): Promise<unknown> {
    if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return rpcError(msg?.id ?? null, -32600, "Invalid Request");
    const isNotification = msg.id === undefined;
    if (isNotification) return undefined;
    const id = msg.id ?? null;
    switch (msg.method) {
      case "initialize": {
        const requested = String(msg.params?.protocolVersion ?? "");
        return rpcResult(id, {
          protocolVersion: SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : SUPPORTED_PROTOCOL_VERSIONS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: this.opts.name, version: this.opts.version },
          ...(this.opts.instructions ? { instructions: this.opts.instructions } : {}),
        });
      }
      case "ping":
        return rpcResult(id, {});
      case "tools/list":
        return rpcResult(id, { tools: [...this.tools.values()].map(({ handler: _h, ...def }) => def) });
      case "tools/call": {
        const name = String(msg.params?.name ?? "");
        const args = (msg.params?.arguments ?? {}) as Record<string, unknown>;
        const tool = this.tools.get(name);
        if (!tool) return rpcError(id, -32602, `Unknown tool: ${name}`);
        const invalid = validateArgs(tool.inputSchema, args);
        if (invalid) return rpcResult(id, { content: [{ type: "text", text: `Invalid arguments: ${invalid}` }], isError: true });
        try {
          const result = await this.opts.guard.execute({ auth, tool: name, args, sessionId }, () => tool.handler(args, { auth, sessionId }));
          return rpcResult(id, normalizeResult(result));
        } catch (e) {
          if (e instanceof GuardDenied) return rpcResult(id, deniedResult(e));
          return rpcResult(id, { content: [{ type: "text", text: `Tool error: ${(e as Error).message}` }], isError: true });
        }
      }
      default:
        return rpcError(id, -32601, `Method not found: ${msg.method}`);
    }
  }

  /** Binds to loopback by default; pass host "0.0.0.0" only behind a TLS-terminating proxy. */
  listen(port: number, host = "127.0.0.1"): Promise<Server> {
    this.server = createServer(this.handler);
    return new Promise((resolve) => this.server!.listen(port, host, () => resolve(this.server!)));
  }

  close(): Promise<void> {
    return new Promise((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }
}

/** MCP tool result shown to the model when Mandat blocks a call. */
export function deniedResult(e: GuardDenied): CallToolResult {
  const text = e.code === "approval_pending"
    ? `Mandat: this action needs human approval. ${e.message}`
    : `Mandat blocked this action: ${e.message}`;
  return {
    content: [{ type: "text", text }],
    isError: true,
    _meta: {
      "mandat/decision": {
        code: e.code,
        effect: e.decision?.effect ?? "deny",
        rules: e.decision?.matched ?? [],
        approval_id: e.approvalId ?? null,
        record_id: e.record ? e.record.id : null,
      },
    },
  };
}

function normalizeResult(r: unknown): CallToolResult {
  if (typeof r === "string") return { content: [{ type: "text", text: r }] };
  if (r && typeof r === "object" && Array.isArray((r as CallToolResult).content)) return r as CallToolResult;
  // MCP requires structuredContent to be a JSON object, so arrays and primitives are sent as text only.
  const isObject = r !== null && typeof r === "object" && !Array.isArray(r);
  return { content: [{ type: "text", text: JSON.stringify(r) }], ...(isObject ? { structuredContent: r } : {}) };
}

/** Header values must be visible ASCII; quotes would break the auth-param syntax. */
function headerSafe(s: string): string {
  return s.replace(/[\u2013\u2014]/g, "-").replace(/[^\x20-\x7e]/g, "").replace(/["\\]/g, "'").slice(0, 300);
}

function rpcResult(id: unknown, result: unknown) { return { jsonrpc: "2.0", id, result }; }
function rpcError(id: unknown, code: number, message: string) { return { jsonrpc: "2.0", id, error: { code, message } }; }

/** Small JSON Schema subset check: object, required, primitive types, enum, minimum/maximum. */
export function validateArgs(schema: unknown, args: unknown): string | null {
  const s = schema as { type?: string; properties?: Record<string, any>; required?: string[]; additionalProperties?: boolean } | undefined;
  if (!s || s.type !== "object") return null;
  if (!args || typeof args !== "object" || Array.isArray(args)) return "arguments must be an object";
  const a = args as Record<string, unknown>;
  for (const k of s.required ?? []) if (a[k] === undefined) return `missing required '${k}'`;
  for (const [k, v] of Object.entries(a)) {
    const p = s.properties?.[k];
    if (!p) { if (s.additionalProperties === false) return `unexpected property '${k}'`; continue; }
    const t = p.type as string | undefined;
    const ok = !t
      || (t === "integer" ? Number.isInteger(v) : t === "number" ? typeof v === "number" && Number.isFinite(v)
        : t === "array" ? Array.isArray(v) : t === "object" ? v !== null && typeof v === "object" && !Array.isArray(v) : typeof v === t);
    if (!ok) return `'${k}' must be ${t}`;
    if (p.enum && !p.enum.includes(v)) return `'${k}' must be one of ${JSON.stringify(p.enum)}`;
    if (typeof v === "number" && p.minimum !== undefined && v < p.minimum) return `'${k}' must be >= ${p.minimum}`;
    if (typeof v === "number" && p.maximum !== undefined && v > p.maximum) return `'${k}' must be <= ${p.maximum}`;
    if (t === "array" && p.items?.type === "string" && (v as unknown[]).some((x) => typeof x !== "string")) return `'${k}' must be an array of strings`;
  }
  return null;
}
