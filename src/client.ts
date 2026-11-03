// Agent-side helpers: obtain a per-task token (RFC 8693) and call an MCP server over Streamable HTTP.

import { GRANT_TOKEN_EXCHANGE, TT_ID_TOKEN } from "./sts/sts.ts";
import type { AuthorizationDetail } from "./policy/engine.ts";
import { sha256 } from "./util.ts";

export interface ExchangeOptions {
  /** Mandat control plane base URL. */
  mandatUrl: string;
  clientId: string;
  clientSecret: string;
  /** The user's token from the IdP (ID token / access token), or a parent Mandat token for sub-agents. */
  subjectToken: string;
  subjectTokenType?: string;
  /** MCP server URL the token is for (RFC 8707). */
  resource: string;
  /** Narrow the capability: tools (and optional limits) for this task only. */
  authorizationDetails?: AuthorizationDetail[];
  agentVersion?: string;
  /** System prompt (hashed client-side; only the hash is sent and logged). */
  systemPrompt?: string;
  taskId?: string;
  sessionId?: string;
  expiresIn?: number;
}

export interface TaskToken { access_token: string; expires_in: number; authorization_details: AuthorizationDetail[] }

export async function exchangeToken(o: ExchangeOptions): Promise<TaskToken> {
  const form = new URLSearchParams({
    grant_type: GRANT_TOKEN_EXCHANGE,
    subject_token: o.subjectToken,
    subject_token_type: o.subjectTokenType ?? TT_ID_TOKEN,
    resource: o.resource,
  });
  if (o.authorizationDetails) form.set("authorization_details", JSON.stringify(o.authorizationDetails));
  if (o.agentVersion) form.set("mandat_agent_version", o.agentVersion);
  if (o.systemPrompt) form.set("mandat_prompt_hash", "sha256:" + sha256(o.systemPrompt).slice(0, 32));
  if (o.taskId) form.set("mandat_task_id", o.taskId);
  if (o.sessionId) form.set("mandat_session_id", o.sessionId);
  if (o.expiresIn) form.set("expires_in", String(o.expiresIn));
  const res = await fetch(`${o.mandatUrl.replace(/\/$/, "")}/oauth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: "Basic " + Buffer.from(`${encodeURIComponent(o.clientId)}:${encodeURIComponent(o.clientSecret)}`).toString("base64"),
    },
    body: form,
  });
  const body = (await res.json()) as TaskToken & { error?: string; error_description?: string };
  if (!res.ok) throw new Error(`Token exchange failed: ${body.error}: ${body.error_description}`);
  return body;
}

/** Dev IdP login (only when the control plane runs with `devIdp: true`). */
export async function devLogin(mandatUrl: string, user: { sub: string; email?: string; tenant?: string }): Promise<string> {
  const res = await fetch(`${mandatUrl.replace(/\/$/, "")}/dev/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(user) });
  if (!res.ok) throw new Error(`dev login failed: ${res.status}`);
  return ((await res.json()) as { id_token: string }).id_token;
}

export class McpHttpClient {
  private url: string;
  token: string;
  private sessionId: string | null = null;
  private id = 0;

  constructor(url: string, token: string) {
    this.url = url;
    this.token = token;
  }

  async request(method: string, params: Record<string, unknown> = {}): Promise<any> {
    const res = await fetch(this.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${this.token}`,
        "mcp-protocol-version": "2026-07-28",
        ...(this.sessionId ? { "mcp-session-id": this.sessionId } : {}),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++this.id, method, params }),
    });
    if (res.status === 401 || res.status === 403) {
      const body = (await res.json().catch(() => ({}))) as { error_description?: string };
      const err = new Error(`HTTP ${res.status}: ${body.error_description ?? "unauthorized"}`) as Error & { status: number; challenge: string | null };
      err.status = res.status;
      err.challenge = res.headers.get("www-authenticate");
      throw err;
    }
    const sid = res.headers.get("mcp-session-id");
    if (sid) this.sessionId = sid;
    const msg = (await res.json()) as { result?: unknown; error?: { message: string } };
    if (msg.error) throw new Error(`MCP error: ${msg.error.message}`);
    return msg.result;
  }

  initialize() {
    return this.request("initialize", { protocolVersion: "2026-07-28", capabilities: {}, clientInfo: { name: "mandat-client", version: "0.1.0" } });
  }

  async listTools(): Promise<Array<{ name: string; description?: string }>> {
    return (await this.request("tools/list")).tools;
  }

  callTool(name: string, args: Record<string, unknown>): Promise<{ content: Array<{ type: string; text?: string }>; isError?: boolean; _meta?: Record<string, any>; structuredContent?: unknown }> {
    return this.request("tools/call", { name, arguments: args });
  }
}
