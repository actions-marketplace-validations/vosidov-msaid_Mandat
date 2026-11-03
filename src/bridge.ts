// stdio <-> Streamable HTTP bridge that lets any stdio MCP client (Claude Code, Codex, Cursor, Claude Desktop)
// talk to a Mandat-protected MCP server. It acts as the agent: it holds the agent credentials, exchanges the
// user's token for short-lived task tokens (RFC 8693) and transparently re-exchanges before they expire.
//
// stdout carries only MCP JSON-RPC messages (one per line); diagnostics go to stderr.

import { createInterface } from "node:readline";
import { decodeJwt } from "./sts/jwt.ts";
import { devLogin, exchangeToken } from "./client.ts";
import type { AuthorizationDetail } from "./policy/engine.ts";
import { randomId } from "./util.ts";

export interface BridgeOptions {
  /** Protected MCP server URL. */
  url: string;
  /** Mandat control plane URL. */
  mandatUrl: string;
  agentId: string;
  agentSecret: string;
  agentVersion?: string;
  /** User token from a real IdP. If absent, the dev IdP is used with `user`. */
  subjectToken?: string;
  user?: { sub: string; email?: string; tenant?: string };
  tools?: string[];
  log?: (msg: string) => void;
}

export class Bridge {
  private o: BridgeOptions;
  private token: { value: string; exp: number } | null = null;
  private refreshing: Promise<string> | null = null;
  private mcpSessionId: string | null = null;
  private sessionId = randomId("sess_");
  private log: (m: string) => void;

  constructor(o: BridgeOptions) {
    this.o = o;
    this.log = o.log ?? ((m) => process.stderr.write(`[mandat-bridge] ${m}\n`));
  }

  /** Returns a valid task token, exchanging a new one when the current one expires within 30 s. */
  async taskToken(force = false): Promise<string> {
    if (!force && this.token && this.token.exp - Date.now() / 1000 > 30) return this.token.value;
    this.refreshing ??= (async () => {
      const subject = this.o.subjectToken ?? (await devLogin(this.o.mandatUrl, this.o.user ?? { sub: "user:local" }));
      const details: AuthorizationDetail[] | undefined = this.o.tools?.length ? [{ type: "mandat_tool_call", tools: this.o.tools }] : undefined;
      const t = await exchangeToken({
        mandatUrl: this.o.mandatUrl,
        clientId: this.o.agentId,
        clientSecret: this.o.agentSecret,
        subjectToken: subject,
        resource: this.o.url,
        agentVersion: this.o.agentVersion,
        authorizationDetails: details,
        sessionId: this.sessionId,
      });
      const exp = decodeJwt(t.access_token).payload.exp as number;
      this.token = { value: t.access_token, exp };
      this.log(`new task token for ${this.o.agentId}, valid ${t.expires_in}s`);
      return t.access_token;
    })().finally(() => { this.refreshing = null; });
    return this.refreshing;
  }

  /** Forwards one JSON-RPC message; returns the response message (or null for notifications). */
  async forward(msg: { id?: unknown; method?: string }): Promise<unknown> {
    const send = async (token: string) =>
      fetch(this.o.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
          ...(this.mcpSessionId ? { "mcp-session-id": this.mcpSessionId } : {}),
        },
        body: JSON.stringify(msg),
      });
    try {
      let res = await send(await this.taskToken());
      if (res.status === 401) {
        // Expired or revoked: try once with a fresh token (a revoked agent fails at the exchange).
        res = await send(await this.taskToken(true));
      }
      const sid = res.headers.get("mcp-session-id");
      if (sid) this.mcpSessionId = sid;
      if (res.status === 202 || msg.id === undefined) return null;
      const text = await res.text();
      if (!res.ok) {
        let detail = text;
        try { detail = JSON.parse(text).error_description ?? text; } catch { /* keep raw */ }
        return rpcError(msg.id, `Mandat: HTTP ${res.status}: ${detail}`);
      }
      return parseBody(text, res.headers.get("content-type") ?? "");
    } catch (e) {
      this.log((e as Error).message);
      return msg.id === undefined ? null : rpcError(msg.id, `Mandat bridge: ${(e as Error).message}`);
    }
  }

  /** Runs the stdio loop until stdin closes. Requests are handled concurrently (approvals can block). */
  run(input: NodeJS.ReadableStream = process.stdin, output: NodeJS.WritableStream = process.stdout): Promise<void> {
    const rl = createInterface({ input, crlfDelay: Infinity });
    const pending = new Set<Promise<void>>();
    rl.on("line", (line) => {
      if (!line.trim()) return;
      let msg: { id?: unknown; method?: string };
      try { msg = JSON.parse(line); } catch {
        output.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }) + "\n");
        return;
      }
      const p = this.forward(msg).then((r) => { if (r) output.write(JSON.stringify(r) + "\n"); });
      pending.add(p);
      void p.finally(() => pending.delete(p));
    });
    return new Promise((resolve) => rl.on("close", () => void Promise.allSettled([...pending]).then(() => resolve())));
  }
}

function rpcError(id: unknown, message: string) {
  return { jsonrpc: "2.0", id, error: { code: -32001, message } };
}

function parseBody(text: string, contentType: string): unknown {
  if (contentType.includes("text/event-stream")) {
    const data = text.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).filter(Boolean);
    return data.length ? JSON.parse(data[data.length - 1]!) : null;
  }
  return text ? JSON.parse(text) : null;
}
