// An MCP server built the standard way with the official TypeScript SDK (@modelcontextprotocol/sdk),
// protected by Mandat. The only Mandat-specific lines are marked "← Mandat".

import { randomUUID } from "node:crypto";
import type { Server } from "node:http";
import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { protect, type Guard, type VerifiedAuth } from "../../src/index.ts";

const orders: Record<string, { email: string; total: number; refunded: number }> = {
  "A-1001": { email: "jonas.weber@example.org", total: 45, refunded: 0 },
  "A-1002": { email: "lea.martin@example.org", total: 180, refunded: 0 },
  "A-1003": { email: "sam.okafor@example.org", total: 1290, refunded: 0 },
};

const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });

/** Who the call is for, as verified by Mandat (attached to the SDK's AuthInfo by guard.sdkTokenVerifier). */
const actingFor = (extra: { authInfo?: { extra?: Record<string, unknown> } }) => {
  const auth = extra.authInfo?.extra?.mandat as VerifiedAuth | undefined;
  return auth ? `${auth.agent.id} for ${auth.principal.email ?? auth.principal.sub}` : "unknown";
};

/** One McpServer per session, as in the SDK's own examples. */
function buildServer(guard: Guard): McpServer {
  const server = protect(new McpServer({ name: "acme-support-sdk", version: "1.0.0" }), guard); // ← Mandat: policy + audit on every tool

  server.registerTool("lookup_order", {
    description: "Look up an order by id.",
    inputSchema: { order_id: z.string() },
    annotations: { readOnlyHint: true },
  }, async ({ order_id }) => {
    const o = orders[order_id];
    return o ? text(JSON.stringify({ order_id, ...o })) : { ...text(`Order ${order_id} not found`), isError: true };
  });

  server.registerTool("refund", {
    description: "Refund (part of) an order.",
    inputSchema: { order_id: z.string(), amount: z.number().positive(), currency: z.enum(["EUR", "USD"]) },
  }, async ({ order_id, amount, currency }, extra) => {
    const o = orders[order_id];
    if (!o) return { ...text(`Order ${order_id} not found`), isError: true };
    o.refunded += amount;
    return text(`Refunded ${amount} ${currency} on ${order_id} (${actingFor(extra)}).`);
  });

  server.registerTool("send_email", {
    description: "Send an e-mail from the support mailbox.",
    inputSchema: { to: z.array(z.string()), subject: z.string(), body: z.string() },
    annotations: { openWorldHint: true },
  }, async ({ to, subject }) => text(`Sent "${subject}" to ${to.join(", ")}.`));

  return server;
}

export interface SdkServerOptions { guard: Guard; port: number; host?: string }

/** Starts the express app. Resolves with the HTTP server once it listens. */
export function startSdkServer({ guard, port, host = "127.0.0.1" }: SdkServerOptions): Promise<Server> {
  const resource = new URL(guard.opts.resource);
  const prmPath = `/.well-known/oauth-protected-resource${resource.pathname}`;
  const app = express();
  app.use(express.json());

  // RFC 9728 metadata so MCP clients can discover the authorization server.  ← Mandat
  app.get(prmPath, (_req, res) => { res.json(guard.protectedResourceMetadata({ resource_name: "Acme Support (official MCP SDK)" })); });

  // The SDK's own bearer middleware, with Mandat verifying the per-task token.  ← Mandat
  const auth = requireBearerAuth({
    verifier: guard.sdkTokenVerifier({ InvalidTokenError }),
    resourceMetadataUrl: `${resource.origin}${prmPath}`,
    expectedResource: resource,
  });

  const transports = new Map<string, StreamableHTTPServerTransport>();
  app.post(resource.pathname, auth, async (req, res) => {
    const sid = req.headers["mcp-session-id"];
    let transport = typeof sid === "string" ? transports.get(sid) : undefined;
    if (!transport) {
      if (sid || !isInitializeRequest(req.body)) {
        res.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "Unknown or missing session" }, id: null });
        return;
      }
      const t: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => { transports.set(id, t); },
      });
      t.onclose = () => { if (t.sessionId) transports.delete(t.sessionId); };
      await buildServer(guard).connect(t);
      transport = t;
    }
    await transport.handleRequest(req, res, req.body);
  });
  const sessionRequest = async (req: express.Request, res: express.Response) => {
    const sid = req.headers["mcp-session-id"];
    const transport = typeof sid === "string" ? transports.get(sid) : undefined;
    if (!transport) { res.status(400).send("Unknown or missing session"); return; }
    await transport.handleRequest(req, res);
  };
  app.get(resource.pathname, auth, sessionRequest);
  app.delete(resource.pathname, auth, sessionRequest);

  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, (err?: Error) => (err ? reject(err) : resolve(server)));
  });
}
