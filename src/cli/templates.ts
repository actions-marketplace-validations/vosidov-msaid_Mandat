// Files written by `mandat init`.

import type { PolicyDocument } from "../policy/engine.ts";

export const STARTER_POLICY: PolicyDocument = {
  version: 1,
  default: "deny",
  tools: {
    "lookup_*": { risk: "read" },
    "list_*": { risk: "read" },
    "get_*": { risk: "read" },
    "read_inbox": { risk: "read", taints: true, description: "Returns untrusted e-mail content: taints the session" },
    "fetch_url": { risk: "read", taints: true },
    "send_email": { risk: "external_comm", redact: ["body"] },
    "refund": { risk: "financial" },
    "delete_*": { risk: "destructive" },
  },
  rules: [
    { id: "reads", description: "Read-only tools are allowed", tool: ["lookup_*", "list_*", "get_*", "read_inbox", "fetch_url"], effect: "allow" },

    { id: "refund-auto", description: "Small refunds are automatic", tool: "refund", when: "args.amount <= 50 && args.currency == 'EUR'", effect: "allow" },
    { id: "refund-approval", description: "€50–500 needs a human", tool: "refund", when: "args.amount > 50 && args.amount <= 500 && args.currency == 'EUR'", effect: "require_approval", approval: { approvers: 1, timeout: "15m" } },
    { id: "refund-limit", tool: "refund", when: "args.amount > 500 || args.currency != 'EUR'", effect: "deny", reason: "Refunds above €500 (or not in EUR) must be done by finance, not by an agent" },

    { id: "email-internal", tool: "send_email", when: "args.to.all(r, r.endsWith('@example.com'))", effect: "allow_with_obligations", obligations: [{ type: "annotate", tags: ["internal-email"] }] },
    { id: "email-external", tool: "send_email", when: "!args.to.all(r, r.endsWith('@example.com'))", effect: "require_approval", reason: "External recipients need approval" },
    { id: "no-exfil-after-untrusted", description: "Lethal trifecta guard: after reading untrusted content, never write to external channels", tool: "send_email", when: "session.tainted && !args.to.all(r, r.endsWith('@example.com'))", effect: "deny", reason: "Session processed untrusted content; external e-mail is blocked (possible prompt injection)" },

    { id: "destructive-four-eyes", description: "Deletes need two humans", tool: "delete_*", effect: "require_approval", approval: { approvers: 2, timeout: "30m" } },
    { id: "no-prod-delete-at-night", tool: "delete_*", when: "has(args.environment) && args.environment == 'production' && (env.hour_utc < 6 || env.hour_utc >= 22)", effect: "deny", reason: "No destructive production changes outside working hours" },
  ],
};

export const STARTER_TESTS = [
  { name: "small refund is automatic", input: { tool: "refund", args: { amount: 20, currency: "EUR", order_id: "A1" } }, expect: "allow" },
  { name: "medium refund needs approval", input: { tool: "refund", args: { amount: 120, currency: "EUR", order_id: "A1" } }, expect: "require_approval" },
  { name: "large refund is denied", input: { tool: "refund", args: { amount: 900, currency: "EUR", order_id: "A1" } }, expect: "deny" },
  { name: "internal e-mail allowed", input: { tool: "send_email", args: { to: ["ops@example.com"], subject: "hi", body: "x" } }, expect: "allow*" },
  { name: "external e-mail after untrusted input is denied", input: { tool: "send_email", args: { to: ["x@evil.test"], subject: "hi", body: "x" }, session: { tainted: true } }, expect: "deny" },
  { name: "unknown tool is denied by default", input: { tool: "drop_database", args: {} }, expect: "deny" },
  { name: "capability from task token is enforced", input: { tool: "refund", args: { amount: 10, currency: "EUR" }, task: { authorization_details: [{ type: "mandat_tool_call", tools: ["lookup_order"] }] } }, expect: "deny" },
];

export function readmeSnippet(resource: string, url: string): string {
  return `
Protect an MCP server built with the official TypeScript SDK:

  import { createGuard, protect } from "mandat";
  import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
  import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

  const guard = await createGuard({
    resource: "${resource}",
    controlPlane: "${url}",
    apiKey: process.env.MANDAT_SERVICE_KEY,
    pinning: { lockfile: "mandat.lock.json", mode: "block" },
  });
  const server = protect(new McpServer({ name: "my-server", version: "1.0.0" }), guard);
  app.get("/.well-known/oauth-protected-resource/mcp", (_q, r) => r.json(guard.protectedResourceMetadata()));
  app.use("/mcp", requireBearerAuth({ verifier: guard.sdkTokenVerifier({ InvalidTokenError }),
    resourceMetadataUrl: "${new URL(resource).origin}/.well-known/oauth-protected-resource/mcp" }));

Or with the built-in zero-dependency server:  new McpHttpServer({ name, version, guard, tools }).listen(7401)
`;
}
