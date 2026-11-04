// US-2: Mandat protects a server built with the official MCP TypeScript SDK, exercised by the SDK's own client.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server as NetServer } from "node:net";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createControlPlane, createGuard, exchangeToken, devLogin, hashApiKey, type ControlPlane, type Guard } from "../src/index.ts";
import { STARTER_POLICY } from "../src/cli/templates.ts";
import { startSdkServer } from "../examples/sdk-server/app.ts";

const freePort = () => new Promise<number>((r) => { const s: NetServer = createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => r(p)); }); });
const keys = { admin: "mdt_admin_sdk_test_000000000000", service: "mdt_service_sdk_test_0000000000" };

let cp: ControlPlane, guard: Guard, http: Server, issuer: string, resource: string, secret: string;

before(async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandat-sdk-"));
  const [cpPort, mcpPort] = [await freePort(), await freePort()];
  issuer = `http://127.0.0.1:${cpPort}`;
  resource = `http://127.0.0.1:${mcpPort}/mcp`;
  writeFileSync(join(dir, "policy.json"), JSON.stringify(STARTER_POLICY));
  cp = createControlPlane({
    issuer, port: cpPort, dataDir: join(dir, "data"), policyFile: join(dir, "policy.json"), devIdp: true,
    apiKeys: [{ id: "admin", hash: hashApiKey(keys.admin), roles: ["admin", "approver", "auditor"] }, { id: "svc", hash: hashApiKey(keys.service), roles: ["service"] }],
    approvals: { log: false },
  });
  await cp.listen();
  const reg = await (await fetch(`${issuer}/api/agents`, {
    method: "POST", headers: { authorization: `Bearer ${keys.admin}`, "content-type": "application/json" },
    body: JSON.stringify({ id: "sdk-agent", allowed_tools: ["lookup_*", "refund", "send_email"], allowed_resources: [resource] }),
  })).json();
  secret = reg.client_secret;
  guard = await createGuard({ resource, controlPlane: issuer, apiKey: keys.service, dataDir: join(dir, "g"), approvalWaitMs: 5000, log: () => {} });
  http = await startSdkServer({ guard, port: mcpPort });
});
after(async () => {
  await new Promise<void>((r) => { http.close(() => r()); http.closeAllConnections(); });
  await cp.close();
});

async function sdkClient(token: string): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(resource), { requestInit: { headers: { Authorization: `Bearer ${token}` } } });
  const client = new Client({ name: "mandat-sdk-test", version: "1.0.0" });
  await client.connect(transport);
  return client;
}
async function taskToken(): Promise<string> {
  const id = await devLogin(issuer, { sub: "user:maria", email: "maria@acme.example" });
  return (await exchangeToken({ mandatUrl: issuer, clientId: "sdk-agent", clientSecret: secret, subjectToken: id, resource })).access_token;
}
const textOf = (r: unknown) => ((r as { content: Array<{ text?: string }> }).content ?? []).map((c) => c.text).join(" ");

test("SDK server: unauthenticated and invalid-token requests get 401 with a resource_metadata challenge", async () => {
  const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "x", version: "1" } } };
  const anon = await fetch(resource, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify(init) });
  assert.equal(anon.status, 401);
  assert.match(anon.headers.get("www-authenticate") ?? "", /resource_metadata="http:\/\/127\.0\.0\.1:\d+\/\.well-known\/oauth-protected-resource\/mcp"/);
  const prm = await (await fetch(new URL("/.well-known/oauth-protected-resource/mcp", resource))).json();
  assert.equal(prm.resource, resource);
  assert.deepEqual(prm.authorization_servers, [issuer]);
  await assert.rejects(sdkClient("not-a-token"));
});

test("SDK server: policy runs on every tool call made through the official SDK client", async () => {
  const client = await sdkClient(await taskToken());
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), ["lookup_order", "refund", "send_email"]);

  const ok = await client.callTool({ name: "refund", arguments: { order_id: "A-1001", amount: 20, currency: "EUR" } });
  assert.equal(ok.isError, undefined);
  assert.match(textOf(ok), /Refunded 20 EUR on A-1001 \(sdk-agent for maria@acme\.example\)/);

  const denied = await client.callTool({ name: "refund", arguments: { order_id: "A-1003", amount: 900, currency: "EUR" } });
  assert.equal(denied.isError, true);
  assert.match(textOf(denied), /Mandat blocked this action/);
  assert.equal((denied._meta as any)["mandat/decision"].rules[0], "refund-limit");

  // Mid-size refund: waits for a human, then runs.
  setTimeout(async () => {
    const list = await (await fetch(`${issuer}/api/approvals?status=pending`, { headers: { authorization: `Bearer ${keys.admin}` } })).json();
    await fetch(`${issuer}/api/approvals/${list.approvals[0].id}/approve`, { method: "POST", headers: { authorization: `Bearer ${keys.admin}`, "content-type": "application/json" }, body: "{}" });
  }, 300);
  const approved = await client.callTool({ name: "refund", arguments: { order_id: "A-1002", amount: 120, currency: "EUR" } });
  assert.equal(approved.isError, undefined, textOf(approved));
  await client.close();

  await guard.opts.ledger.flush?.();
  const { records } = await (await fetch(`${issuer}/api/ledger?type=agent.tool_call&tool=refund`, { headers: { authorization: `Bearer ${keys.admin}` } })).json();
  assert.deepEqual(records.map((r: any) => r.decision.final).reverse(), ["allow", "deny", "allow"]);
  assert.equal(records[0].principal.sub, "user:maria");
  assert.deepEqual(records[0].actor_chain, ["sdk-agent"]);
  assert.ok(records[0].tool.definition_hash, "tools registered through protect() are pinned");
});

test("SDK server: a revoked agent is locked out within seconds", async () => {
  const client = await sdkClient(await taskToken());
  await client.callTool({ name: "lookup_order", arguments: { order_id: "A-1001" } });
  await fetch(`${issuer}/api/revocations`, { method: "POST", headers: { authorization: `Bearer ${keys.admin}`, "content-type": "application/json" }, body: JSON.stringify({ type: "agent", value: "sdk-agent" }) });
  const t0 = Date.now();
  let locked = false;
  while (Date.now() - t0 < 10_000) {
    try { await client.callTool({ name: "lookup_order", arguments: { order_id: "A-1001" } }); } catch { locked = true; break; }
    await new Promise((r) => setTimeout(r, 200));
  }
  assert.ok(locked, "revoked agent still served after 10 s");
});
