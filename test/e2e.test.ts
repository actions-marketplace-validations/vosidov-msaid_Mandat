// Control plane + Guard + MCP server over real HTTP.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane, createGuard, McpHttpServer, McpHttpClient, exchangeToken, devLogin, hashApiKey, scanRemote, protect, RemoteRevocations, type ControlPlane, type Guard } from "../src/index.ts";
import { STARTER_POLICY } from "../src/cli/templates.ts";
import { tools } from "../examples/refund-server/tools.ts";

const port = () => new Promise<number>((r) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => r(p)); }); });
const keys = { admin: "mdt_admin_test_key_000000000000", approver: "mdt_approver_test_key_0000000", service: "mdt_service_test_key_00000000" };

let cp: ControlPlane, mcp: McpHttpServer, guard: Guard, issuer: string, resource: string, secret: string;

const api = async (k: string, method: string, path: string, body?: unknown) => {
  const r = await fetch(issuer + path, { method, headers: { authorization: `Bearer ${k}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json() as any };
};

before(async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandat-e2e-"));
  const [cpPort, mcpPort] = [await port(), await port()];
  issuer = `http://127.0.0.1:${cpPort}`;
  resource = `http://127.0.0.1:${mcpPort}/mcp`;
  writeFileSync(join(dir, "policy.json"), JSON.stringify(STARTER_POLICY));
  cp = createControlPlane({
    issuer, port: cpPort, dataDir: join(dir, "data"), policyFile: join(dir, "policy.json"), devIdp: true,
    apiKeys: [
      { id: "admin", hash: hashApiKey(keys.admin), roles: ["admin"] },
      { id: "alice", hash: hashApiKey(keys.approver), roles: ["approver"] },
      { id: "svc", hash: hashApiKey(keys.service), roles: ["service"] },
    ],
    approvals: { log: false },
  });
  await cp.listen();
  const reg = await api(keys.admin, "POST", "/api/agents", { id: "support-bot", allowed_tools: ["lookup_*", "refund", "read_inbox", "send_email"], allowed_resources: [resource] });
  secret = reg.body.client_secret;
  guard = await createGuard({ resource, controlPlane: issuer, apiKey: keys.service, dataDir: join(dir, "guard"), approvalWaitMs: 5000, log: () => {} });
  mcp = new McpHttpServer({ name: "t", version: "1", guard, tools });
  await mcp.listen(mcpPort);
});

after(async () => {
  await mcp.close();
  await cp.close();
});

async function agentClient() {
  const id = await devLogin(issuer, { sub: "user:maria", email: "maria@acme.test" });
  const t = await exchangeToken({ mandatUrl: issuer, clientId: "support-bot", clientSecret: secret, subjectToken: id, resource });
  const c = new McpHttpClient(resource, t.access_token);
  await c.initialize();
  return c;
}

test("e2e: discovery metadata, role separation, scanner finds the server clean", async () => {
  const meta = await (await fetch(`${issuer}/.well-known/oauth-authorization-server`)).json();
  assert.deepEqual(meta.code_challenge_methods_supported, ["S256"]);
  assert.equal(meta.authorization_response_iss_parameter_supported, true);
  assert.equal((await api(keys.approver, "POST", "/api/revocations", { type: "agent", value: "x" })).status, 403);
  assert.equal((await api(keys.service, "GET", "/api/ledger")).status, 403);
  assert.equal((await api("mdt_nope", "GET", "/api/agents")).status, 401);
  const scan = await scanRemote(resource);
  assert.deepEqual(scan.findings.filter((f) => f.severity !== "info" && f.severity !== "low"), []);
});

test("e2e: allowed call, approval via API, denial — all in the central ledger", async () => {
  const c = await agentClient();
  const r1 = await c.callTool("refund", { order_id: "A-1001", amount: 10, currency: "EUR" });
  assert.equal(r1.isError, undefined);
  setTimeout(async () => {
    const { body } = await api(keys.approver, "GET", "/api/approvals?status=pending");
    await api(keys.approver, "POST", `/api/approvals/${body.approvals[0].id}/approve`, {});
  }, 300);
  const r2 = await c.callTool("refund", { order_id: "A-1002", amount: 100, currency: "EUR" });
  assert.equal(r2.isError, undefined, JSON.stringify(r2));
  const r3 = await c.callTool("refund", { order_id: "A-1003", amount: 1000, currency: "EUR" });
  assert.equal(r3.isError, true);
  assert.equal(r3._meta?.["mandat/decision"].rules[0], "refund-limit");

  await guard.opts.ledger.flush?.();
  const { body } = await api(keys.admin, "GET", "/api/ledger?type=agent.tool_call&tool=refund");
  assert.deepEqual(body.records.map((r: any) => r.decision.final).reverse(), ["allow", "allow", "deny"]);
  assert.equal(body.records[1].approval.approvers[0], "alice");
  assert.equal((await api(keys.admin, "GET", "/api/ledger/verify")).body.ok, true);
});

test("e2e: a guard with a key the control plane rejects fails loudly", async () => {
  // At startup: refuse to run instead of silently losing audit records.
  await assert.rejects(
    createGuard({ resource, controlPlane: issuer, apiKey: "mdt_key_from_another_instance_000", log: () => {} }),
    /rejected the API key \(HTTP 401\)/,
  );
  await assert.rejects(
    createGuard({ resource, controlPlane: issuer, apiKey: keys.approver, log: () => {} }),
    /lacks the "service" role/,
  );
  // At runtime (control plane replaced under a running guard): warn once, not on every poll.
  const warnings: string[] = [];
  const revs = new RemoteRevocations({ url: issuer, apiKey: "mdt_key_from_another_instance_000", log: (m) => warnings.push(m) });
  await revs.refresh();
  await revs.refresh();
  revs.close();
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /rejected this guard's API key \(HTTP 401\); revocations cannot be refreshed/);
});

test("e2e: ingest is idempotent (at-least-once delivery without duplicates)", async () => {
  const rec = { id: "rec_fixed_1", type: "agent.tool_call", tool: { name: "x" } };
  const a = await api(keys.service, "POST", "/api/ledger/ingest", { records: [rec] });
  const b = await api(keys.service, "POST", "/api/ledger/ingest", { records: [rec] });
  assert.equal(a.body.appended, 1);
  assert.equal(b.body.appended, 0);
});

test("e2e: `mandat bridge` serves a stdio MCP client (as Claude Code / Codex would launch it)", async () => {
  const reg = await api(keys.admin, "POST", "/api/agents", { id: "claude-code", allowed_tools: ["lookup_*", "refund", "read_inbox"], allowed_resources: [resource] });
  const child = spawn(process.execPath, ["bin/mandat.ts", "bridge", "--url", resource, "--mandat", issuer, "--agent", "claude-code", "--user", "user:dev"], {
    env: { ...process.env, MANDAT_AGENT_SECRET: reg.body.client_secret },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const responses = new Map<number, any>();
  let buf = "";
  child.stdout.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const m = JSON.parse(buf.slice(0, i));
      buf = buf.slice(i + 1);
      responses.set(m.id, m);
    }
  });
  const rpc = async (id: number, method: string, params: object = {}) => {
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    for (let t = 0; t < 100 && !responses.has(id); t++) await new Promise((r) => setTimeout(r, 50));
    return responses.get(id);
  };
  try {
    const init = await rpc(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
    assert.equal(init.result.serverInfo.name, "t");
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    assert.ok((await rpc(2, "tools/list")).result.tools.length >= 5);
    const ok = await rpc(3, "tools/call", { name: "lookup_order", arguments: { order_id: "A-1001" } });
    assert.equal(ok.result.isError, undefined);
    assert.equal(typeof ok.result.structuredContent, "object");
    // Regression: array results must not be sent as structuredContent (MCP requires an object; Claude Code rejects it).
    const inbox = await rpc(5, "tools/call", { name: "read_inbox", arguments: {} });
    assert.equal(inbox.result.structuredContent, undefined);
    assert.match(inbox.result.content[0].text, /Damaged parcel/);
    const denied = await rpc(4, "tools/call", { name: "send_email", arguments: { to: ["x@evil.test"], subject: "s", body: "b" } });
    assert.equal(denied.result.isError, true);
    assert.match(denied.result.content[0].text, /outside the task's delegated capability/);
  } finally {
    child.kill();
  }
});

test("e2e: kill switch revokes a live agent within 10 s (US-7)", async () => {
  const c = await agentClient();
  await c.callTool("lookup_order", { order_id: "A-1001" });
  const t0 = Date.now();
  assert.equal((await api(keys.admin, "POST", "/api/revocations", { type: "agent", value: "support-bot" })).status, 201);
  let elapsed = -1;
  while (Date.now() - t0 < 10_000) {
    try { await c.callTool("lookup_order", { order_id: "A-1001" }); } catch (e) { elapsed = Date.now() - t0; assert.equal((e as { status: number }).status, 401); break; }
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(elapsed >= 0 && elapsed < 10_000, `revocation took ${elapsed} ms`);
  await assert.rejects(agentClient(), /Issuance blocked/);
});

test("protect(): adapter wraps official-SDK-style registerTool callbacks", async () => {
  const registered: Record<string, (...a: unknown[]) => unknown> = {};
  const fakeSdk = { registerTool(name: string, _cfg: Record<string, unknown>, cb: (...a: unknown[]) => unknown) { registered[name] = cb; } };
  protect(fakeSdk, guard);
  fakeSdk.registerTool("refund", { description: "Refund" }, async (args: unknown) => ({ content: [{ type: "text", text: `refunded ${(args as { amount: number }).amount}` }] }));
  const r = (await registered.refund!({ amount: 5, currency: "EUR" }, { authInfo: { token: "garbage" } })) as any;
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /unauthenticated/);
});
