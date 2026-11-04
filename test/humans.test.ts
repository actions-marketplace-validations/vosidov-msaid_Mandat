// People sign in with the IdP (console + CLI), roles come from explicit grants, every refused
// login is audited, and agent secrets can be rotated or removed.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startFakeIdp, type FakeIdp } from "./fake-idp.ts";
import { createControlPlane, createGuard, McpHttpServer, McpHttpClient, exchangeToken, devLogin, hashApiKey, signJwt, buildReport, type ControlPlane, type Guard } from "../src/index.ts";
import { STARTER_POLICY } from "../src/cli/templates.ts";
import { tools } from "../examples/refund-server/tools.ts";
import { main } from "../src/cli/main.ts";
import { nowSeconds } from "../src/util.ts";

const freePort = () => new Promise<number>((r) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => r(p)); }); });
const keys = { admin: "mdt_admin_humans_test_00000000", service: "mdt_service_humans_test_000000" };

let idp: FakeIdp, cp: ControlPlane, guard: Guard, mcp: McpHttpServer, issuer: string, resource: string;

before(async () => {
  idp = await startFakeIdp();
  const dir = mkdtempSync(join(tmpdir(), "mandat-humans-"));
  const [cpPort, mcpPort] = [await freePort(), await freePort()];
  issuer = `http://127.0.0.1:${cpPort}`;
  resource = `http://127.0.0.1:${mcpPort}/mcp`;
  writeFileSync(join(dir, "policy.json"), JSON.stringify(STARTER_POLICY));
  cp = createControlPlane({
    issuer, port: cpPort, dataDir: join(dir, "data"), policyFile: join(dir, "policy.json"),
    devIdp: true, // on purpose: dev tokens must never work as a human's credential
    trustedIssuers: [{ issuer: idp.issuer, jwks_uri: `${idp.issuer}.well-known/jwks.json`, audience: idp.clientId }],
    apiKeys: [{ id: "admin", hash: hashApiKey(keys.admin), roles: ["admin", "auditor"] }, { id: "svc", hash: hashApiKey(keys.service), roles: ["service"] }],
    approvals: { log: false },
  });
  await cp.listen();
  guard = await createGuard({ resource, controlPlane: issuer, apiKey: keys.service, dataDir: join(dir, "g"), log: () => {} });
  mcp = new McpHttpServer({ name: "acme", version: "1", guard, tools });
  await mcp.listen(mcpPort);
});
after(async () => { await mcp.close(); await cp.close(); await idp.close(); });

const call = async (method: string, path: string, opts: { key?: string; cookie?: string; csrf?: boolean; body?: unknown } = {}) => {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.key) headers.authorization = `Bearer ${opts.key}`;
  if (opts.cookie) headers.cookie = opts.cookie;
  if (opts.csrf) headers["x-requested-with"] = "mandat";
  const r = await fetch(issuer + path, { method, headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
  return { status: r.status, body: (await r.json().catch(() => ({}))) as any };
};
const admin = (method: string, path: string, body?: unknown) => call(method, path, { key: keys.admin, body });
const idToken = (sub: string, email: string, aud = idp.clientId) => {
  const now = nowSeconds();
  return signJwt({ iss: idp.issuer, aud, sub, email, email_verified: true, iat: now, exp: now + 600 }, idp.key);
};
const ledger = async (type: string) => (await admin("GET", `/api/ledger?type=${encodeURIComponent(type)}&limit=1000`)).body.records as any[];

test("console sign-in: IdP login sets a session; access requires an explicit role grant", async () => {
  const start = await fetch(`${issuer}/auth/login`, { redirect: "manual" });
  assert.equal(start.status, 302);
  const toIdp = start.headers.get("location")!;
  assert.ok(toIdp.startsWith(`${idp.issuer}authorize`));
  assert.equal(new URL(toIdp).searchParams.get("redirect_uri"), `${issuer}/auth/callback`);
  const back = await fetch(toIdp, { redirect: "manual" });
  const callback = await fetch(back.headers.get("location")!);
  assert.equal(callback.status, 200);
  const cookie = callback.headers.get("set-cookie")!.split(";")[0]!;
  assert.match(callback.headers.get("set-cookie")!, /HttpOnly; SameSite=Strict/);

  const denied = await call("GET", "/api/whoami", { cookie });
  assert.equal(denied.status, 403);
  assert.match(denied.body.error_description, /no role is granted.*mandat users grant --email maria@acme.example/);

  assert.equal((await admin("POST", "/api/users", { email: "Maria@Acme.example", roles: ["approver"] })).status, 200);
  const me = await call("GET", "/api/whoami", { cookie });
  assert.equal(me.status, 200);
  assert.deepEqual([me.body.id, me.body.via, me.body.email, me.body.roles], ["maria@acme.example", "session", "maria@acme.example", ["approver"]]);

  // Cookie-authenticated writes need the same-origin header (CSRF defence).
  assert.equal((await call("POST", "/api/approvals/apr_x/approve", { cookie, body: {} })).body.error, "csrf");
  assert.equal((await call("POST", "/api/approvals/apr_x/approve", { cookie, csrf: true, body: {} })).status, 404);

  await fetch(`${issuer}/auth/logout`, { method: "POST", headers: { cookie, "x-requested-with": "mandat" } });
  assert.equal((await call("GET", "/api/whoami", { cookie })).status, 401);
});

test("CLI sign-in: IdP ID token as bearer; wrong audience and dev-IdP tokens are refused", async () => {
  await admin("POST", "/api/users", { sub: "auth0|alice", roles: ["approver"] });
  assert.equal((await call("GET", "/api/approvals", { key: idToken("auth0|alice", "alice@acme.example") })).status, 200);
  assert.equal((await call("GET", "/api/approvals", { key: idToken("auth0|alice", "alice@acme.example", "another-app") })).status, 401);
  const forged = await devLogin(issuer, { sub: "auth0|alice", email: "alice@acme.example" });
  assert.equal((await call("GET", "/api/approvals", { key: forged })).status, 401, "anyone can mint dev tokens: never a human credential");
  assert.ok((await ledger("api.auth_rejected")).some((r) => r.details.code === "invalid_id_token"));
});

test("approvals: a person cannot approve their own agent's action, whatever sign-in they use", async () => {
  const created = await call("POST", "/api/approvals", {
    key: keys.service,
    body: { binding: "b-self", required: 1, timeoutMs: 60_000, channels: [], context: { tool: "refund", args: { amount: 120 }, principal: { sub: "auth0|maria", email: "maria@acme.example" }, agent: { id: "claude-code" }, rule: "refund-approval", reasons: [] } },
  });
  const id = created.body.id;
  const self = await call("POST", `/api/approvals/${id}/approve`, { key: idToken("auth0|maria", "maria@acme.example"), body: {} });
  assert.equal(self.status, 403);
  assert.match(self.body.error_description, /Self-approval/);
  const ok = await call("POST", `/api/approvals/${id}/approve`, { key: idToken("auth0|alice", "alice@acme.example"), body: {} });
  assert.equal(ok.body.status, "approved");
  assert.deepEqual([ok.body.votes[0].by, ok.body.votes[0].via], ["auth0|alice", "cli"]);
});

test("rejected logins are audited at the guard, the STS and the API (rate-limited)", async () => {
  for (let i = 0; i < 3; i++) {
    const r = await fetch(resource, { method: "POST", headers: { authorization: "Bearer not-a-real-token", "content-type": "application/json" }, body: "{}" });
    assert.equal(r.status, 401);
  }
  await guard.opts.ledger.flush?.();
  const atGuard = (await ledger("auth.rejected")).filter((r) => r.details.code === "malformed");
  assert.equal(atGuard.length, 1, "3 identical attempts within 10 s -> 1 record");
  assert.equal(atGuard[0].details.resource, resource);

  const bad = await fetch(`${issuer}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + Buffer.from("claude-code:wrong").toString("base64") }, body: "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" });
  assert.equal(bad.status, 401);
  assert.ok((await ledger("token.denied")).some((r) => r.details.code === "invalid_client" && r.details.client_id === "claude-code"));

  await call("GET", "/api/agents", { key: "mdt_wrong_key_1" });
  await call("GET", "/api/agents", { key: "mdt_wrong_key_2" });
  assert.equal((await ledger("api.auth_rejected")).filter((r) => r.details.code === "invalid_api_key").length, 1);

  const all = await ledger("@rejected");
  assert.ok(all.length >= 4);
  const report = buildReport(cp.ledger.read());
  assert.ok(report.rejected_auth.total >= 4);
});

test("agent secrets: rotate (old secret and its tokens stop working) and remove", async () => {
  const reg = await admin("POST", "/api/agents", { id: "rotate-me", allowed_tools: ["lookup_*"], allowed_resources: [resource] });
  const subject = await devLogin(issuer, { sub: "user:x" });
  const old = await exchangeToken({ mandatUrl: issuer, clientId: "rotate-me", clientSecret: reg.body.client_secret, subjectToken: subject, resource });
  const client = new McpHttpClient(resource, old.access_token);
  await client.initialize();

  const rot = await admin("POST", "/api/agents/rotate-me/rotate-secret", { revoke_tokens: true });
  assert.match(rot.body.client_secret, /^mdt_as_/);
  await assert.rejects(exchangeToken({ mandatUrl: issuer, clientId: "rotate-me", clientSecret: reg.body.client_secret, subjectToken: subject, resource }), /invalid_client/);
  await new Promise((r) => setTimeout(r, 2500)); // guard polls revocations every 2 s
  await assert.rejects(client.callTool("lookup_order", { order_id: "A-1001" }), /revoked/);
  const fresh = await exchangeToken({ mandatUrl: issuer, clientId: "rotate-me", clientSecret: rot.body.client_secret, subjectToken: subject, resource });
  const c2 = new McpHttpClient(resource, fresh.access_token);
  await c2.initialize();
  assert.equal((await c2.callTool("lookup_order", { order_id: "A-1001" })).isError, undefined);

  assert.equal((await admin("DELETE", "/api/agents/rotate-me")).status, 200);
  assert.ok(!(await admin("GET", "/api/agents")).body.agents.some((a: any) => a.id === "rotate-me"));
  await assert.rejects(exchangeToken({ mandatUrl: issuer, clientId: "rotate-me", clientSecret: rot.body.client_secret, subjectToken: subject, resource }), /invalid_client/);
  const types = (await admin("GET", "/api/ledger?limit=1000")).body.records.map((r: any) => r.type);
  assert.ok(types.includes("agent.secret_rotated") && types.includes("agent.removed") && types.includes("user.granted"));
});

test("users API and CLI: grant, list, revoke; humans cannot get the service role", async () => {
  assert.equal((await admin("POST", "/api/users", { email: "bot@acme.example", roles: ["service"] })).status, 400);
  const out: string[] = [];
  const log = console.log;
  console.log = (m: string) => out.push(String(m));
  try {
    assert.equal(await main(["users", "grant", "--email", "carol@acme.example", "--roles", "auditor", "--url", issuer, "--key", keys.admin]), 0);
    assert.equal(await main(["users", "list", "--url", issuer, "--key", keys.admin]), 0);
    assert.equal(await main(["users", "revoke", "carol@acme.example", "--url", issuer, "--key", keys.admin]), 0);
  } finally { console.log = log; }
  assert.ok(out.some((l) => l.includes("carol@acme.example now has: auditor")));
  assert.ok(out.some((l) => l.includes("Console sign-in: enabled")));
  assert.ok(!(await admin("GET", "/api/users")).body.users.some((u: any) => u.id === "carol@acme.example"));
});
