// Real-user login (OIDC, Auth0-like) through to a protected MCP tool call.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startFakeIdp, type FakeIdp } from "./fake-idp.ts";
import { login, saveSession, loadSession, currentIdToken, OidcError } from "../src/oidc.ts";
import { createControlPlane, createGuard, McpHttpServer, Bridge, hashApiKey, signJwt, type ControlPlane } from "../src/index.ts";
import { STARTER_POLICY } from "../src/cli/templates.ts";
import { tools } from "../examples/refund-server/tools.ts";
import { main } from "../src/cli/main.ts";
import { nowSeconds } from "../src/util.ts";

const freePort = () => new Promise<number>((r) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => r(p)); }); });

let idp: FakeIdp;
const home = mkdtempSync(join(tmpdir(), "mandat-home-"));
before(async () => {
  process.env.MANDAT_HOME = home;
  idp = await startFakeIdp({ idTokenTtl: 3600 });
});
after(async () => { await idp.close(); });

test("login: authorization code + PKCE through the loopback callback, verified ID token", async () => {
  const s = await login({ issuer: idp.issuer, clientId: idp.clientId, port: await freePort(), openBrowser: idp.browser });
  assert.equal(s.user.sub, "auth0|maria");
  assert.equal(s.user.email, "maria@acme.example");
  assert.equal(s.issuer, idp.issuer, "Auth0-style trailing slash issuer is preserved");
  assert.ok(s.refresh_token);
  saveSession(s);
  assert.equal(loadSession()?.user.sub, "auth0|maria");
});

test("login: rejects a forged callback (state mismatch)", async () => {
  const port = await freePort();
  await assert.rejects(
    login({ issuer: idp.issuer, clientId: idp.clientId, port, openBrowser: async () => { await fetch(`http://127.0.0.1:${port}/callback?code=stolen&state=wrong`); } }),
    (e: Error) => e instanceof OidcError && /State mismatch/.test(e.message),
  );
});

test("login: IdP error is surfaced", async () => {
  const port = await freePort();
  await assert.rejects(
    login({ issuer: idp.issuer, clientId: idp.clientId, port, openBrowser: async () => { await fetch(`http://127.0.0.1:${port}/callback?error=access_denied&error_description=User%20cancelled`); } }),
    /access_denied: User cancelled/,
  );
});

test("session: an expiring ID token is refreshed with the (rotated) refresh token", async () => {
  const s = loadSession()!;
  saveSession({ ...s, expires_at: nowSeconds() + 10 });
  const before = idp.refreshCount;
  const tok = await currentIdToken();
  assert.equal(idp.refreshCount, before + 1);
  assert.notEqual(tok, s.id_token);
  const after = loadSession()!;
  assert.notEqual(after.refresh_token, s.refresh_token, "rotated refresh token is stored");
  assert.ok(after.expires_at > nowSeconds() + 3000);
});

test("idp add: trusts the IdP in mandat.config.json and can disable the dev IdP", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandat-cfg-"));
  const cfg = join(dir, "mandat.config.json");
  writeFileSync(cfg, JSON.stringify({ issuer: "http://x", port: 1, devIdp: true, apiKeys: [], trustedIssuers: [] }));
  const log = console.log; console.log = () => {};
  try {
    assert.equal(await main(["idp", "add", "--issuer", idp.issuer, "--client-id", idp.clientId, "--tenant-claim", "org_id", "--disable-dev-idp", "--config", cfg]), 0);
  } finally { console.log = log; }
  const written = JSON.parse(readFileSync(cfg, "utf8"));
  assert.equal(written.devIdp, false);
  assert.deepEqual(written.trustedIssuers, [{ issuer: idp.issuer, jwks_uri: `${idp.issuer}.well-known/jwks.json`, audience: idp.clientId, tenant_claim: "org_id" }]);
});

test("end to end: the logged-in IdP user is the principal of an agent's MCP call; dev IdP is off", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandat-oidc-e2e-"));
  const [cpPort, mcpPort] = [await freePort(), await freePort()];
  const issuer = `http://127.0.0.1:${cpPort}`;
  const resource = `http://127.0.0.1:${mcpPort}/mcp`;
  writeFileSync(join(dir, "policy.json"), JSON.stringify(STARTER_POLICY));
  const keys = { admin: "mdt_admin_oidc_test_0000000000", service: "mdt_service_oidc_test_00000000" };
  const cp: ControlPlane = createControlPlane({
    issuer, port: cpPort, dataDir: join(dir, "data"), policyFile: join(dir, "policy.json"), devIdp: false,
    trustedIssuers: [{ issuer: idp.issuer, jwks_uri: `${idp.issuer}.well-known/jwks.json`, audience: idp.clientId, tenant_claim: "org_id" }],
    apiKeys: [{ id: "admin", hash: hashApiKey(keys.admin), roles: ["admin", "auditor"] }, { id: "svc", hash: hashApiKey(keys.service), roles: ["service"] }],
    approvals: { log: false },
  });
  await cp.listen();
  const api = async (method: string, path: string, body?: unknown) =>
    (await fetch(issuer + path, { method, headers: { authorization: `Bearer ${keys.admin}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined })).json() as Promise<any>;
  const reg = await api("POST", "/api/agents", { id: "claude-code", allowed_tools: ["lookup_*"], allowed_resources: [resource] });
  const guard = await createGuard({ resource, controlPlane: issuer, apiKey: keys.service, dataDir: join(dir, "g"), log: () => {} });
  const mcp = new McpHttpServer({ name: "acme", version: "1", guard, tools });
  await mcp.listen(mcpPort);
  try {
    assert.equal((await fetch(`${issuer}/dev/login`, { method: "POST", body: "{}" })).status, 404, "dev IdP disabled");

    const bridge = new Bridge({ url: resource, mandatUrl: issuer, agentId: "claude-code", agentSecret: reg.client_secret, subjectTokenProvider: () => currentIdToken(), log: () => {} });
    const init: any = await bridge.forward({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } } as never);
    assert.equal(init.result.serverInfo.name, "acme");
    const r: any = await bridge.forward({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "lookup_order", arguments: { order_id: "A-1001" } } } as never);
    assert.equal(r.result.isError, undefined, JSON.stringify(r));

    await guard.opts.ledger.flush?.();
    const { records } = await api("GET", "/api/ledger?type=agent.tool_call");
    assert.deepEqual(records[0].principal, { sub: "auth0|maria", tenant: "org_acme", email: "maria@acme.example" });
    assert.deepEqual(records[0].actor_chain, ["claude-code"]);

    // An ID token issued to a different client of the same tenant is rejected by the STS.
    const now = nowSeconds();
    const otherClient = signJwt({ iss: idp.issuer, aud: "some-other-app", sub: "auth0|maria", iat: now, exp: now + 600 }, idp.key);
    const bad = new Bridge({ url: resource, mandatUrl: issuer, agentId: "claude-code", agentSecret: reg.client_secret, subjectToken: otherClient, log: () => {} });
    const denied: any = await bad.forward({ jsonrpc: "2.0", id: 3, method: "tools/list" } as never);
    assert.match(denied.error.message, /subject_token rejected/);
  } finally {
    await mcp.close();
    await cp.close();
  }
});
