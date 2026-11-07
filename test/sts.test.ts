import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { JwksClient, decodeJwt, signJwt, verifyJwt, JwtError } from "../src/sts/jwt.ts";
import { Sts, OAuthError, hashSecret, GRANT_TOKEN_EXCHANGE, TT_ACCESS_TOKEN, TT_ID_TOKEN, type AgentRecord } from "../src/sts/sts.ts";
import { matchRevocation, type Revocation } from "../src/sts/revocation.ts";
import { nowSeconds } from "../src/util.ts";
import { testKey } from "./helpers.ts";

test("jwt: sign/verify ES256 and reject tampering, wrong aud, expiry, alg confusion", async () => {
  const k = testKey();
  const pub = createPublicKey(k.privateKey);
  const now = nowSeconds();
  const tok = signJwt({ iss: "i", aud: "a", sub: "s", exp: now + 60 }, k);
  assert.equal((await verifyJwt(tok, () => pub, { issuer: "i", audience: "a" })).sub, "s");
  await assert.rejects(verifyJwt(tok, () => pub, { audience: "b" }), (e: JwtError) => e.code === "bad_aud");
  const [h, , s] = tok.split(".");
  const forged = `${h}.${Buffer.from(JSON.stringify({ iss: "i", aud: "a", sub: "admin", exp: now + 60 })).toString("base64url")}.${s}`;
  await assert.rejects(verifyJwt(forged, () => pub), (e: JwtError) => e.code === "bad_signature");
  const none = `${Buffer.from('{"alg":"none"}').toString("base64url")}.${tok.split(".")[1]}.`;
  await assert.rejects(verifyJwt(none, () => pub), (e: JwtError) => e.code === "bad_alg");
  const old = signJwt({ exp: now - 120 }, k);
  await assert.rejects(verifyJwt(old, () => pub), (e: JwtError) => e.code === "expired");
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
  await assert.rejects(verifyJwt(tok, () => rsa), (e: JwtError) => e.code === "bad_alg");
});

test("jwks: cached keys keep working through an outage; with no keys the failure surfaces", async () => {
  const k = testKey();
  const srv = createServer((_req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ keys: [k.publicJwk] })); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/jwks`;
  const client = new JwksClient(url, 20, 5);
  assert.ok(await client.getKey(k.kid));
  srv.closeAllConnections();
  await new Promise((r) => srv.close(r));
  await new Promise((r) => setTimeout(r, 40));
  assert.ok(await client.getKey(k.kid), "the TTL passed while the server was down");
  await assert.rejects(new JwksClient(url).getKey(k.kid));
});

function makeSts(revs: Revocation[] = []) {
  const key = testKey();
  const agents: AgentRecord[] = [
    { id: "support-bot", secret_hash: hashSecret("s1"), allowed_tools: ["lookup_*", "refund"], allowed_resources: ["https://mcp.test/mcp"], versions: ["1.0.0"], created_at: "" },
    { id: "billing-bot", secret_hash: hashSecret("s2"), allowed_tools: ["refund"], created_at: "" },
  ];
  const issued: string[] = [];
  const sts = new Sts({ issuer: "https://mandat.test", key, agents: () => agents, revocations: () => revs, trustedIssuers: [], devIdp: true, onIssued: (t) => issued.push(t.jti) });
  return { sts, key, issued };
}

const form = (o: Record<string, string>) => new URLSearchParams({ grant_type: GRANT_TOKEN_EXCHANGE, subject_token_type: TT_ID_TOKEN, resource: "https://mcp.test/mcp", mandat_agent_version: "1.0.0", ...o });

test("sts: token exchange yields sub=user, act=agent, aud=resource, RAR, short ttl", async () => {
  const { sts, issued } = makeSts();
  const id = sts.devLogin({ sub: "user:maria", tenant: "acme" });
  const r = await sts.exchange(form({ subject_token: id, authorization_details: JSON.stringify([{ type: "mandat_tool_call", tools: ["refund"], limits: { amount: { max: 100 } } }]) }), { id: "support-bot", secret: "s1" });
  const c = decodeJwt(r.access_token as string);
  assert.equal(c.header.typ, "at+jwt");
  assert.equal(c.payload.sub, "user:maria");
  assert.deepEqual(c.payload.act, { sub: "support-bot", client_id: "support-bot", mandat_agent_version: "1.0.0" });
  assert.equal(c.payload.aud, "https://mcp.test/mcp");
  assert.ok((c.payload.exp as number) - (c.payload.iat as number) <= 300);
  assert.deepEqual(c.payload.authorization_details, [{ type: "mandat_tool_call", tools: ["refund"], locations: ["https://mcp.test/mcp"], limits: { amount: { max: 100 } } }]);
  assert.equal((c.payload.mandat as { tenant: string }).tenant, "acme");
  assert.equal(issued.length, 1);
});

test("sts: rejects bad client, unknown version, foreign resource, over-broad tools, untrusted issuer", async () => {
  const { sts } = makeSts();
  const id = sts.devLogin({ sub: "u" });
  const code = (e: unknown) => (e as OAuthError).error;
  await assert.rejects(sts.exchange(form({ subject_token: id }), { id: "support-bot", secret: "wrong" }), (e) => code(e) === "invalid_client");
  await assert.rejects(sts.exchange(form({ subject_token: id, mandat_agent_version: "9.9.9" }), { id: "support-bot", secret: "s1" }), (e) => code(e) === "invalid_request");
  await assert.rejects(sts.exchange(form({ subject_token: id, resource: "https://other.test/mcp" }), { id: "support-bot", secret: "s1" }), (e) => code(e) === "invalid_target");
  await assert.rejects(sts.exchange(form({ subject_token: id, authorization_details: '[{"type":"mandat_tool_call","tools":["delete_all"]}]' }), { id: "support-bot", secret: "s1" }), (e) => code(e) === "invalid_authorization_details");
  const foreign = signJwt({ iss: "https://evil.test", sub: "admin", exp: nowSeconds() + 60 }, testKey());
  await assert.rejects(sts.exchange(form({ subject_token: foreign }), { id: "support-bot", secret: "s1" }), (e) => code(e) === "invalid_grant");
});

test("sts: an agent cannot give itself a scope", async () => {
  const { sts } = makeSts();
  const request = form({ subject_token: sts.devLogin({ sub: "user:maria" }) });
  request.set("scope", "admin:everything");
  const r = await sts.exchange(request, { id: "support-bot", secret: "s1" });
  assert.equal(r.scope, undefined);
  assert.equal(decodeJwt(r.access_token as string).payload.scope, undefined);
});

test("sts: a sub-agent cannot move a token to another resource", async () => {
  const { sts } = makeSts();
  const id = sts.devLogin({ sub: "user:maria" });
  const parent = await sts.exchange(form({ subject_token: id }), { id: "support-bot", secret: "s1" });
  await assert.rejects(
    sts.exchange(new URLSearchParams({ grant_type: GRANT_TOKEN_EXCHANGE, subject_token: parent.access_token as string, subject_token_type: TT_ACCESS_TOKEN, resource: "https://other.test/mcp" }), { id: "billing-bot", secret: "s2" }),
    (e: OAuthError) => e.error === "invalid_target",
  );
});

test("sts: a sub-agent cannot widen enum or equals limits", async () => {
  const { sts } = makeSts();
  const id = sts.devLogin({ sub: "user:maria" });
  const parent = await sts.exchange(form({ subject_token: id, authorization_details: '[{"type":"mandat_tool_call","tools":["refund"],"limits":{"currency":{"enum":["EUR","USD"]},"country":{"equals":"DE"}}}]' }), { id: "support-bot", secret: "s1" });
  const child = await sts.exchange(
    new URLSearchParams({ grant_type: GRANT_TOKEN_EXCHANGE, subject_token: parent.access_token as string, subject_token_type: TT_ACCESS_TOKEN, resource: "https://mcp.test/mcp", authorization_details: '[{"type":"mandat_tool_call","tools":["refund"],"limits":{"currency":{"enum":["EUR","BTC"]},"country":{"equals":"XX"}}}]' }),
    { id: "billing-bot", secret: "s2" },
  );
  const limits = (decodeJwt(child.access_token as string).payload.authorization_details as any)[0].limits;
  assert.deepEqual(limits.currency.enum, ["EUR"]);
  assert.equal(limits.country.equals, "DE");
});

test("sts: nested delegation keeps the user, nests act, and can only narrow", async () => {
  const { sts } = makeSts();
  const id = sts.devLogin({ sub: "user:maria" });
  const parent = await sts.exchange(form({ subject_token: id, authorization_details: '[{"type":"mandat_tool_call","tools":["refund","lookup_order"],"limits":{"amount":{"max":100}}}]' }), { id: "support-bot", secret: "s1" });
  const child = await sts.exchange(
    new URLSearchParams({ grant_type: GRANT_TOKEN_EXCHANGE, subject_token: parent.access_token as string, subject_token_type: TT_ACCESS_TOKEN, resource: "https://mcp.test/mcp", authorization_details: '[{"type":"mandat_tool_call","tools":["refund"],"limits":{"amount":{"max":500}}}]' }),
    { id: "billing-bot", secret: "s2" },
  );
  const c = decodeJwt(child.access_token as string).payload;
  assert.equal(c.sub, "user:maria");
  assert.equal((c.act as any).sub, "billing-bot");
  assert.equal((c.act as any).act.sub, "support-bot");
  // child asked for max 500 but parent only had 100 -> narrowed
  assert.equal((c.authorization_details as any)[0].limits.amount.max, 100);
  assert.ok((c.exp as number) <= (decodeJwt(parent.access_token as string).payload.exp as number));
});

test("revocation: by agent (anywhere in the chain), version, subject; blocks issuance", async () => {
  const now = nowSeconds();
  const claims = { iat: now - 5, sub: "u", jti: "j", act: { sub: "billing-bot", act: { sub: "support-bot", mandat_agent_version: "1.0.0" } }, mandat: { task_id: "t" } };
  const r = (type: Revocation["type"], value: string, version?: string): Revocation => ({ id: "r", type, value, version, issued_before: now, blocks_issuance: true, created_at: "" });
  assert.ok(matchRevocation(claims, [r("agent", "support-bot")]));
  assert.ok(matchRevocation(claims, [r("agent_version", "support-bot", "1.0.0")]));
  assert.equal(matchRevocation(claims, [r("agent_version", "support-bot", "2.0.0")]), null);
  assert.ok(matchRevocation(claims, [r("subject", "u")]));
  assert.ok(matchRevocation(claims, [r("task", "t")]));
  assert.equal(matchRevocation({ ...claims, iat: now + 10 }, [r("agent", "support-bot")]), null, "tokens issued after the revocation are unaffected");

  const { sts } = makeSts([r("agent", "support-bot")]);
  await assert.rejects(sts.exchange(form({ subject_token: sts.devLogin({ sub: "u" }) }), { id: "support-bot", secret: "s1" }), (e) => (e as OAuthError).error === "access_denied");
});
