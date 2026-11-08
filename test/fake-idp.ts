// A minimal OIDC provider that mimics Auth0's behaviour for tests: issuer with a trailing slash,
// RS256 ID tokens with kid, PKCE S256 enforcement, nonce echo, refresh-token rotation, org_id claim.

import { createHash, generateKeyPairSync, randomBytes, createPublicKey } from "node:crypto";
import { createServer, type Server } from "node:http";
import { signJwt, signingKeyFromPem, type SigningKey } from "../src/sts/jwt.ts";
import { nowSeconds } from "../src/util.ts";

export interface FakeIdp {
  issuer: string;
  clientId: string;
  key: SigningKey;
  /** Simulated browser: follows the authorize URL to the loopback callback. */
  browser: (url: string) => Promise<void>;
  idTokenTtl: number;
  refreshCount: number;
  user: { sub: string; email: string; email_verified: boolean; name: string; org_id: string };
  close(): Promise<void>;
}

export async function startFakeIdp(opts: { idTokenTtl?: number; issueRefreshToken?: boolean } = {}): Promise<FakeIdp> {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const key = signingKeyFromPem(privateKey.export({ format: "pem", type: "pkcs8" }) as string);
  const jwk = { ...createPublicKey(key.privateKey).export({ format: "jwk" }), kid: key.kid, alg: "RS256", use: "sig" };
  const codes = new Map<string, { challenge: string; nonce: string; redirect: string; clientId: string }>();
  const refreshTokens = new Set<string>();
  const state: FakeIdp = {
    issuer: "", clientId: "native-client-123", key, idTokenTtl: opts.idTokenTtl ?? 3600, refreshCount: 0,
    user: { sub: "auth0|maria", email: "maria@acme.example", email_verified: true, name: "Maria", org_id: "org_acme" },
    browser: async (url: string) => {
      const res = await fetch(url, { redirect: "manual" });
      const loc = res.headers.get("location");
      if (!loc) throw new Error(`authorize did not redirect: ${res.status} ${await res.text()}`);
      await (await fetch(loc)).text();
    },
    close: () => new Promise((r) => server.close(() => r())),
  };
  const idToken = (nonce?: string) => {
    const now = nowSeconds();
    return signJwt({ iss: state.issuer, aud: state.clientId, iat: now, exp: now + state.idTokenTtl, ...state.user, ...(nonce ? { nonce } : {}) }, key);
  };
  const newRefresh = () => { const t = "rt_" + randomBytes(12).toString("hex"); refreshTokens.add(t); return t; };

  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const json = (status: number, body: unknown) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (url.pathname === "/.well-known/openid-configuration") {
      return json(200, {
        issuer: state.issuer,
        authorization_endpoint: `${state.issuer}authorize`,
        token_endpoint: `${state.issuer}oauth/token`,
        jwks_uri: `${state.issuer}.well-known/jwks.json`,
        code_challenge_methods_supported: ["S256", "plain"],
      });
    }
    if (url.pathname === "/.well-known/jwks.json") return json(200, { keys: [jwk] });
    if (url.pathname === "/authorize") {
      const p = url.searchParams;
      if (p.get("client_id") !== state.clientId) return json(400, { error: "unauthorized_client" });
      if (p.get("code_challenge_method") !== "S256" || !p.get("code_challenge")) return json(400, { error: "invalid_request", error_description: "PKCE required" });
      const code = "code_" + randomBytes(8).toString("hex");
      codes.set(code, { challenge: p.get("code_challenge")!, nonce: p.get("nonce")!, redirect: p.get("redirect_uri")!, clientId: p.get("client_id")! });
      const back = new URL(p.get("redirect_uri")!);
      back.searchParams.set("code", code);
      back.searchParams.set("state", p.get("state")!);
      res.writeHead(302, { location: back.toString() }).end();
      return;
    }
    if (url.pathname === "/oauth/token" && req.method === "POST") {
      let body = "";
      for await (const c of req) body += c;
      const f = new URLSearchParams(body);
      if (f.get("grant_type") === "authorization_code") {
        const c = codes.get(f.get("code") ?? "");
        codes.delete(f.get("code") ?? "");
        if (!c) return json(400, { error: "invalid_grant", error_description: "bad code" });
        const expected = createHash("sha256").update(f.get("code_verifier") ?? "").digest("base64url");
        if (expected !== c.challenge) return json(400, { error: "invalid_grant", error_description: "PKCE verification failed" });
        if (f.get("redirect_uri") !== c.redirect || f.get("client_id") !== c.clientId) return json(400, { error: "invalid_grant" });
        return json(200, { id_token: idToken(c.nonce), access_token: "opaque", token_type: "Bearer", ...(opts.issueRefreshToken !== false ? { refresh_token: newRefresh() } : {}) });
      }
      if (f.get("grant_type") === "refresh_token") {
        const t = f.get("refresh_token") ?? "";
        if (!refreshTokens.delete(t)) return json(403, { error: "invalid_grant", error_description: "Unknown or reused refresh token" });
        state.refreshCount++;
        return json(200, { id_token: idToken(), access_token: "opaque", refresh_token: newRefresh() });
      }
      return json(400, { error: "unsupported_grant_type" });
    }
    json(404, { error: "not_found" });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  state.issuer = `http://127.0.0.1:${(server.address() as { port: number }).port}/`;
  return state;
}
