// OpenID Connect login for humans (Auth0, Okta, Entra ID, Keycloak, …).
//
// `mandat login` runs the Authorization Code flow with PKCE (S256) through a loopback redirect
// (RFC 8252, native apps): no client secret, the code can only be redeemed by this process.
// The verified ID token becomes the `subject_token` for Mandat's token exchange; the session
// (with refresh token, if the IdP issues one) is cached in ~/.mandat/session.json (mode 0600).

import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { JwksClient, verifyJwt, type JwtPayload } from "./sts/jwt.ts";
import { nowSeconds } from "./util.ts";

export interface OidcMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  code_challenge_methods_supported?: string[];
}

export interface Session {
  issuer: string;
  client_id: string;
  id_token: string;
  refresh_token?: string;
  /** ID token expiry (unix seconds). */
  expires_at: number;
  user: { sub: string; email?: string; name?: string };
  created_at: string;
}

export interface LoginOptions {
  issuer: string;
  clientId: string;
  /** Loopback port registered as callback in the IdP: http://127.0.0.1:<port>/callback */
  port?: number;
  scopes?: string[];
  /** Extra authorize parameters (e.g. { organization: "org_123" } for Auth0 Organizations). */
  extraParams?: Record<string, string>;
  /** How to show the login URL. Default: open the system browser. */
  openBrowser?: (url: string) => Promise<void> | void;
  timeoutMs?: number;
}

export class OidcError extends Error {}

const b64url = (b: Buffer) => b.toString("base64url");

export async function discover(issuer: string): Promise<OidcMetadata> {
  const base = issuer.replace(/\/+$/, "");
  const res = await fetch(`${base}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new OidcError(`OIDC discovery failed for ${issuer}: HTTP ${res.status}`);
  const meta = (await res.json()) as OidcMetadata;
  // Auth0's issuer ends with "/": compare without trailing slashes, but keep the IdP's exact value.
  if (meta.issuer.replace(/\/+$/, "") !== base) throw new OidcError(`Issuer mismatch: discovery says ${meta.issuer}, expected ${issuer}`);
  for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
    if (!meta[k]) throw new OidcError(`Discovery document has no ${k}`);
  }
  return meta;
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
}

/** Interactive browser login. Resolves with a verified session. */
export async function login(o: LoginOptions): Promise<Session> {
  const meta = await discover(o.issuer);
  if (meta.code_challenge_methods_supported && !meta.code_challenge_methods_supported.includes("S256"))
    throw new OidcError("The IdP does not advertise PKCE S256");
  const port = o.port ?? 8765;
  const redirectUri = `http://127.0.0.1:${port}/callback`;
  const { verifier, challenge } = pkcePair();
  const state = b64url(randomBytes(16));
  const nonce = b64url(randomBytes(16));
  const url = new URL(meta.authorization_endpoint);
  const params: Record<string, string> = {
    response_type: "code",
    client_id: o.clientId,
    redirect_uri: redirectUri,
    scope: (o.scopes ?? ["openid", "profile", "email", "offline_access"]).join(" "),
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...o.extraParams,
  };
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);

  const code = await new Promise<string>((resolve, reject) => {
    let server: Server;
    const timer = setTimeout(() => { server.close(); reject(new OidcError("Login timed out")); }, o.timeoutMs ?? 5 * 60_000);
    const finish = (err: Error | null, value?: string) => {
      clearTimeout(timer);
      setImmediate(() => server.close());
      err ? reject(err) : resolve(value!);
    };
    server = createServer((req, res) => {
      const u = new URL(req.url ?? "/", redirectUri);
      if (u.pathname !== "/callback") { res.writeHead(404).end(); return; }
      const page = (title: string, msg: string) => {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font:16px system-ui;margin:3rem"><h2>${title}</h2><p>${msg}</p></body>`);
      };
      const err = u.searchParams.get("error");
      if (err) { page("Login failed", "You can close this window."); return finish(new OidcError(`${err}: ${u.searchParams.get("error_description") ?? ""}`)); }
      if (u.searchParams.get("state") !== state) { page("Login failed", "State mismatch."); return finish(new OidcError("State mismatch (possible CSRF)")); }
      const iss = u.searchParams.get("iss");
      if (iss && iss !== meta.issuer) { page("Login failed", "Issuer mismatch."); return finish(new OidcError(`Authorization response from unexpected issuer ${iss} (RFC 9207)`)); }
      const c = u.searchParams.get("code");
      if (!c) { page("Login failed", "No authorization code."); return finish(new OidcError("No authorization code in callback")); }
      page("Signed in to Mandat", "You can close this window and return to the terminal.");
      finish(null, c);
    });
    server.on("error", (e: NodeJS.ErrnoException) =>
      finish(new OidcError(e.code === "EADDRINUSE" ? `Port ${port} is in use; pass --port and register http://127.0.0.1:<port>/callback in the IdP` : e.message)));
    server.listen(port, "127.0.0.1", () => {
      void Promise.resolve((o.openBrowser ?? openSystemBrowser)(url.toString())).catch(() => {});
    });
  });

  const tokens = await tokenRequest(meta, {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: o.clientId,
    code_verifier: verifier,
  });
  return toSession(meta, o.clientId, tokens, nonce);
}

/** Uses the refresh token to obtain a fresh ID token. */
export async function refreshSession(s: Session): Promise<Session> {
  if (!s.refresh_token) throw new OidcError("Session expired and has no refresh token: run `mandat login` again");
  const meta = await discover(s.issuer);
  const tokens = await tokenRequest(meta, { grant_type: "refresh_token", refresh_token: s.refresh_token, client_id: s.client_id });
  if (!tokens.id_token) throw new OidcError("Refresh did not return an ID token (request the openid scope)");
  // Refresh-token rotation (Auth0 default for new apps) returns a new refresh token; keep the old one otherwise.
  return toSession(meta, s.client_id, { refresh_token: s.refresh_token, ...tokens }, null);
}

async function tokenRequest(meta: OidcMetadata, form: Record<string, string>): Promise<{ id_token?: string; refresh_token?: string; access_token?: string }> {
  const res = await fetch(meta.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams(form),
    signal: AbortSignal.timeout(15_000),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, string>;
  if (!res.ok) throw new OidcError(`Token endpoint: ${body.error ?? res.status} ${body.error_description ?? ""}`.trim());
  return body;
}

async function toSession(meta: OidcMetadata, clientId: string, tokens: { id_token?: string; refresh_token?: string }, nonce: string | null): Promise<Session> {
  if (!tokens.id_token) throw new OidcError("IdP returned no ID token (is the openid scope allowed?)");
  const jwks = new JwksClient(meta.jwks_uri);
  const claims: JwtPayload = await verifyJwt(tokens.id_token, (h) => jwks.getKey(h.kid), { issuer: meta.issuer, audience: clientId });
  if (nonce !== null && claims.nonce !== nonce) throw new OidcError("ID token nonce mismatch");
  if (!claims.sub) throw new OidcError("ID token has no sub");
  return {
    issuer: meta.issuer,
    client_id: clientId,
    id_token: tokens.id_token,
    refresh_token: tokens.refresh_token,
    expires_at: Number(claims.exp),
    user: { sub: claims.sub, email: claims.email as string | undefined, name: claims.name as string | undefined },
    created_at: new Date().toISOString(),
  };
}

// ---------- session cache ----------

export function sessionPath(): string {
  return join(process.env.MANDAT_HOME ?? join(homedir(), ".mandat"), "session.json");
}

export function saveSession(s: Session): void {
  const p = sessionPath();
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, JSON.stringify(s, null, 2) + "\n", { mode: 0o600 });
}

export function loadSession(): Session | null {
  const p = sessionPath();
  return existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as Session) : null;
}

export function clearSession(): boolean {
  const p = sessionPath();
  if (!existsSync(p)) return false;
  rmSync(p);
  return true;
}

/** Returns a valid ID token from the cached session, refreshing (and re-saving) it when it is about to expire. */
export async function currentIdToken(minValiditySec = 120): Promise<string> {
  let s = loadSession();
  if (!s) throw new OidcError("Not logged in: run `mandat login --issuer <url> --client-id <id>`");
  if (s.expires_at - nowSeconds() < minValiditySec) {
    s = await refreshSession(s);
    saveSession(s);
  }
  return s.id_token;
}

export function openSystemBrowser(url: string): void {
  const [cmd, args] = process.platform === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
    : process.platform === "darwin" ? ["open", [url]] : ["xdg-open", [url]];
  const child = spawn(cmd, args, { stdio: "ignore", detached: true });
  child.on("error", () => {});
  child.unref();
}
