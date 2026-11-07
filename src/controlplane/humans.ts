// Human sign-in for the control plane: people (approvers, admins, auditors) authenticate with the
// organisation's IdP instead of shared API keys, so every approval and admin change in the ledger
// names a real, verified person.
//
//   console  -> /auth/login -> IdP (Authorization Code + PKCE) -> /auth/callback -> HttpOnly session cookie
//   CLI      -> `--login`: the ID token from `mandat login` as bearer
//
// Signing in proves *who* someone is; what they may do comes from explicit grants (users.json),
// managed by an admin with `mandat users grant`.

import { randomBytes } from "node:crypto";
import { join } from "node:path";
import type { Role } from "./config.ts";
import { JsonCollection } from "../store.ts";
import { authorizeUrl, discover, pkcePair, redeemCode, type OidcMetadata } from "../oidc.ts";
import { HttpError } from "../util.ts";

export interface HumanUser {
  /** Lower-cased e-mail, or the IdP subject when granted by sub. */
  id: string;
  email?: string;
  sub?: string;
  roles: Role[];
  created_at: string;
  by: string;
}

/** Who is calling the API, however they authenticated. */
export interface Principal {
  id: string;
  roles: Role[];
  via: "api_key" | "session" | "id_token";
  sub?: string;
  email?: string;
}

export const HUMAN_ROLES: Role[] = ["admin", "approver", "auditor"];
export const SESSION_COOKIE = "mandat_session";
const SESSION_TTL_MS = 8 * 3_600_000;
const LOGIN_TTL_MS = 10 * 60_000;

interface Session { sub: string; email?: string; email_verified?: boolean; exp: number }

export class HumanAuth {
  readonly users: JsonCollection<HumanUser>;
  private sessions = new Map<string, Session>();
  private pending = new Map<string, { verifier: string; nonce: string; exp: number }>();
  private login: { issuer: string; clientId: string } | null;
  private publicUrl: string;
  private meta: OidcMetadata | null = null;

  constructor(opts: { dataDir: string; publicUrl: string; login: { issuer: string; clientId: string } | null }) {
    this.users = new JsonCollection<HumanUser>(join(opts.dataDir, "users.json"));
    this.login = opts.login;
    this.publicUrl = opts.publicUrl;
  }

  get loginEnabled(): boolean { return this.login !== null; }
  get loginIssuer(): string | null { return this.login?.issuer ?? null; }
  get redirectUri(): string { return `${this.publicUrl}/auth/callback`; }

  /** Finds the grant for a verified identity: by IdP subject, or by e-mail only if the IdP confirms it is verified. */
  findUser(sub: string, email?: string, emailVerified?: boolean): HumanUser | undefined {
    const bySub = this.users.all().find((u) => u.sub === sub);
    if (bySub) return bySub;
    if (!email || emailVerified !== true) return undefined;
    return this.users.get(email.toLowerCase());
  }

  principal(sub: string, email: string | undefined, emailVerified: boolean | undefined, via: Principal["via"]): Principal {
    const u = this.findUser(sub, email, emailVerified);
    if (!u) {
      const who = email ?? sub;
      throw new HttpError(403, "no_role", `Signed in as ${who}, but no role is granted. An admin can run: mandat users grant ${email && emailVerified === true ? `--email ${email}` : `--sub ${sub}`} --roles approver`);
    }
    return { id: u.id, roles: u.roles, via, sub, email };
  }

  // ---------- browser login ----------

  async startLogin(): Promise<string> {
    if (!this.login) throw new HttpError(404, "login_disabled", "No identity provider configured: run `mandat idp add` first");
    this.meta ??= await discover(this.login.issuer);
    const now = Date.now();
    for (const [k, v] of this.pending) if (v.exp < now) this.pending.delete(k);
    const state = randomBytes(16).toString("base64url");
    const nonce = randomBytes(16).toString("base64url");
    const { verifier, challenge } = pkcePair();
    this.pending.set(state, { verifier, nonce, exp: now + LOGIN_TTL_MS });
    // No offline_access: the console session is short-lived and needs no refresh token.
    return authorizeUrl(this.meta, { clientId: this.login.clientId, redirectUri: this.redirectUri, state, nonce, challenge, scopes: ["openid", "profile", "email"] }).toString();
  }

  /** Completes the login and returns the new session id. */
  async finishLogin(params: URLSearchParams): Promise<{ sessionId: string; who: string }> {
    if (!this.login || !this.meta) throw new HttpError(400, "login_not_started", "Start the login from the console");
    const err = params.get("error");
    if (err) throw new HttpError(400, err, params.get("error_description") ?? err);
    const state = params.get("state") ?? "";
    const p = this.pending.get(state);
    this.pending.delete(state);
    if (!p || p.exp < Date.now()) throw new HttpError(400, "invalid_state", "Login expired or state mismatch; start again from the console");
    const iss = params.get("iss");
    if (iss && iss !== this.meta.issuer) throw new HttpError(400, "invalid_issuer", `Authorization response from unexpected issuer ${iss}`);
    const code = params.get("code");
    if (!code) throw new HttpError(400, "invalid_request", "No authorization code");
    const s = await redeemCode(this.meta, { clientId: this.login.clientId, code, verifier: p.verifier, redirectUri: this.redirectUri, nonce: p.nonce });
    const sessionId = randomBytes(32).toString("base64url");
    this.sessions.set(sessionId, { sub: s.user.sub, email: s.user.email, email_verified: s.user.email_verified, exp: Date.now() + SESSION_TTL_MS });
    return { sessionId, who: s.user.email ?? s.user.sub };
  }

  session(cookieHeader: string | undefined): Session | null {
    const id = readCookie(cookieHeader, SESSION_COOKIE);
    if (!id) return null;
    const s = this.sessions.get(id);
    if (!s) return null;
    if (s.exp < Date.now()) { this.sessions.delete(id); return null; }
    return s;
  }

  logout(cookieHeader: string | undefined): void {
    const id = readCookie(cookieHeader, SESSION_COOKIE);
    if (id) this.sessions.delete(id);
  }

  sessionCookie(sessionId: string | null): string {
    const secure = this.publicUrl.startsWith("https:") ? "; Secure" : "";
    return sessionId
      ? `${SESSION_COOKIE}=${sessionId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${secure}`
      : `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`;
  }
}

export function readCookie(header: string | undefined, name: string): string | null {
  for (const part of (header ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=") || null;
  }
  return null;
}
