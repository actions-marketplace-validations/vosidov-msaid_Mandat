// Mandat STS: OAuth 2.0 Token Exchange (RFC 8693) that mints short-lived, per-task tokens.
//
//   sub  = the human the agent acts for (from the IdP's subject_token)
//   act  = the agent (nested `act` when one agent delegates to another)
//   aud  = the single resource the token is for (RFC 8707 `resource`)
//   authorization_details = RFC 9396 capability: which tools, which limits
//   mandat = { agent_version, prompt_hash, task_id, tenant }
//
// The user's own token is never forwarded downstream: resource servers only see Mandat tokens.

import { createPublicKey, type KeyObject } from "node:crypto";
import { JwksClient, JwtError, signJwt, verifyJwt, type JwtPayload, type SigningKey } from "./jwt.ts";
import { blocksIssuance, matchRevocation, type ActClaim, type MandatClaim, type Revocation } from "./revocation.ts";
import type { AuthorizationDetail } from "../policy/engine.ts";
import { globMatch, nowSeconds, randomId, safeEqual, sha256 } from "../util.ts";

export const GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
export const TT_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
export const TT_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
export const TT_JWT = "urn:ietf:params:oauth:token-type:jwt";
const SUBJECT_TOKEN_TYPES = [TT_ACCESS_TOKEN, TT_ID_TOKEN, TT_JWT];

export interface AgentRecord {
  id: string;
  name?: string;
  /** "sha256:<hex>" of the agent's client secret. */
  secret_hash: string;
  /** Tool names / globs this agent may ever be delegated. */
  allowed_tools: string[];
  /** Resource (MCP server) URLs this agent may get tokens for. Empty = any. */
  allowed_resources?: string[];
  /** Known/approved versions. Empty = any version accepted. */
  versions?: string[];
  max_ttl_seconds?: number;
  owner?: string;
  created_at: string;
  disabled?: boolean;
}

export interface TrustedIssuer {
  issuer: string;
  jwks_uri: string;
  /** Expected `aud` of the user's token (the client id Mandat is registered as in the IdP). */
  audience?: string | string[];
  /** Claim carrying the tenant / organisation id (e.g. "org_id" for Auth0, "tid" for Entra). */
  tenant_claim?: string;
}

export interface StsOptions {
  issuer: string;
  key: SigningKey;
  agents: () => AgentRecord[];
  revocations: () => Iterable<Revocation>;
  trustedIssuers: TrustedIssuer[];
  /** Dev-only IdP (issuer `${issuer}/dev-idp`) that signs user tokens with the STS key. */
  devIdp?: boolean;
  defaultTtlSeconds?: number;
  maxTtlSeconds?: number;
  onIssued?: (info: IssuedTokenInfo) => void;
}

export interface IssuedTokenInfo {
  jti: string; sub: string; tenant: string | null; agent: string; agent_version: string | null;
  task_id: string; aud: string; exp: number; actor_chain: string[]; authorization_details: AuthorizationDetail[];
}

export class OAuthError extends Error {
  error: string;
  status: number;
  constructor(error: string, description: string, status = 400) {
    super(description);
    this.error = error;
    this.status = status;
  }
}

export function hashSecret(secret: string): string {
  return "sha256:" + sha256(secret);
}

export class Sts {
  private opts: StsOptions;
  private jwks = new Map<string, JwksClient>();

  constructor(opts: StsOptions) {
    this.opts = opts;
  }

  get devIssuer(): string { return `${this.opts.issuer}/dev-idp`; }

  /** Dev IdP: mint a user ID token. Never enable in production. */
  devLogin(user: { sub: string; email?: string; name?: string; tenant?: string }): string {
    if (!this.opts.devIdp) throw new OAuthError("access_denied", "Dev IdP disabled", 403);
    const now = nowSeconds();
    return signJwt({ iss: this.devIssuer, aud: "mandat", iat: now, exp: now + 3600, ...user, tenant: user.tenant ?? null }, this.opts.key);
  }

  authenticateAgent(clientId: string | undefined, secret: string | undefined): AgentRecord {
    const agent = clientId ? this.opts.agents().find((a) => a.id === clientId) : undefined;
    // Compare against a dummy hash for unknown agents so timing doesn't reveal which ids exist.
    const ok = safeEqual(hashSecret(secret ?? ""), agent?.secret_hash ?? hashSecret(randomId()));
    if (!agent || !ok) throw new OAuthError("invalid_client", "Agent authentication failed", 401);
    if (agent.disabled) throw new OAuthError("invalid_client", "Agent is disabled", 401);
    return agent;
  }

  async exchange(form: URLSearchParams, client: { id?: string; secret?: string }): Promise<Record<string, unknown>> {
    if (form.get("grant_type") !== GRANT_TOKEN_EXCHANGE) throw new OAuthError("unsupported_grant_type", "Only token exchange (RFC 8693) is supported");
    const agent = this.authenticateAgent(client.id, client.secret);

    const subjectToken = form.get("subject_token");
    const subjectType = form.get("subject_token_type") ?? "";
    if (!subjectToken) throw new OAuthError("invalid_request", "subject_token is required");
    if (!SUBJECT_TOKEN_TYPES.includes(subjectType)) throw new OAuthError("invalid_request", `Unsupported subject_token_type '${subjectType}'`);
    const requestedType = form.get("requested_token_type");
    if (requestedType && requestedType !== TT_ACCESS_TOKEN && requestedType !== TT_JWT)
      throw new OAuthError("invalid_request", "requested_token_type must be access_token or jwt");

    const resource = form.get("resource") ?? form.get("audience");
    if (!resource) throw new OAuthError("invalid_target", "resource (RFC 8707) is required: tokens are bound to one MCP server");
    if (agent.allowed_resources?.length && !agent.allowed_resources.includes(resource))
      throw new OAuthError("invalid_target", `Agent '${agent.id}' may not access ${resource}`);

    const version = form.get("mandat_agent_version");
    if (agent.versions?.length && (!version || !agent.versions.includes(version)))
      throw new OAuthError("invalid_request", `Agent version '${version ?? "(none)"}' is not registered for '${agent.id}'`);

    const subject = await this.verifySubject(subjectToken);
    const parent = subject.mandatParent;

    const blocked = blocksIssuance(this.opts.revocations(), { agent: agent.id, version, sub: subject.sub, tenant: subject.tenant });
    if (blocked) throw new OAuthError("access_denied", `Issuance blocked by revocation ${blocked.id} (${blocked.type}: ${blocked.value})`, 403);
    if (parent) {
      const r = matchRevocation(parent, this.opts.revocations());
      if (r) throw new OAuthError("invalid_grant", "Parent token has been revoked");
    }

    const details = this.resolveAuthorizationDetails(form.get("authorization_details"), agent, resource, parent);

    const maxTtl = Math.min(agent.max_ttl_seconds ?? Infinity, this.opts.maxTtlSeconds ?? 900);
    const reqTtl = Number(form.get("expires_in") ?? this.opts.defaultTtlSeconds ?? 300);
    const ttl = Math.max(1, Math.min(Number.isFinite(reqTtl) ? reqTtl : 300, maxTtl, parent?.exp ? parent.exp - nowSeconds() : Infinity));

    const now = nowSeconds();
    const jti = randomId("tok_");
    const taskId = form.get("mandat_task_id") ?? (parent?.mandat as MandatClaim | undefined)?.task_id ?? randomId("task_");
    const act: ActClaim = { sub: agent.id, client_id: agent.id, mandat_agent_version: version ?? null };
    if (parent?.act) act.act = parent.act as ActClaim;
    const mandat: MandatClaim = {
      agent_version: version ?? null,
      prompt_hash: form.get("mandat_prompt_hash"),
      task_id: taskId,
      tenant: subject.tenant,
      session_id: form.get("mandat_session_id"),
    };
    const scope = form.get("scope");
    const payload: JwtPayload = {
      iss: this.opts.issuer,
      sub: subject.sub,
      aud: resource,
      iat: now,
      nbf: now,
      exp: now + ttl,
      jti,
      client_id: agent.id,
      act,
      authorization_details: details,
      mandat,
      ...(scope ? { scope } : {}),
      ...(subject.email ? { email: subject.email } : {}),
    };
    // RFC 9068 typ distinguishes access tokens from ID tokens signed by the same key.
    const token = signJwt(payload, this.opts.key, "at+jwt");

    const chain: string[] = [];
    for (let a: ActClaim | undefined = act; a; a = a.act) chain.push(a.sub);
    this.opts.onIssued?.({
      jti, sub: subject.sub, tenant: subject.tenant, agent: agent.id, agent_version: version ?? null,
      task_id: taskId, aud: resource, exp: now + ttl, actor_chain: chain, authorization_details: details,
    });

    return {
      access_token: token,
      issued_token_type: TT_ACCESS_TOKEN,
      token_type: "Bearer",
      expires_in: ttl,
      authorization_details: details,
      ...(scope ? { scope } : {}),
    };
  }

  private async verifySubject(token: string): Promise<{ sub: string; tenant: string | null; email?: string; mandatParent?: JwtPayload }> {
    let iss: unknown;
    try {
      iss = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")).iss;
    } catch {
      throw new OAuthError("invalid_grant", "subject_token is not a JWT");
    }
    try {
      // Nested delegation: an agent hands its Mandat task token to a sub-agent.
      if (iss === this.opts.issuer) {
        const p = await verifyJwt(token, this.ownKey, { issuer: this.opts.issuer, typ: "at+jwt" });
        return { sub: String(p.sub), tenant: ((p.mandat as MandatClaim)?.tenant ?? null), email: p.email as string | undefined, mandatParent: p };
      }
      if (this.opts.devIdp && iss === this.devIssuer) {
        const p = await verifyJwt(token, this.ownKey, { issuer: this.devIssuer, audience: "mandat" });
        if (!p.sub) throw new OAuthError("invalid_grant", "subject_token has no sub");
        return { sub: p.sub, tenant: (p.tenant as string) ?? null, email: p.email as string | undefined };
      }
      const u = await this.verifyTrusted(token, iss);
      return { sub: u.sub, tenant: u.tenant, email: u.email };
    } catch (e) {
      if (e instanceof OAuthError) throw e;
      if (e instanceof JwtError) throw new OAuthError("invalid_grant", `subject_token rejected: ${e.message}`);
      throw e;
    }
  }

  /**
   * Verifies a human's ID token from a trusted IdP (for console / CLI sign-in). Dev-IdP and Mandat
   * agent tokens are deliberately not accepted here: anyone can mint the former.
   */
  async verifyIdpToken(token: string): Promise<{ iss: string; sub: string; email?: string; email_verified?: boolean; tenant: string | null }> {
    let iss: unknown;
    try { iss = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")).iss; } catch { throw new JwtError("malformed", "Not a JWT"); }
    return this.verifyTrusted(token, iss);
  }

  private async verifyTrusted(token: string, iss: unknown): Promise<{ iss: string; sub: string; email?: string; email_verified?: boolean; tenant: string | null }> {
    const ti = this.opts.trustedIssuers.find((t) => t.issuer === iss);
    if (!ti) throw new OAuthError("invalid_grant", `subject_token issuer '${String(iss)}' is not trusted`);
    let client = this.jwks.get(ti.jwks_uri);
    if (!client) { client = new JwksClient(ti.jwks_uri); this.jwks.set(ti.jwks_uri, client); }
    const p = await verifyJwt(token, (h) => client!.getKey(h.kid), { issuer: ti.issuer, audience: ti.audience });
    if (!p.sub) throw new OAuthError("invalid_grant", "subject_token has no sub");
    const tenant = ti.tenant_claim ? (p[ti.tenant_claim] as string | undefined) ?? null : null;
    return { iss: ti.issuer, sub: p.sub, email: p.email as string | undefined, email_verified: p.email_verified as boolean | undefined, tenant };
  }

  private ownKey = (): KeyObject => {
    return createPublicFromSigning(this.opts.key);
  };

  /** Requested capability must be a subset of what the agent (and, when nested, the parent token) holds. */
  private resolveAuthorizationDetails(raw: string | null, agent: AgentRecord, resource: string, parent?: JwtPayload): AuthorizationDetail[] {
    const parentDetails = (parent?.authorization_details as AuthorizationDetail[] | undefined)?.filter((d) => d.type === "mandat_tool_call");
    let requested: AuthorizationDetail[];
    if (raw) {
      try { requested = JSON.parse(raw); } catch { throw new OAuthError("invalid_authorization_details", "authorization_details must be a JSON array"); }
      if (!Array.isArray(requested) || !requested.length) throw new OAuthError("invalid_authorization_details", "authorization_details must be a non-empty JSON array");
    } else if (parentDetails?.length) {
      requested = parentDetails.map((d) => ({ ...d, tools: d.tools?.filter((t) => agent.allowed_tools.some((p) => globMatch(p, t))) }));
    } else {
      requested = [{ type: "mandat_tool_call", tools: agent.allowed_tools }];
    }
    return requested.map((d) => {
      if (d.type !== "mandat_tool_call") throw new OAuthError("invalid_authorization_details", `Unsupported authorization_details type '${d.type}'`);
      const tools = d.tools ?? agent.allowed_tools;
      for (const t of tools) {
        if (!agent.allowed_tools.some((p) => p === t || (p.includes("*") && globMatch(p, t))))
          throw new OAuthError("invalid_authorization_details", `Agent '${agent.id}' may not be delegated tool '${t}'`);
        if (parentDetails && !parentDetails.some((pd) => !pd.tools || pd.tools.some((p) => p === t || globMatch(p, t))))
          throw new OAuthError("invalid_authorization_details", `Tool '${t}' exceeds the parent token's capability`);
      }
      // Narrowing only: inherit every parent limit; a child limit can only tighten it.
      const limits = { ...(d.limits ?? {}) };
      for (const pd of parentDetails ?? []) {
        for (const [k, pl] of Object.entries(pd.limits ?? {})) {
          const cl = limits[k] ?? {};
          limits[k] = {
            ...pl, ...cl,
            ...(pl.max !== undefined ? { max: Math.min(pl.max, cl.max ?? Infinity) } : {}),
            ...(pl.min !== undefined ? { min: Math.max(pl.min, cl.min ?? -Infinity) } : {}),
            ...(pl.enum !== undefined ? { enum: pl.enum.filter((v) => !cl.enum || cl.enum.includes(v)) } : {}),
            ...(pl.equals !== undefined ? { equals: pl.equals } : {}),
          };
        }
      }
      const out: AuthorizationDetail = { type: "mandat_tool_call", tools, locations: [resource] };
      if (Object.keys(limits).length) out.limits = limits;
      return out;
    });
  }
}

const pubCache = new WeakMap<SigningKey, KeyObject>();
function createPublicFromSigning(k: SigningKey): KeyObject {
  let p = pubCache.get(k);
  if (!p) { p = createPublicKey(k.privateKey); pubCache.set(k, p); }
  return p;
}
