// Revocation model shared by the control plane (source of truth) and the Guard (enforcement).
//
// A revocation invalidates every matching token issued at or before `issued_before`, and while
// `blocks_issuance` is true the STS refuses to mint new tokens for the match (kill-switch).

import type { JwtPayload } from "./jwt.ts";

export type RevocationType = "jti" | "agent" | "agent_version" | "subject" | "task" | "tenant";

export interface Revocation {
  id: string;
  type: RevocationType;
  /** jti / agent id / user sub / task id / tenant id */
  value: string;
  /** For type "agent_version". */
  version?: string;
  issued_before: number;
  blocks_issuance: boolean;
  created_at: string;
  reason?: string;
  by?: string;
}

/** Shape of the Mandat-specific claim inside task tokens. */
export interface MandatClaim {
  agent_version?: string | null;
  prompt_hash?: string | null;
  task_id?: string | null;
  tenant?: string | null;
  session_id?: string | null;
}

export interface ActClaim { sub: string; client_id?: string; mandat_agent_version?: string | null; act?: ActClaim }

/** Flattens the nested RFC 8693 `act` claim: [current actor, previous actor, ...]. */
export function actorChain(claims: JwtPayload): ActClaim[] {
  const out: ActClaim[] = [];
  let a = claims.act as ActClaim | undefined;
  while (a && out.length < 16) {
    out.push(a);
    a = a.act;
  }
  return out;
}

export function matchRevocation(claims: JwtPayload, revs: Iterable<Revocation>): Revocation | null {
  const iat = typeof claims.iat === "number" ? claims.iat : 0;
  const m = (claims.mandat ?? {}) as MandatClaim;
  const chain = actorChain(claims);
  for (const r of revs) {
    if (iat > r.issued_before) continue;
    if (matches(r, claims.jti, claims.sub, m, chain)) return r;
  }
  return null;
}

export function blocksIssuance(revs: Iterable<Revocation>, q: { agent: string; version?: string | null; sub?: string; tenant?: string | null }): Revocation | null {
  for (const r of revs) {
    if (!r.blocks_issuance) continue;
    if (r.type === "agent" && r.value === q.agent) return r;
    if (r.type === "agent_version" && r.value === q.agent && r.version === q.version) return r;
    if (r.type === "subject" && r.value === q.sub) return r;
    if (r.type === "tenant" && q.tenant && r.value === q.tenant) return r;
  }
  return null;
}

function matches(r: Revocation, jti: unknown, sub: unknown, m: MandatClaim, chain: ActClaim[]): boolean {
  switch (r.type) {
    case "jti": return jti === r.value;
    case "subject": return sub === r.value;
    case "task": return m.task_id === r.value;
    case "tenant": return m.tenant === r.value;
    case "agent": return chain.some((a) => a.sub === r.value);
    case "agent_version":
      return chain.some((a, i) => a.sub === r.value && (i === 0 ? (a.mandat_agent_version ?? m.agent_version) : a.mandat_agent_version) === r.version);
  }
}
