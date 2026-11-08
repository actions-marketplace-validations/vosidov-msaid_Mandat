// Minimal JWS/JWT (RFC 7515/7519) on node:crypto. Asymmetric algorithms only: ES256, RS256, PS256, EdDSA.
// "none" and HMAC are rejected so a public key can never be abused as a shared secret.

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject, type JsonWebKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { nowSeconds, sha256, canonicalJson } from "../util.ts";

export type Alg = "ES256" | "RS256" | "PS256" | "EdDSA";
const ALGS: Alg[] = ["ES256", "RS256", "PS256", "EdDSA"];

export interface JwtHeader { alg: string; kid?: string; typ?: string }
export type JwtPayload = Record<string, unknown> & {
  iss?: string; sub?: string; aud?: string | string[]; exp?: number; iat?: number; nbf?: number; jti?: string;
};

export interface SigningKey { kid: string; alg: Alg; privateKey: KeyObject; publicJwk: JsonWebKey & { kid: string; alg: Alg; use: "sig" } }

export class JwtError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");

function algParams(alg: Alg): { hash: string | null; opts: Record<string, unknown> } {
  switch (alg) {
    case "ES256": return { hash: "sha256", opts: { dsaEncoding: "ieee-p1363" } };
    case "RS256": return { hash: "sha256", opts: {} };
    case "PS256": return { hash: "sha256", opts: { padding: 6 /* RSA_PKCS1_PSS_PADDING */, saltLength: 32 } };
    case "EdDSA": return { hash: null, opts: {} };
  }
}

export function signJwt(payload: JwtPayload, key: SigningKey, typ = "JWT"): string {
  const header: JwtHeader = { alg: key.alg, kid: key.kid, typ };
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const { hash, opts } = algParams(key.alg);
  const sig = sign(hash, Buffer.from(input), { key: key.privateKey, ...opts } as never);
  return `${input}.${b64u(sig)}`;
}

export function decodeJwt(token: string): { header: JwtHeader; payload: JwtPayload; signingInput: string; signature: Buffer } {
  if (typeof token !== "string" || token.length > 16_384) throw new JwtError("malformed", "Token missing or too large");
  const parts = token.split(".");
  if (parts.length !== 3) throw new JwtError("malformed", "Token is not a compact JWS");
  try {
    return {
      header: JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")),
      payload: JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: Buffer.from(parts[2]!, "base64url"),
    };
  } catch {
    throw new JwtError("malformed", "Token segments are not valid base64url JSON");
  }
}

export type KeyResolver = (header: JwtHeader, payload: JwtPayload) => Promise<KeyObject | null> | KeyObject | null;

export interface VerifyOptions {
  issuer?: string | string[];
  audience?: string | string[];
  clockToleranceSec?: number;
  requireExp?: boolean;
  maxTokenAgeSec?: number;
  typ?: string;
}

export async function verifyJwt(token: string, resolveKey: KeyResolver, opts: VerifyOptions = {}): Promise<JwtPayload> {
  const { header, payload, signingInput, signature } = decodeJwt(token);
  if (!ALGS.includes(header.alg as Alg)) throw new JwtError("bad_alg", `Algorithm '${header.alg}' is not allowed`);
  if (opts.typ && header.typ && header.typ.toLowerCase() !== opts.typ.toLowerCase())
    throw new JwtError("bad_typ", `Unexpected token type '${header.typ}'`);
  const key = await resolveKey(header, payload);
  if (!key) throw new JwtError("unknown_key", `No key for kid '${header.kid ?? "(none)"}'`);
  if (!keyMatchesAlg(key, header.alg as Alg)) throw new JwtError("bad_alg", "Key type does not match algorithm");
  const { hash, opts: vopts } = algParams(header.alg as Alg);
  const ok = verify(hash, Buffer.from(signingInput), { key, ...vopts } as never, signature);
  if (!ok) throw new JwtError("bad_signature", "Signature verification failed");

  const now = nowSeconds();
  const skew = opts.clockToleranceSec ?? 30;
  if (payload.exp === undefined && opts.requireExp !== false) throw new JwtError("no_exp", "Token has no exp");
  if (typeof payload.exp === "number" && now > payload.exp + skew) throw new JwtError("expired", "Token expired");
  if (typeof payload.nbf === "number" && now + skew < payload.nbf) throw new JwtError("not_yet_valid", "Token not yet valid");
  if (opts.maxTokenAgeSec && typeof payload.iat === "number" && now - payload.iat > opts.maxTokenAgeSec + skew)
    throw new JwtError("too_old", "Token too old");
  if (opts.issuer) {
    const iss = Array.isArray(opts.issuer) ? opts.issuer : [opts.issuer];
    if (!payload.iss || !iss.includes(payload.iss)) throw new JwtError("bad_iss", `Unexpected issuer '${payload.iss}'`);
  }
  if (opts.audience) {
    const want = Array.isArray(opts.audience) ? opts.audience : [opts.audience];
    const got = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
    if (!got.some((a) => want.includes(a))) throw new JwtError("bad_aud", `Token audience ${JSON.stringify(payload.aud)} is not for this resource`);
  }
  return payload;
}

function keyMatchesAlg(key: KeyObject, alg: Alg): boolean {
  const t = key.asymmetricKeyType;
  if (alg === "ES256") return t === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1";
  if (alg === "RS256" || alg === "PS256") return t === "rsa" || t === "rsa-pss";
  return t === "ed25519";
}

// ---------- keys ----------

export function jwkThumbprint(jwk: JsonWebKey): string {
  // RFC 7638 required members only.
  const members = jwk.kty === "EC" ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
    : jwk.kty === "RSA" ? { e: jwk.e, kty: jwk.kty, n: jwk.n }
    : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return Buffer.from(sha256(canonicalJson(members)), "hex").toString("base64url");
}

export function signingKeyFromPem(pem: string): SigningKey {
  const privateKey = createPrivateKey(pem);
  const pub = createPublicKey(privateKey).export({ format: "jwk" });
  const alg: Alg = pub.kty === "EC" ? "ES256" : pub.kty === "OKP" ? "EdDSA" : "RS256";
  const kid = jwkThumbprint(pub);
  return { kid, alg, privateKey, publicJwk: { ...pub, kid, alg, use: "sig" } };
}

/** Loads the ES256 signing key from `dir/signing-key.pem`, creating it (mode 0600) on first run. */
export function loadOrCreateSigningKey(dir: string): SigningKey {
  const path = join(dir, "signing-key.pem");
  if (!existsSync(path)) {
    mkdirSync(dir, { recursive: true });
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    writeFileSync(path, privateKey.export({ format: "pem", type: "pkcs8" }) as string, { mode: 0o600 });
  }
  return signingKeyFromPem(readFileSync(path, "utf8"));
}

export function publicKeyFromJwk(jwk: JsonWebKey): KeyObject {
  return createPublicKey({ key: jwk, format: "jwk" });
}

/** Caches a remote JWKS; refetches on unknown kid at most once per `minRefreshMs`. */
export class JwksClient {
  private keys = new Map<string, KeyObject>();
  private fetchedAt = 0;
  private inflight: Promise<void> | null = null;
  readonly url: string;
  private ttlMs: number;
  private minRefreshMs: number;

  constructor(url: string, ttlMs = 10 * 60_000, minRefreshMs = 30_000) {
    this.url = url;
    this.ttlMs = ttlMs;
    this.minRefreshMs = minRefreshMs;
  }

  async getKey(kid: string | undefined): Promise<KeyObject | null> {
    const fresh = Date.now() - this.fetchedAt < this.ttlMs;
    if (!fresh || (kid && !this.keys.has(kid) && Date.now() - this.fetchedAt > this.minRefreshMs)) {
      // An outage must not reject tokens the cached keys can still check: retry later instead.
      await this.refresh().catch((e: unknown) => {
        if (!this.keys.size) throw e;
        this.fetchedAt = Date.now() - this.ttlMs + this.minRefreshMs;
      });
    }
    if (kid) return this.keys.get(kid) ?? null;
    return this.keys.size === 1 ? [...this.keys.values()][0]! : null;
  }

  private refresh(): Promise<void> {
    if (!this.inflight) {
      const run = async () => {
        const res = await fetch(this.url, { signal: AbortSignal.timeout(5000) });
        if (!res.ok) throw new Error(`JWKS ${this.url} returned ${res.status}`);
        const body = (await res.json()) as { keys?: JsonWebKey[] };
        const next = new Map<string, KeyObject>();
        for (const jwk of body.keys ?? []) {
          if ((jwk as { use?: string }).use && (jwk as { use?: string }).use !== "sig") continue;
          const kid = (jwk as { kid?: string }).kid ?? jwkThumbprint(jwk);
          try { next.set(kid, publicKeyFromJwk(jwk)); } catch { /* skip unsupported key */ }
        }
        this.keys = next;
        this.fetchedAt = Date.now();
      };
      this.inflight = run().finally(() => { this.inflight = null; });
    }
    return this.inflight;
  }
}
