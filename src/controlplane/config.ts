import { dirname, isAbsolute, resolve } from "node:path";
import type { TrustedIssuer } from "../sts/sts.ts";
import type { RedactionOptions } from "../ledger/redact.ts";
import { interpolateEnv, readJson, sha256 } from "../util.ts";

export type Role = "admin" | "approver" | "auditor" | "service";
export const ROLES: Role[] = ["admin", "approver", "auditor", "service"];

export interface ApiKeyEntry {
  /** Identity recorded in the ledger (e.g. "alice", "refund-mcp"). */
  id: string;
  /** "sha256:<hex>" of the key. */
  hash: string;
  roles: Role[];
}

export interface ControlPlaneConfig {
  /** Public base URL; also the token issuer. */
  issuer: string;
  port: number;
  host?: string;
  dataDir: string;
  policyFile: string;
  devIdp?: boolean;
  tokenTtlSeconds?: number;
  maxTokenTtlSeconds?: number;
  trustedIssuers?: TrustedIssuer[];
  apiKeys: ApiKeyEntry[];
  approvals?: {
    defaultTimeout?: string;
    log?: boolean;
    slack?: { webhookUrl: string; signingSecret?: string };
    webhooks?: Array<{ name?: string; url: string; secret: string }>;
  };
  ledger?: {
    retentionDays?: number;
    otlp?: { endpoint: string; headers?: Record<string, string> };
    redaction?: RedactionOptions;
  };
}

export function hashApiKey(key: string): string {
  return "sha256:" + sha256(key);
}

/** Loads a config file, expands ${env:VAR}, resolves relative paths against the file's directory. */
export function loadConfig(path: string): ControlPlaneConfig {
  const raw = interpolateEnv(readJson<ControlPlaneConfig>(path));
  const base = dirname(resolve(path));
  const abs = (p: string) => (isAbsolute(p) ? p : resolve(base, p));
  const cfg: ControlPlaneConfig = {
    host: "127.0.0.1",
    tokenTtlSeconds: 300,
    maxTokenTtlSeconds: 900,
    trustedIssuers: [],
    ...raw,
    dataDir: abs(raw.dataDir ?? ".mandat"),
    policyFile: abs(raw.policyFile ?? "mandat.policy.json"),
  };
  if (!cfg.issuer) throw new Error("config: `issuer` is required");
  if (!cfg.apiKeys?.length) throw new Error("config: at least one entry in `apiKeys` is required");
  for (const k of cfg.apiKeys) {
    if (!k.hash?.startsWith("sha256:")) throw new Error(`config: apiKeys[${k.id}].hash must be "sha256:<hex>"`);
    for (const r of k.roles) if (!ROLES.includes(r)) throw new Error(`config: apiKeys[${k.id}] unknown role '${r}'`);
  }
  return cfg;
}
