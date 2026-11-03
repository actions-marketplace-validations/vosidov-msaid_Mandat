// Public API of the `mandat` package.

import { join } from "node:path";
import { Guard, type GuardOptions } from "./guard/guard.ts";
import { FilePolicy, HttpLedgerSink, RemoteApprovalBroker, RemotePolicy, RemoteRevocations } from "./guard/remote.ts";
import { FileLedger } from "./ledger/ledger.ts";

export * from "./policy/engine.ts";
export { compileExpr, ExprError } from "./policy/expr.ts";
export * from "./guard/guard.ts";
export * from "./guard/pinning.ts";
export * from "./guard/remote.ts";
export * from "./mcp/server.ts";
export { protect } from "./mcp/protect.ts";
export * from "./sts/sts.ts";
export * from "./sts/jwt.ts";
export * from "./sts/revocation.ts";
export * from "./ledger/ledger.ts";
export * from "./ledger/redact.ts";
export * from "./ledger/export.ts";
export * from "./ledger/report.ts";
export * from "./approvals/approvals.ts";
export * from "./scan/findings.ts";
export { scanRemote } from "./scan/remote.ts";
export { scanConfigFile, scanServers, scanSource } from "./scan/static.ts";
export { createControlPlane, type ControlPlane } from "./controlplane/server.ts";
export { loadConfig, hashApiKey, type ControlPlaneConfig } from "./controlplane/config.ts";
export { Bridge, type BridgeOptions } from "./bridge.ts";
export { exchangeToken, devLogin, McpHttpClient, type ExchangeOptions, type TaskToken } from "./client.ts";

export interface CreateGuardOptions extends Partial<Pick<GuardOptions, "mode" | "approvalWaitMs" | "pinning" | "redaction" | "source" | "log">> {
  /** Canonical URL of the protected MCP server (token audience). */
  resource: string;
  /** Mandat control plane base URL. */
  controlPlane: string;
  /** Control plane API key with the `service` role. */
  apiKey: string;
  /** Use a local policy file (hot-reloaded) instead of the control plane's policy. */
  policyFile?: string;
  /** Directory for the policy snapshot and optional local ledger copy. Default ".mandat". */
  dataDir?: string;
  /** Also keep a local hash-chained copy of this guard's records. */
  localLedger?: boolean;
}

/**
 * Creates a Guard wired to a Mandat control plane: JWKS + issuer discovered from AS metadata,
 * revocations polled every 2 s, policy pulled with an offline snapshot, approvals and ledger over HTTP.
 */
export async function createGuard(o: CreateGuardOptions): Promise<Guard> {
  const cp = { url: o.controlPlane, apiKey: o.apiKey };
  const dataDir = o.dataDir ?? ".mandat";
  const meta = await fetch(`${o.controlPlane.replace(/\/$/, "")}/.well-known/oauth-authorization-server`, { signal: AbortSignal.timeout(5000) })
    .then((r) => (r.ok ? (r.json() as Promise<{ issuer: string; jwks_uri: string }>) : null))
    .catch(() => null);
  const issuer = meta?.issuer ?? o.controlPlane.replace(/\/$/, "");

  const revocations = new RemoteRevocations(cp);
  await revocations.refresh();

  let policy;
  if (o.policyFile) {
    policy = new FilePolicy(o.policyFile);
  } else {
    const rp = new RemotePolicy(cp, { snapshotPath: join(dataDir, "policy.snapshot.json") });
    await rp.refresh();
    rp.current(); // throws if neither control plane nor snapshot is available
    policy = rp;
  }

  return new Guard({
    resource: o.resource,
    issuer,
    jwksUri: meta?.jwks_uri,
    policy,
    revocations,
    approvals: new RemoteApprovalBroker(cp),
    ledger: new HttpLedgerSink(cp, { local: o.localLedger ? new FileLedger(join(dataDir, "guard-ledger.jsonl")) : undefined }),
    mode: o.mode,
    approvalWaitMs: o.approvalWaitMs,
    pinning: o.pinning,
    redaction: o.redaction,
    source: o.source,
    log: o.log,
  });
}
