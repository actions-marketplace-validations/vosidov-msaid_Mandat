import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { signingKeyFromPem, signJwt, type SigningKey } from "../src/sts/jwt.ts";
import { compilePolicy, type PolicyDocument } from "../src/policy/engine.ts";
import { Guard, LocalApprovalBroker, LocalRevocations, StaticPolicy, type GuardOptions } from "../src/guard/guard.ts";
import { ApprovalService } from "../src/approvals/approvals.ts";
import { MemoryLedger } from "../src/ledger/ledger.ts";
import type { Revocation } from "../src/sts/revocation.ts";
import { nowSeconds } from "../src/util.ts";

export const ISSUER = "https://mandat.test";
export const RESOURCE = "https://mcp.test/mcp";

export function testKey(): SigningKey {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return signingKeyFromPem(privateKey.export({ format: "pem", type: "pkcs8" }) as string);
}

export function taskToken(key: SigningKey, over: Record<string, unknown> = {}): string {
  const now = nowSeconds();
  return signJwt({
    iss: ISSUER, sub: "user:maria", aud: RESOURCE, iat: now, nbf: now, exp: now + 300, jti: "tok_" + Math.random().toString(36).slice(2),
    act: { sub: "support-bot", mandat_agent_version: "1.0.0" },
    mandat: { task_id: "task-1", tenant: "acme", agent_version: "1.0.0" },
    email: "maria@acme.test",
    ...over,
  }, key, "at+jwt");
}

export function embeddedGuard(policy: PolicyDocument, extra: Partial<GuardOptions> = {}) {
  const key = testKey();
  const revocations: Revocation[] = [];
  const ledger = new MemoryLedger();
  const approvals = new ApprovalService({ path: null, ledger });
  const guard = new Guard({
    resource: RESOURCE,
    issuer: ISSUER,
    publicKey: createPublicKey(key.privateKey),
    policy: new StaticPolicy(compilePolicy(policy)),
    revocations: new LocalRevocations(() => revocations),
    approvals: new LocalApprovalBroker(approvals),
    ledger,
    approvalWaitMs: 0,
    log: () => {},
    ...extra,
  });
  return { guard, key, revocations, ledger, approvals, close: () => approvals.close() };
}

export const REFUND_POLICY: PolicyDocument = {
  version: 1,
  tools: { refund: { risk: "financial" }, read_inbox: { risk: "read", taints: true }, send_email: { risk: "external_comm", redact: ["body"] }, lookup: { risk: "read" } },
  rules: [
    { id: "lookup", tool: "lookup", effect: "allow" },
    { id: "inbox", tool: "read_inbox", effect: "allow" },
    { id: "refund-auto", tool: "refund", when: "args.amount <= 50", effect: "allow" },
    { id: "refund-approval", tool: "refund", when: "args.amount > 50 && args.amount <= 500", effect: "require_approval", approval: { approvers: 1, timeout: "5m" } },
    { id: "refund-deny", tool: "refund", when: "args.amount > 500", effect: "deny", reason: "too much" },
    { id: "email", tool: "send_email", effect: "allow" },
    { id: "no-exfil", tool: "send_email", when: "session.tainted && !args.to.endsWith('@acme.test')", effect: "deny", reason: "tainted" },
  ],
};
