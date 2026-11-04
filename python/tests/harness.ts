// Test harness: runs the real (TypeScript) Mandat control plane for the Python end-to-end tests.
//   node tests/harness.ts <resource-url>
// Prints one JSON line with URLs and keys, then runs until stdin closes.
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createControlPlane, hashApiKey } from "../../src/index.ts";
import { STARTER_POLICY } from "../../src/cli/templates.ts";

const resource = process.argv[2]!;
const port = await new Promise<number>((r) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => r(p)); }); });
const dir = mkdtempSync(join(tmpdir(), "mandat-py-e2e-"));
writeFileSync(join(dir, "policy.json"), JSON.stringify(STARTER_POLICY));
const keys = { admin: "mdt_admin_python_e2e_0000000000", service: "mdt_service_python_e2e_00000000" };
const issuer = `http://127.0.0.1:${port}`;
const cp = createControlPlane({
  issuer, port, dataDir: join(dir, "data"), policyFile: join(dir, "policy.json"), devIdp: true,
  apiKeys: [{ id: "admin", hash: hashApiKey(keys.admin), roles: ["admin", "approver", "auditor"] }, { id: "py-guard", hash: hashApiKey(keys.service), roles: ["service"] }],
  approvals: { log: false },
});
await cp.listen();
const reg = await (await fetch(`${issuer}/api/agents`, {
  method: "POST", headers: { authorization: `Bearer ${keys.admin}`, "content-type": "application/json" },
  body: JSON.stringify({ id: "py-agent", allowed_tools: ["lookup_*", "refund", "read_inbox", "send_email"], allowed_resources: [resource] }),
})).json();
process.stdout.write(JSON.stringify({ issuer, admin: keys.admin, service: keys.service, agent: "py-agent", secret: reg.client_secret }) + "\n");
process.stdin.resume();
process.stdin.on("end", () => { void cp.close().then(() => process.exit(0)); });
