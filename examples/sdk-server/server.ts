// Official-SDK MCP server protected by Mandat. Start `mandat serve` first (same folder), then:
//   node examples/sdk-server/server.ts
// Env: MANDAT_URL, MANDAT_SERVICE_KEY, MCP_PORT (default 7402).

import { existsSync, readFileSync } from "node:fs";
import { createGuard } from "../../src/index.ts";
import { startSdkServer } from "./app.ts";

const creds = existsSync(".mandat/credentials.json") ? JSON.parse(readFileSync(".mandat/credentials.json", "utf8")) : null;
const port = Number(process.env.MCP_PORT ?? 7402);
const guard = await createGuard({
  resource: `http://127.0.0.1:${port}/mcp`,
  controlPlane: process.env.MANDAT_URL ?? creds?.url ?? "http://127.0.0.1:7400",
  apiKey: process.env.MANDAT_SERVICE_KEY ?? creds?.keys?.service,
  source: "acme-support-sdk",
  approvalWaitMs: 15_000,
});
await startSdkServer({ guard, port });
console.log(`Acme Support (official MCP SDK, protected by Mandat) at http://127.0.0.1:${port}/mcp`);
