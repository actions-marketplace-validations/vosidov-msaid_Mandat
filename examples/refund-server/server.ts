// Standalone protected MCP server. Run `mandat init && mandat serve` first (same directory), then:
//   node examples/refund-server/server.ts
// Env: MANDAT_URL, MANDAT_SERVICE_KEY, MCP_PORT (default 7401).

import { existsSync, readFileSync } from "node:fs";
import { createGuard, McpHttpServer } from "../../src/index.ts";
import { tools } from "./tools.ts";

const creds = existsSync(".mandat/credentials.json") ? JSON.parse(readFileSync(".mandat/credentials.json", "utf8")) : null;
const controlPlane = process.env.MANDAT_URL ?? creds?.url ?? "http://127.0.0.1:7400";
const apiKey = process.env.MANDAT_SERVICE_KEY ?? creds?.keys?.service;
if (!apiKey) throw new Error("Set MANDAT_SERVICE_KEY (service role API key) or run in a directory initialised with `mandat init`.");
const port = Number(process.env.MCP_PORT ?? 7401);
const resource = `http://127.0.0.1:${port}/mcp`;

const guard = await createGuard({
  resource,
  controlPlane,
  apiKey,
  source: "acme-support-mcp",
  approvalWaitMs: 15_000,
  pinning: { lockfile: "mandat.lock.json", mode: "block" },
});

const server = new McpHttpServer({ name: "acme-support", version: "1.0.0", guard, tools });
await server.listen(port);
console.log(`Acme Support MCP server (protected by Mandat) at ${resource}`);
console.log(`  PRM: http://127.0.0.1:${port}/.well-known/oauth-protected-resource/mcp`);
