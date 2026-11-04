# Protect an MCP server

A **guard** runs inside your MCP server and checks every tool call:
1. the agent's task token (signature, issuer, audience = your server, expiry, revocation);
2. the policy, including the call's arguments;
3. human approval when the policy asks for it.

It writes one audit record per call. The guard talks to the [control plane](control-plane.md) for keys, revocations, policy, approvals and the ledger. Decisions themselves are made in-process in microseconds.

You need a running control plane (`mandat serve`) and an API key with the `service` role (in `.mandat/credentials.json` after `mandat init`).

## TypeScript, with the official MCP SDK

```ts
import { createGuard, protect } from "mandat";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

const guard = await createGuard({
  resource: "https://mcp.example.com/mcp",          // token audience: this server's URL
  controlPlane: process.env.MANDAT_URL!,
  apiKey: process.env.MANDAT_SERVICE_KEY!,          // role: service
  pinning: { lockfile: "mandat.lock.json", mode: "block" },
});

const server = protect(new McpServer({ name: "billing", version: "1.0.0" }), guard); // register tools after this

app.get("/.well-known/oauth-protected-resource/mcp", (_q, r) => r.json(guard.protectedResourceMetadata()));
app.use("/mcp", requireBearerAuth({
  verifier: guard.sdkTokenVerifier({ InvalidTokenError }),
  resourceMetadataUrl: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
  expectedResource: new URL("https://mcp.example.com/mcp"),
}));
```

- **`protect()`** wraps every `registerTool` with policy, approvals, session taint, tool pinning and audit.
- **Denied calls** return `isError: true` with Mandat's decision in `_meta["mandat/decision"]`, so the agent sees why.
- **Calls that need approval** wait up to `approvalWaitMs` (default 20 s) for a human. After that, the agent is told to retry the same call once it's approved.

A complete server is in [`examples/sdk-server`](../examples/sdk-server). It uses `McpServer`, the session transport, express and `requireBearerAuth`; Mandat adds three lines, marked `← Mandat`. Run it from a clone next to `mandat serve` with `npm run demo:sdk-server`.

It has been tested with `@modelcontextprotocol/sdk` 1.32.1 (server and `Client`) and MCP Inspector 2.11.0. The SDK supports MCP up to revision 2025-11-25.

## TypeScript, without dependencies

Mandat's built-in Streamable HTTP server already includes the guard, the discovery metadata and the 401 challenge:

```ts
import { createGuard, McpHttpServer } from "mandat";

const guard = await createGuard({ resource: "http://127.0.0.1:7401/mcp", controlPlane: MANDAT_URL, apiKey: SERVICE_KEY });
await new McpHttpServer({ name: "acme", version: "1.0.0", guard, tools: [/* { name, description, inputSchema, handler } */] }).listen(7401);
```

See [`examples/refund-server`](../examples/refund-server). It supports MCP revisions 2025-03-26 up to 2026-07-28.

## Python

```bash
pip install "mandat[mcp]"
```

```python
from mcp.server.mcpserver import MCPServer
from mandat import create_guard
from mandat.mcp import auth_settings, protect, token_verifier

guard = await create_guard(resource="https://mcp.example.com/mcp", control_plane=MANDAT_URL, api_key=SERVICE_KEY)
server = MCPServer("billing", token_verifier=token_verifier(guard), auth=auth_settings(guard))
protect(server, guard)   # register tools after this
```

The full guide is in [`python/README.md`](../python/README.md). Both SDKs decide identically: they replay the same conformance suite, [`spec/conformance/policy.json`](../spec/conformance/policy.json).

## Classify your tools

Tell the policy what each tool does: `risk` and `taints` in [the policy](policies.md). `financial` and `destructive` tools fail closed when the control plane is unreachable. Tools that return untrusted content (e-mail, web pages, tickets) should set `taints: true`, so rules can block exfiltration after a prompt injection.
