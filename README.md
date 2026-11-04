# Mandat

**Authorization, delegation and audit for AI agent actions. MCP first.**

[![ci](https://github.com/vosidov-msaid/Mandat/actions/workflows/ci.yml/badge.svg)](https://github.com/vosidov-msaid/Mandat/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/mandat)](https://www.npmjs.com/package/mandat)
[![PyPI](https://img.shields.io/pypi/v/mandat)](https://pypi.org/project/mandat/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

When an AI agent calls a tool, Mandat answers three questions:

1. **May it?** A policy is checked on every call, including its arguments: `refund ≤ €50 → allow · €50–500 → ask a human · > €500 → deny`.
2. **On whose behalf?** Agents get short-lived, single-task tokens that carry the whole chain: `human → agent → sub-agent`.
3. **What happened?** Every call leaves one tamper-evident audit record, exportable to your SIEM and summarised in an auditor report.

It also ships a **scanner** for the authentication and supply-chain mistakes common in MCP servers and client configs.

**→ Scan your MCP server now: [scan.themandat.xyz](https://scan.themandat.xyz)**

## Install

```bash
npm install -g mandat          # CLI: control plane, scanner, agent bridge (Node ≥ 20)
npm install mandat             # TypeScript library for your MCP server
pip install "mandat[mcp]"      # Python library for MCP servers built with the official mcp SDK (Python ≥ 3.10)
```

No runtime dependencies in the npm package, no install scripts. Releases are built in CI with provenance and approved by a maintainer.

## Five-minute start

**Scan a server or your MCP client config:**

```bash
npx mandat scan https://mcp.example.com/mcp        # authentication, OAuth discovery, PKCE, CORS, tool poisoning
npx mandat scan-config                             # Claude Desktop, Cursor, VS Code … configs: unpinned packages, secrets, shell commands
```

**See the whole thing work** (from a clone; Node ≥ 23.6, no install needed):

```bash
git clone https://github.com/vosidov-msaid/Mandat.git && cd Mandat
node examples/demo.ts
```

The demo plays out a support agent working for "Maria":
- a €20 refund is allowed; a €120 refund waits for a human; a €900 refund is denied;
- after the agent reads an e-mail containing a prompt injection, sending data to an outside address is blocked;
- a sub-agent gets a narrower mandate (refunds up to €30 only);
- a kill switch locks the agent out in under a second;
- editing one past audit record is detected.

**Protect your own MCP server** (TypeScript, official SDK):

```ts
import { createGuard, protect } from "mandat";

const guard = await createGuard({ resource: "https://mcp.example.com/mcp", controlPlane: MANDAT_URL, apiKey: SERVICE_KEY });
const server = protect(new McpServer({ name: "billing", version: "1.0.0" }), guard);   // policy + audit on every tool
```

Python works the same way with `protect(MCPServer(...), guard)`. See the guides below.

## Guides

| Guide | What it covers |
|---|---|
| [Scanner](docs/scanner.md) | `mandat scan`, `scan-config`, tool pinning, the scanner web page, GitHub Action, deploying on Fly.io |
| [Protect an MCP server](docs/protect-a-server.md) | TypeScript (official SDK or built-in server) and [Python](python/README.md) |
| [Connect agents](docs/agents.md) | Claude Code, Codex, Cursor, Claude Desktop through `mandat bridge` |
| [Run the control plane](docs/control-plane.md) | Setup, agents, approvals (Slack, webhooks), kill switch, audit ledger, SIEM export |
| [Identity](docs/identity.md) | Real users and approvers with Auth0, Okta, Entra ID or Keycloak |
| [Policies](docs/policies.md) | The policy language, decision rules, testing and shadow mode |
| [Architecture and security](docs/architecture.md) | How the pieces fit, threat model, known limitations |

## Project

- [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)
- License: [Apache-2.0](LICENSE)
