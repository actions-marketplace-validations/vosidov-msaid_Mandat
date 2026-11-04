# Mandat

**Authorization, delegation and audit for AI agent actions — MCP first.**

Mandat answers three questions about every tool call an AI agent makes:

1. **May it?** A policy is checked on *every* call, including its arguments (`refund ≤ €50 → auto · €50–500 → ask a human · > €500 → deny`).
2. **On whose behalf?** Agents get short-lived, single-task tokens that carry the whole delegation chain: `human → agent → sub-agent` (RFC 8693 `act` and RFC 9396 `authorization_details`).
3. **What happened?** One tamper-evident Action Record per call (hash chain), exportable to a SIEM (OCSF, OpenTelemetry), with a DPO/auditor report.

It also ships a **scanner** that checks MCP servers and client configs for the auth and supply-chain mistakes found in most public MCP servers.

This is the **MVP** (PRD phase 0–3 months, plus the core of delegation from phase 3–6). The spec it implements is in [`specs/rpd.md`](specs/rpd.md).

[![ci](https://github.com/vosidov-msaid/Mandat/actions/workflows/ci.yml/badge.svg)](https://github.com/vosidov-msaid/Mandat/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/mandat)](https://www.npmjs.com/package/mandat)

## Install

```bash
npm install -g mandat        # the `mandat` CLI (control plane, scanner, bridge for agents)
npm install mandat           # the library, inside your MCP server or agent project
npx mandat scan <url>        # or run any command without installing
```

Requires Node ≥ 20. Zero runtime dependencies and no install scripts.

---

## 60-second demo

The demo and the example MCP server live in the repository, not in the npm package:

```bash
git clone https://github.com/vosidov-msaid/Mandat.git && cd Mandat
node examples/demo.ts          # full scenario, then exit (Node ≥ 23.6; no npm install needed)
node examples/demo.ts --keep   # …and keep the console running at the printed URL
```

The demo starts a control plane and a protected "Acme Support" MCP server, then plays out this story:

| Step | What happens | Mandat feature |
|---|---|---|
| Scan | `mandat scan` finds the protected server clean; an anonymous request gets `401` + `resource_metadata` | Scanner, PRM (RFC 9728) |
| Delegate | Maria signs in. `support-bot` exchanges her token for a 5-minute token that covers only 4 tools | STS, RFC 8693 + RAR |
| €20 refund | Allowed automatically | PDP on arguments |
| €120 refund | The agent waits while "Alice" approves, then the call runs | Human approval bound to this exact call |
| €900 refund | Denied by the `refund-limit` rule | Deny overrides |
| `delete_customer` | Denied: the tool is outside the task's delegated capability | Capability in token |
| Prompt injection | After `read_inbox`, e-mail to `archive@exfil.test` is blocked; internal mail still works | Session taint ("lethal trifecta") |
| Sub-agent | `billing-bot` receives a narrower mandate (refund ≤ €30) with a nested `act` chain | Delegation can only narrow |
| Kill switch | `support-bot` and every token it delegated stop working in < 1 s; new tokens are refused | Revocation |
| Audit | The chain verifies. Editing one past record ("€900" → "€9") is detected | Hash-chained ledger |

---

## Quick start (your own setup)

```bash
mandat init                                   # config, starter policy + tests, keys (.mandat/credentials.json)
mandat policy test                            # 7/7 starter decision tests
mandat serve                                  # control plane + console on http://127.0.0.1:7400/console

mandat agents add support-bot --tools "lookup_*,refund,send_email,read_inbox" \
       --resources http://127.0.0.1:7401/mcp --versions 1.4.0     # prints the client secret once
node examples/refund-server/server.ts         # in a clone: protected example MCP server on :7401
```

These commands assume `npm install -g mandat`. Inside a clone of the repo, use `node bin/mandat.ts` instead of `mandat`.

Then, as an agent:

```bash
TOKEN=$(mandat token --agent support-bot --secret <secret> --user user:maria --resource http://127.0.0.1:7401/mcp --version 1.4.0)
curl -s http://127.0.0.1:7401/mcp -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"refund","arguments":{"order_id":"A-1002","amount":150,"currency":"EUR"}}}'
mandat approvals list            # in another terminal
mandat approvals approve apr_…   # the waiting call completes
mandat revoke --agent support-bot --reason "incident 42"
mandat ledger verify && mandat ledger report --retention 365
```

### Protecting your MCP server

With the official TypeScript SDK:

```ts
import { createGuard, protect } from "mandat";

const guard = await createGuard({
  resource: "https://mcp.example.com/mcp",          // token audience
  controlPlane: process.env.MANDAT_URL!,
  apiKey: process.env.MANDAT_SERVICE_KEY!,          // role: service
  pinning: { lockfile: "mandat.lock.json", mode: "block" },
});
const server = protect(new McpServer({ name: "billing", version: "1.0.0" }), guard); // every registerTool is guarded
app.get("/.well-known/oauth-protected-resource/mcp", (_q, r) => r.json(guard.protectedResourceMetadata()));
app.use("/mcp", requireBearerAuth({ verifier: guard.sdkTokenVerifier({ InvalidTokenError }) }));
```

Without dependencies, use the built-in server: `new McpHttpServer({ name, version, guard, tools }).listen(7401)` (see [`examples/refund-server`](examples/refund-server)).

On the agent side, use `exchangeToken()` and `McpHttpClient` from `mandat`.

---

## Connecting real agents (Claude Code, Codex, Cursor, Claude Desktop)

These clients start a browser login when an MCP server answers `401`. Mandat's control plane only does token exchange, not that login flow, so connect them through **`mandat bridge`**. The bridge is a local stdio MCP server: it acts as a registered agent, exchanges the user's identity for 5-minute task tokens, and gets a new one before the old one expires.

```bash
mandat agents add claude-code --tools "lookup_*,refund,read_inbox,send_email,delete_*" --resources http://127.0.0.1:7401/mcp
# → copy the client_secret
```

The examples pin an exact version (`mandat@0.1.1`). Use the version you have reviewed: an unpinned `npx -y` runs whatever is published next, and `mandat scan-config` flags that.

**Claude Code**

```bash
claude mcp add acme -e MANDAT_AGENT_SECRET=<secret> -- \
  npx -y mandat@0.1.1 bridge --url http://127.0.0.1:7401/mcp \
  --mandat http://127.0.0.1:7400 --agent claude-code --user user:maria --email maria@acme.example
```

On Windows, start the command with `cmd /c`: `… -- cmd /c npx -y mandat@0.1.1 bridge …`

Equivalent `.mcp.json` (on Windows: `"command": "cmd"`, and put `"/c", "npx"` at the start of `args`):

```json
{ "mcpServers": { "acme": { "command": "npx",
  "args": ["-y", "mandat@0.1.1", "bridge", "--url", "http://127.0.0.1:7401/mcp", "--mandat", "http://127.0.0.1:7400",
           "--agent", "claude-code", "--user", "user:maria", "--email", "maria@acme.example"],
  "env": { "MANDAT_AGENT_SECRET": "<secret>" } } } }
```

**Codex** (`~/.codex/config.toml`; on Windows use `command = "cmd"` and `args = ["/c", "npx", "-y", …]`)

```toml
[mcp_servers.acme]
command = "npx"
args = ["-y", "mandat@0.1.1", "bridge", "--url", "http://127.0.0.1:7401/mcp", "--mandat", "http://127.0.0.1:7400",
        "--agent", "codex", "--user", "user:maria", "--email", "maria@acme.example"]
env = { MANDAT_AGENT_SECRET = "<secret>" }

# Codex has its own approval gate for MCP tools that aren't read-only. Pass these tools through
# so that Mandat's policy decides (allow / deny / human approval):
[mcp_servers.acme.tools.refund]
approval_mode = "approve"
[mcp_servers.acme.tools.send_email]
approval_mode = "approve"
[mcp_servers.acme.tools.read_inbox]
approval_mode = "approve"
[mcp_servers.acme.tools.delete_customer]
approval_mode = "approve"
```

**Notes**

- **Approvals.** A call that needs approval blocks for up to `approvalWaitMs` (15 s in the example server) while a human approves in the console, Slack or `mandat approvals approve <id>`. If nobody answers in time, the agent gets "approval required (request apr_…). Retry the same call once it is approved", and the approval is honoured when the agent retries the identical call.
- **Real users.** `--user` uses the dev IdP. With a real IdP, put the user's token in `MANDAT_SUBJECT_TOKEN` and configure `trustedIssuers`.
- **Narrower tasks.** Add `--tools a,b` to give a session less than everything the agent is allowed.
- **Tested with:** Claude Code 2.1.302 and codex-cli 0.166.0. Both attributed every call in the ledger; Mandat denied over-limit refunds, blocked exfiltration after a prompt injection, and held mid-size refunds and deletes for human approval.

---

## Real users with Auth0 (or any OIDC provider)

By default, `mandat init` turns on a dev IdP: anyone can claim to be any user. To have agents act for **real, signed-in people**, connect your identity provider. Auth0 is shown here; Okta, Entra ID and Keycloak work the same way, because Mandat only relies on standard OIDC discovery, JWKS and PKCE.

**1. Create an Auth0 application** (Dashboard → Applications → *Create Application*)

- **Type:** *Native*. It's a CLI, so there's no client secret; PKCE protects the login instead.
- **Settings → Allowed Callback URLs:** `http://127.0.0.1:8765/callback`
- **Settings → Advanced → Grant Types:** *Authorization Code* and *Refresh Token* (both on by default for Native apps).
- Copy the **Domain** and **Client ID**. You need at least one user (User Management → Users) or a social connection.

**2. Trust it on the control plane**, then restart `mandat serve`:

```bash
mandat idp add --issuer https://YOUR_DOMAIN/ --client-id YOUR_CLIENT_ID --disable-dev-idp
# Auth0 Organizations: add --tenant-claim org_id
```

**3. Sign in once** (this opens your browser):

```bash
mandat login --issuer https://YOUR_DOMAIN/ --client-id YOUR_CLIENT_ID
mandat login status
```

The session is stored in `~/.mandat/session.json` (mode 0600) and refreshed automatically when Auth0 issues a refresh token. `login status` tells you whether it did.

**4. Let your agent act for you:** in the bridge command, replace `--user …` with `--login`:

```bash
claude mcp add acme -e MANDAT_AGENT_SECRET=<secret> -- \
  npx -y mandat@0.1.1 bridge --url http://127.0.0.1:7401/mcp --mandat http://127.0.0.1:7400 --agent claude-code --login
```

Every call is now attributed to the Auth0 user, for example `principal.sub = "auth0|…"`, with their e-mail and `org_id` as tenant. That identity is what policies, approvals and the ledger see. The STS accepts only ID tokens issued by the trusted tenant **to that client ID**, so tokens issued to your other Auth0 apps are rejected.

---

## Architecture

```
Human (IdP: Okta/Entra/Auth0/Keycloak via JWKS; dev IdP for local use)
   │ ID / access token
   ▼
Agent ──RFC 8693 (sub=user, act=agent) + RAR──▶ Mandat STS ──▶ 5-min task token (aud = one MCP server)
   │
   ▼  MCP (Streamable HTTP)
MCP server + Mandat Guard (PEP + in-process PDP) ◀── policy (ETag poll, offline snapshot) ── Control plane
   │  allow / deny / require_approval ───────── approvals API ──▶ Slack · webhook · console · CLI
   │  revocations (2 s poll) ◀──────────────────────────────────── kill switch
   │  Action Records (async, batched, at-least-once, deduped) ──▶ hash-chained ledger ──▶ OCSF / OTLP
   ▼
Downstream services (the user's token is never forwarded)
```

| Path | What lives there |
|---|---|
| `src/policy/` | Expression language (CEL subset, no `eval`) and the PDP (deny-overrides, fail-closed on errors) |
| `src/sts/` | JWT/JWKS (ES256/RS256/PS256/EdDSA, no `none`/HMAC), token exchange, revocation model |
| `src/guard/` | Guard (PEP), tool pinning, remote clients for the control plane |
| `src/mcp/` | Zero-dep MCP HTTP server with Guard, and the `protect()` adapter for the official SDK |
| `src/approvals/` | Approval service, Slack (Block Kit + signed interactions), signed webhooks |
| `src/ledger/` | Hash chain, PII redaction, OCSF/OTel export, OTLP exporter, compliance report |
| `src/scan/` | Remote scanner and config/source scanner; text/JSON/SARIF/HTML output |
| `src/controlplane/` | HTTP control plane and web console |
| `src/cli/` | `mandat` CLI |

### Decision semantics

- **Deny overrides.** Any matching `deny` wins. Otherwise any `require_approval` wins. Otherwise `allow` (obligations are merged). Otherwise the policy `default` applies, which is `deny`. Rule order doesn't matter.
- **Errors fail closed.** If a condition can't be evaluated (type error, missing data), it counts as a match for `deny`/`require_approval` rules and as no match for `allow` rules.
- **Capability first.** A call outside the token's `authorization_details` (tool, location, argument limits) is denied before any rule runs.
- **Taint.** A tool marked `taints: true` (e-mail, web, tickets) marks the session. Rules can then check `session.tainted`.
- **Approvals.** Each approval is bound to `sha256(user, agent, tool, server, args)` and can be used once. Self-approval is refused, `approvers: 2` means four-eyes, and a timeout means deny.
- **Fail modes.** If revocations can't be refreshed for 15 s, `financial`/`destructive` tools fail closed. Policy keeps working from the last snapshot.
- **Shadow mode** (`mode: "shadow"`) records the decision but never blocks. Use it to roll out new policies.

### Policy language

```jsonc
{
  "version": 1,
  "default": "deny",
  "tools": { "refund": { "risk": "financial" }, "read_inbox": { "risk": "read", "taints": true },
             "send_email": { "risk": "external_comm", "redact": ["body"] } },
  "rules": [
    { "id": "refund-approval", "tool": "refund", "when": "args.amount > 50 && args.amount <= 500",
      "effect": "require_approval", "approval": { "approvers": 1, "timeout": "15m", "channels": ["slack"] } },
    { "id": "no-exfil", "tool": "send_email",
      "when": "session.tainted && !args.to.all(r, r.endsWith('@example.com'))", "effect": "deny" }
  ]
}
```

- **Context:** `principal.{sub,tenant,email,scope}`, `agent.{id,version,prompt_hash}`, `actor_chain[]`, `tool.{name,server,risk}`, `args.*`, `session.{tainted,taint_sources,calls}`, `task.{id,authorization_details}`, `env.{hour_utc,weekday_utc}`.
- **Operators:** `== != < <= > >= in && || ! ?: + - * / %`.
- **Functions:** `size has int double string lower upper abs min max`.
- **Methods:** `startsWith endsWith contains matches size lower upper trim keys`.
- **Macros:** `all exists filter`.
- **Effects:** `allow`, `deny`, `require_approval`, `allow_with_obligations` (obligations: `redact` fields, `annotate` tags).

Tooling: `mandat policy check|test|eval` and `mandat bench`. On this machine the PDP measures p50 ≈ 14 µs and p99 ≈ 70 µs (the PRD targets are 0.5 ms and 5 ms).

---

## PRD coverage

| PRD item | MVP status |
|---|---|
| **US-1** `mandat scan <url>`: auth on `tools/list`, invalid token, PRM, PKCE S256/`plain`, DCR vs CIMD, `iss` (RFC 9207), CORS, transport, tool poisoning, opt-in redirect-URI probe (`--active`); fixes include code | ✅ |
| Static scan of client configs (unpinned `npx`/`uvx`, known-malicious versions, typosquats, shell/stdio commands, `curl\|sh`, plaintext secrets, static bearer tokens, `0.0.0.0`, broad filesystem roots, privileged Docker) and server source (eval, shell exec, token passthrough); JSON/SARIF/HTML output; GitHub Action | ✅ |
| **US-2** `protect(server)` for the TS SDK | ✅ (duck-typed adapter, tested against an SDK-shaped fake; not yet run against the real SDK or MCP Inspector) · Python ❌ |
| **US-3** Argument policies with p99 < 5 ms; approval in Slack with context | ✅ (Slack: Block Kit message + signed interactivity endpoint `/slack/interactions`) |
| **US-4** Single-task token via RFC 8693 with `sub` = user, `act` = agent, RAR, 5 min | ✅ for Mandat-protected MCP servers · downstream tokens for Stripe/CRM ❌ |
| **US-5** ID-JAG / Okta XAA | ❌ |
| Real IdP users (PRD Must: Auth0, Okta, Entra, Keycloak) | ✅ OIDC login with PKCE (`mandat login`), `mandat idp add`, ID-token exchange. Covered by tests against an Auth0-like fake IdP |
| **US-6** OCSF event with the delegation chain | ✅ export via `/api/ledger/export`; OTLP push of spans (`ledger.otlp`) · direct SIEM connectors (Splunk HEC and others) ❌ |
| **US-7** Revocation by agent, version, user, task, tenant or token in ≤ 10 s | ✅ < 1 s in tests; issuance blocked until lifted |
| **US-8** DPO report from the hash chain, retention check | ✅ `mandat ledger report`, console |
| **US-9** Tool description/schema drift | ✅ server-side lockfile (warn/block) and client-side `mandat pin --check` |
| Attribution model, local ledger, shadow mode, taint, policy tests | ✅ |
| Control plane: agents registry, roles (admin / approver / auditor / service), policy change log, console | ✅ |
| Cloud Free, hosted multi-tenant ledger, CIBA, Teams, Transaction Tokens, SPIFFE, Gateway, other language SDKs | ❌ out of MVP scope |

## Security notes and known limitations

- **Dev IdP.** `devIdp: true` (the `mandat init` default) lets anyone mint user tokens on `/dev/login`. Disable it with `mandat idp add … --disable-dev-idp` before any real use.
- **Approver identity.** Approvers still authenticate with API keys (console/CLI) or Slack, not through the IdP, so self-approval is only detected when the approver id matches the user's `sub` or e-mail.
- **Storage.** The control plane keeps state in JSON files under `dataDir` (single process, no HA). The `JsonCollection` interface is the seam for a database.
- **Ledger.** The ledger is tamper-*evident*, not tamper-*proof*: someone with write access could rewrite the whole chain. For that threat, anchor the head hash externally (WORM storage, a transparency log, or an eIDAS timestamp; see open question 8). Records are ordered by `seq`, which is arrival order; `ts` is event time.
- **Auth failures** (bad or revoked token → `401`) are returned to the caller but not yet written to the ledger.
- **Slack identity.** Slack approvers are recorded as `slack:<username>`. They are not yet mapped to IdP identities, so the self-approval check covers only the API, console and CLI.
- **MCP server scope.** The built-in MCP server implements the JSON response mode of Streamable HTTP (no SSE stream, no server→client requests).
- **OWASP mappings.** Mappings to OWASP Agentic (ASI) and MCP Top 10 are best effort.

## Development

```bash
npm test            # 46 tests: expression language, PDP, STS, guard, approvals, ledger, scanner, OIDC, end-to-end over HTTP
npm run typecheck   # tsc --strict (dev dependency only)
npm run build       # dist/ (plain JS + .d.ts) for the npm package; Node >= 20
npm run demo
```

## Releasing

Releases are published from GitHub Actions ([`release.yml`](.github/workflows/release.yml)) using npm Trusted Publishing, so no npm token is stored anywhere:

```bash
npm version patch          # bumps package.json, commits, tags vX.Y.Z
git push --follow-tags     # CI checks the tag, runs typecheck and tests, then publishes with provenance
```

License: Apache-2.0.
