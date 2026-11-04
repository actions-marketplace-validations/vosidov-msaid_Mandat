# Architecture and security

```
Person ── signs in with the identity provider (Auth0, Okta, Entra ID, Keycloak)
   │ ID token
   ▼
Agent ── token exchange (RFC 8693: sub = person, act = agent, + allowed tools) ──▶ Mandat control plane
   │                                                                              │ 5-minute task token for one server
   ▼ MCP (Streamable HTTP)                                                        │
MCP server + Mandat guard ◀── policy, revocations (every 2 s), keys ──────────────┤
   │  allow · deny · ask a human ─────── approvals ──▶ console · Slack · webhooks · CLI
   │  one audit record per call (async, batched, at-least-once) ──▶ hash-chained ledger ──▶ OCSF / OpenTelemetry
   ▼
Downstream APIs (the user's own token is never forwarded)
```

- **Task tokens:** short-lived, bound to one server (`aud`), carrying the person (`sub`), the agent chain (nested `act`) and the delegated tools and limits (RFC 9396 `authorization_details`). A sub-agent's token can only narrow its parent's.
- **Decisions** are made inside the guard, in microseconds. The control plane is needed only for approvals.
- **If the control plane is unreachable,** guards keep deciding with the last policy snapshot, and `financial` and `destructive` tools fail closed.

## Repository layout

| Path | Contents |
|---|---|
| `src/policy/` | Expression language and decision engine |
| `src/sts/` | JWT / JWKS verification (ES256, RS256, PS256, EdDSA; no `none`, no HMAC), token exchange, revocation |
| `src/guard/` | The guard, tool pinning, control-plane clients |
| `src/mcp/` | Built-in MCP server and `protect()` for the official SDK |
| `src/approvals/` | Approvals, Slack and signed webhooks |
| `src/ledger/` | Hash chain, redaction, OCSF / OpenTelemetry export, audit report |
| `src/scan/` | Scanner, SSRF-safe fetch, scanner web page |
| `src/controlplane/` | Control plane, people sign-in and console |
| `python/` | Python SDK |
| `spec/conformance/` | Decisions every SDK must reproduce |

## Security properties

- **The supply chain is locked down:**
  - no runtime dependencies in the npm package;
  - releases are built in CI from tagged commits with npm and PyPI Trusted Publishing (no stored tokens), carry provenance, and need a maintainer's approval;
  - third-party GitHub Actions and the container image are pinned by digest.
- **Tokens:** asymmetric signatures only, audience-bound, and checked for revocation on every call.
- **Approvals** are bound to the exact call, single-use and expiring. Self-approval is refused.
- **The console** uses HttpOnly SameSite=Strict cookies, requires a CSRF header for writes, and is served under a strict Content Security Policy.
- **The public scanner** refuses private and reserved addresses at connection time and is rate-limited.

## Known limitations

- **Single node.** The control plane keeps state in JSON files under its data directory: one process, no high availability. Console sessions and scanner reports live in memory.
- **Tamper-evident, not tamper-proof.** Someone with write access to the ledger file could rewrite the whole chain. Anchor the chain head externally (WORM storage or a transparency log) if that is your threat.
- **Slack approvers** are recorded as `slack:<username>`, not mapped to the identity provider, so the self-approval check covers the console, CLI and API only.
- **The built-in MCP server** implements the JSON response mode of Streamable HTTP (no server-to-client stream).
- **Downstream tokens** for third-party APIs (for example Stripe) are not issued yet. Mandat protects the MCP server boundary.
- **OWASP mappings** in scanner findings are best effort.
