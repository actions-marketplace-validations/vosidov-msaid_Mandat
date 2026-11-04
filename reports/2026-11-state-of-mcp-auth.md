# State of MCP Auth: November 2026

*How well do popular MCP servers protect access? A passive scan of 11 vendor-hosted endpoints, plus the documented install commands of 3 local servers. Draft, 4 November 2026.*

## Key findings

- **The big vendors got the basics right.** All 7 endpoints that require authentication answer `401` with a discovery challenge, publish Protected Resource Metadata (RFC 9728) and authorization server metadata, support PKCE with S256, reject invalid tokens, and return `iss` in authorization responses (RFC 9207). That is the opposite of the long tail: a measurement study of 7,973 live remote MCP servers (Fudan University, 2026) found that 40.55% expose their tools without any authentication.
- **4 of 11 endpoints answer without authentication, and they look intentional.** They serve public documentation and search (Context7, Cloudflare Docs, DeepWiki, Hugging Face Hub). Three declare every tool `readOnlyHint`, so clients and scanners can recognise them as public read-only servers. One (DeepWiki) declares no tool annotations, so tooling cannot tell "public on purpose" from "forgot to add auth".
- **The remaining issues are hardening, not open doors:**
  - one authorization server still advertises `plain` PKCE alongside S256;
  - one does not return `iss` in authorization responses;
  - 3 of the 7 authenticated endpoints offer only Dynamic Client Registration (DCR), which MCP revision 2026-07-28 deprecates in favour of Client ID Metadata Documents (CIMD). 3 of 7 already support CIMD.
- **CORS is wide open almost everywhere, safely.** 8 of 11 endpoints allow any origin (`*` or a reflected origin), but none combine this with `Allow-Credentials`. With bearer tokens, a page from another origin cannot borrow a user's access, so this is acceptable for servers meant to serve browser clients.
- **The weak spot is the client side.** The documented install commands of all 3 local servers we checked run an unpinned package on every start: Playwright `@latest`, plus Memory and shadcn/ui without a version. A compromised release, as happened to postmark-mcp and LiteLLM, would reach every machine that restarts its MCP client.
- **Revision 2026-07-28 is already enforced.** At least 5 of the 11 servers reject an old-style `initialize` that carries the new `MCP-Protocol-Version: 2026-07-28` header (`400`: "the request headers and body disagree"). Our own scanner and client sent exactly that combination until this scan, and have been fixed. Clients that send the version header before negotiating it will fail against these servers.

## Method

- **Targets.** Starting from a list of 20 popular MCP servers, we scanned every one that has a **single vendor-hosted endpoint**: GitHub, Figma, Context7, Supabase, Hugging Face, DeepWiki, Linear, Sentry, Higgsfield, and Cloudflare (its Docs and Observability servers). That gives 11 endpoints from 10 vendors.
- **Checks, passive only.** One scan per endpoint with Mandat's scanner (`mandat scan`, version 0.1.4 plus the fixes described above, released in the next version):
  - transport;
  - `initialize` and `tools/list` without credentials, and with an invalid token;
  - the `WWW-Authenticate` challenge;
  - Protected Resource Metadata (RFC 9728) and authorization server metadata (RFC 8414 / OIDC);
  - PKCE methods, grant types, CIMD versus DCR, and `iss` (RFC 9207);
  - CORS preflight;
  - tool descriptions scanned for hidden instructions (tool poisoning).

  We did not register clients, call tools, or send real credentials.
- **Local servers.** For Playwright, Memory and shadcn/ui, we checked the install command from each project's documentation with `mandat scan-config`.
- **Not assessed.** Several entries on the list have no single endpoint to scan: n8n and MCPJungle are self-hosted; Docker MCP and Unity MCP run locally; Zuplo and Portkey give every customer their own endpoint. We found no MCP server for SoChain.

## Recommendations

**For MCP server builders**

1. Require a bearer token on **every** request, including `initialize` and `tools/list`. Answer `401` with `WWW-Authenticate: Bearer resource_metadata="…"`.
2. If your server is public on purpose, mark every tool `readOnlyHint: true`, keep it read-only, and rate-limit it.
3. Offer CIMD now. DCR is deprecated as of 2026-07-28 and will be removed no earlier than 2027-07-28.
4. Accept only `S256` for PKCE, and return `iss` in authorization responses.
5. Never combine a reflected or `*` origin with `Access-Control-Allow-Credentials: true`.

**For MCP client and agent developers**

1. Pin server packages to an exact, reviewed version (`npx -y pkg@1.2.3`, never `@latest`), and check configs in CI (`mandat scan-config`).
2. Don't send `MCP-Protocol-Version` on `initialize`; send it after the version has been negotiated.

## Limitations

- **A small sample.** 11 endpoints from well-funded vendors are not representative of the ecosystem. The long tail, where most of the risk is, looks very different.
- **A single point in time.** Results are from 4 November 2026; servers change.
- **Passive checks only.** They cannot see authorization logic behind the token: scopes, per-tool permissions, or how a server uses its own downstream credentials.
- **Inferred intent.** "Public on purpose" is inferred from tool annotations and the nature of the service, not confirmed by the vendors.

## Appendix: per-server results

*Before publishing the vendor names, share the specific findings with the vendors concerned (Supabase, Hugging Face, DeepWiki) and give them time to respond.*

| Endpoint | Auth required | Grade | Findings |
|---|---|---|---|
| GitHub (`api.githubcopilot.com/mcp/`) | yes | B | CORS `*` (low) |
| Figma (`mcp.figma.com/mcp`) | yes | B | DCR without CIMD (low); CORS `*` (low) |
| Supabase (`mcp.supabase.com/mcp`) | yes | C | PKCE `plain` still advertised (medium); DCR without CIMD (low) |
| Linear (`mcp.linear.app/mcp`) | yes | B | CORS reflects origin, no credentials (low) |
| Sentry (`mcp.sentry.dev/mcp`) | yes | A | none |
| Higgsfield (`mcp.higgsfield.ai/mcp`) | yes | A | none |
| Cloudflare Observability (`observability.mcp.cloudflare.com/mcp`) | yes | B | DCR without CIMD (low); CORS `*` (low) |
| Context7 (`mcp.context7.com/mcp`) | no, public read-only | C | read-only tools exposed (medium); CORS `*` (low) |
| Cloudflare Docs (`docs.mcp.cloudflare.com/mcp`) | no, public read-only | C | read-only tools exposed (medium); CORS `*` (low) |
| Hugging Face (`huggingface.co/mcp`) | optional; anonymous read-only | C | read-only tools exposed (medium); no `iss` in authorization responses (medium); CORS reflects origin (low) |
| DeepWiki (`mcp.deepwiki.com/mcp`) | no | F | tools exposed without auth and no `readOnlyHint` (critical, likely intentional); no PRM (high); CORS `*` (low) |
| Playwright MCP (install docs) | n/a | D | `npx @playwright/mcp@latest`: unpinned (high) |
| Memory MCP (install docs) | n/a | D | `npx -y @modelcontextprotocol/server-memory`: unpinned (high) |
| shadcn/ui MCP (install docs) | n/a | D | `npx shadcn@latest mcp`: unpinned (high) |

Grades: A = no findings, B = low only, C = medium, D = high, F = critical. Reproduce any row with `npx mandat scan <url>`, or use the scanner page (`mandat web`).
