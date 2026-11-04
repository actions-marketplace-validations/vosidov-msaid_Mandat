# Changelog

Mandat follows [semantic versioning](https://semver.org). Before 1.0, minor versions may change APIs.
The npm package (`mandat`) and the Python package (`mandat` on PyPI) are versioned separately.

## npm 0.1.5 (2026-11-04)

- **Scanner: correct results against MCP revision 2026-07-28 servers.** These servers reject an old-style `initialize` that carries a `MCP-Protocol-Version: 2026-07-28` header, so earlier versions could not assess them. The scanner and `McpHttpClient` now send the header only after negotiating it.
- **Scanner calibration:**
  - a server whose tools are all `readOnlyHint` is reported as a public read-only server (*medium*) instead of *critical*;
  - CORS that allows any origin is *high* only together with credentials;
  - a rejected probe is reported as "not assessable" instead of missing metadata;
  - a `400` for a malformed bearer token counts as rejecting it.
- **Scanner web page:** an HSTS header behind HTTPS proxies, and `--client-ip-header` for platform proxies such as Fly.io's `Fly-Client-IP`.
- **Deployment:** a `Dockerfile` and `fly.toml` for the scanner page.
- **GitHub Action:** it now sets up Node 24 itself; it previously failed on runners with an older Node.

## npm 0.1.4 (2026-11-04)

- **Scanner web page (`mandat web`):** paste a server URL or a client config and get a graded report with a share link. Safe to host publicly: SSRF-safe fetch, passive checks only, rate limits.
- **Verified with the official MCP TypeScript SDK and MCP Inspector**, which revealed and fixed a typing problem in `protect()`.

## PyPI 0.1.0 (2026-11-04)

- First release of the Python SDK. It provides the guard, `protect(MCPServer)` and a token verifier for the official `mcp` 2.x SDK, and decides identically to the TypeScript SDK (shared conformance suite).

## npm 0.1.3 (2026-11-04)

- **People sign in with your identity provider:** in the console (browser login) and in the CLI (`--login`). Roles are granted with `mandat users`, and self-approval is checked against verified identities.
- **Rejected logins are recorded in the audit ledger:** `auth.rejected`, `token.denied` and `api.auth_rejected`, rate-limited.
- **`mandat agents rotate-secret` and `mandat agents remove`.**
- **Releases are built in CI** with npm Trusted Publishing and provenance, and approved by a maintainer.

## npm 0.1.2 (2026-11-04)

- `mandat idp add` accepts a bare domain as the issuer.
- A guard fails loudly when the control plane rejects its API key.

## npm 0.1.1 (2026-11-04)

- **Real users through OpenID Connect:** `mandat login` (browser login with PKCE), `mandat idp add` and `mandat bridge --login`.
- **`mandat bridge`** connects Claude Code, Codex and other stdio MCP clients.

## npm 0.1.0 (2026-11-04)

- First release:
  - a policy engine with argument rules;
  - token exchange with delegation chains;
  - guards for MCP servers;
  - approvals, revocation and a hash-chained audit ledger;
  - the scanner, the web console and the CLI.
