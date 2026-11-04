# Scanner

Mandat's scanner finds the authentication and supply-chain mistakes that are common in MCP servers and MCP client configurations. It runs from the CLI, in CI, or as a web page.

**Try it in the browser: [scan.themandat.xyz](https://scan.themandat.xyz)**

## Scan a remote MCP server

```bash
npx mandat scan https://mcp.example.com/mcp
npx mandat scan https://mcp.example.com/mcp --format sarif --out mandat.sarif   # json | sarif | html | text
```

The scan is **passive**. It never registers clients, calls tools or sends real credentials. It checks:

| Area | Checks |
|---|---|
| Authentication | `initialize` and `tools/list` without credentials, and with an invalid token |
| OAuth discovery | `401` with a `resource_metadata` challenge, Protected Resource Metadata (RFC 9728), authorization server metadata (RFC 8414 / OIDC) |
| OAuth hygiene | PKCE S256 and no `plain`, no implicit or password grants, `iss` in authorization responses (RFC 9207), CIMD versus the deprecated Dynamic Client Registration |
| Browser exposure | CORS that allows any origin (high only together with credentials), plain HTTP |
| Tool poisoning | hidden instructions in the descriptions of tools exposed without authentication |

A server that answers without authentication but declares every tool `readOnlyHint` is treated as a public read-only server and reported as *medium*, not *critical*.

`--active` adds one intrusive probe: it registers a client with an attacker-style redirect URI to test Dynamic Client Registration. Only use it against servers you own.

Exit code: non-zero when a finding at or above `--fail-on` (default `high`) exists. Use `--fail-on none` to always exit 0.

## Scan client configs and server source

```bash
npx mandat scan-config                          # auto-detects Claude Desktop, Cursor, Windsurf, VS Code, .mcp.json
npx mandat scan-config .mcp.json --src ./server # specific files, plus a static scan of server source code
```

**Client configs** are checked for:
- unpinned `npx` / `uvx` / `pipx` packages and `@latest`;
- known-malicious package versions and likely typosquats;
- servers launched through a shell, and `curl | sh`;
- plaintext secrets and static bearer tokens;
- servers listening on `0.0.0.0`, broad filesystem roots, and privileged Docker containers.

Windows `cmd /c <command>` wrappers are unwrapped and checked as the inner command.

**Server source** is checked for `eval`, shell execution built from variables, forwarding the client's token to downstream APIs, and listening on all interfaces.

## Pin tool definitions

Tool poisoning ("rug pull") changes a tool's description after you trusted it. Pin a server's tools and check them on every run:

```bash
npx mandat pin https://mcp.example.com/mcp --token <token>          # writes mandat.lock.json
npx mandat pin https://mcp.example.com/mcp --token <token> --check  # fails if any description or schema changed
```

Servers protected by Mandat can pin their own tools at startup and block changed tools (`pinning: { lockfile, mode: "block" }`).

## GitHub Action

```yaml
# .github/workflows/mcp-scan.yml
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # to upload SARIF to code scanning
jobs:
  mandat:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vosidov-msaid/Mandat@v0.1.5      # pin a release tag (or a commit SHA)
        id: scan
        with:
          configs: .mcp.json .vscode/mcp.json
          src: server
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.scan.outputs.sarif }}
```

Inputs: `configs` (space-separated files), `src` (source directory), `url` (a live endpoint to scan), and `fail-on`.

## Scanner web page

`mandat web` serves the scanner as a page. Paste an MCP server URL or a client config to get a graded report (A to F) with fixes, code samples and OWASP references, plus a shareable link.

```bash
mandat web                      # http://127.0.0.1:7800, public mode: only public servers can be scanned
mandat web --allow-private      # self-hosted on a trusted network: also scan localhost and internal servers
```

It is built to be hosted publicly, where strangers choose the URLs:
- **SSRF-safe.** Every request goes through a fetch that refuses private, loopback, link-local, cloud-metadata (`169.254.169.254`), CGNAT, multicast and other reserved addresses. That includes URLs discovered in the scanned server's responses. The check runs at connection time on every address DNS returns, which also defeats DNS rebinding. Redirects are never followed, and bodies are capped at 1 MB.
- **Passive only.** `--active` never runs from the page.
- **Rate-limited.** 10 scans per client IP every 10 minutes, and 4 concurrent scans. Behind a proxy, use `--client-ip-header <header>` (for example `fly-client-ip`) or `--trust-proxy`.
- **No injection from reports.** Report text comes from the scanned server, so it is rendered as text only, under a strict Content Security Policy.
- **Pasted configs are only parsed,** never executed. Reports are kept in memory for 7 days.

## Deploy the web page on Fly.io

The repository ships a [`Dockerfile`](../Dockerfile) and a [`fly.toml`](../fly.toml):
- the image is built from source and contains only the compiled `dist/`, with no dependencies;
- it runs as a non-root user and starts in public mode;
- rate limiting uses Fly's `Fly-Client-IP` header.

```bash
fly auth login
fly launch --no-deploy --copy-config --name <your-app-name>
fly deploy
fly scale count 1                 # state is kept in memory: run exactly one machine
fly certs add scan.example.com    # optional custom domain; add the DNS records it prints
```

The machine is always on (`auto_stop_machines = "off"`), because stopping it would lose share links and rate-limit state.
