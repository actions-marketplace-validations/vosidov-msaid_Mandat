// External scan of a remote MCP server's authorization surface (MCP Authorization rev. 2026-07-28):
// unauthenticated tools, token validation, PRM (RFC 9728), AS metadata (RFC 8414), PKCE S256,
// DCR vs CIMD, `iss` (RFC 9207), CORS, transport. Passive by default; `active` adds a DCR redirect probe.

import type { Finding, ScanReport } from "./findings.ts";
import { VERSION } from "../version.ts";

export interface RemoteScanOptions { active?: boolean; timeoutMs?: number; headers?: Record<string, string> }

const FIX_PROTECT = `// npm i mandat  — then wrap your server:
import { createGuard, protect } from "mandat";
const guard = await createGuard({ resource: "https://mcp.example.com/mcp", controlPlane: process.env.MANDAT_URL, apiKey: process.env.MANDAT_API_KEY });
protect(mcpServer, guard);                       // policy + audit on every tools/call
app.use("/mcp", requireBearerAuth({ verifier: guard.sdkTokenVerifier({ InvalidTokenError }) }));`;

const POISON_PATTERNS: Array<[RegExp, string]> = [
  [/ignore (all |any )?(previous|prior|above) (instructions|prompts)/i, "instruction override"],
  [/<\s*(important|system|instructions?)\s*>/i, "hidden instruction tag"],
  [/do not (tell|inform|mention|reveal)[^.]{0,40}(user|human)/i, "concealment from user"],
  [/(~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b|mcp\.json|claude_desktop_config)/i, "credential file reference"],
  [/\b(bcc|forward|send|exfiltrat\w*|upload)\b[^.]{0,60}\b(to|@)\s*[\w.-]+\.(com|net|io|ru|xyz)/i, "data forwarding to external address"],
  [/before (using|calling) (this|any other) tool/i, "cross-tool instruction"],
];

export async function scanRemote(target: string, opts: RemoteScanOptions = {}): Promise<ScanReport> {
  const findings: Finding[] = [];
  const passed: string[] = [];
  const info: Record<string, unknown> = {};
  const timeout = opts.timeoutMs ?? 8000;
  const url = new URL(target);
  const loc = { url: target };
  const add = (f: Omit<Finding, "location">) => findings.push({ ...f, location: loc });

  const req = async (u: string, init: RequestInit = {}) => {
    try {
      return await fetch(u, { redirect: "manual", ...init, headers: { ...opts.headers, ...(init.headers as Record<string, string>) }, signal: AbortSignal.timeout(timeout) });
    } catch (e) {
      return null;
    }
  };
  const rpc = (method: string, id: number, token?: string) =>
    req(target, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2026-07-28", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params: method === "initialize" ? { protocolVersion: "2026-07-28", capabilities: {}, clientInfo: { name: "mandat-scan", version: VERSION } } : {} }),
    });

  // 1. Transport
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !loopback) {
    add({ rule: "MDT-R001", severity: "high", title: "MCP endpoint not served over HTTPS", detail: `${url.origin} uses ${url.protocol} — bearer tokens travel in clear text.`, fix: "Terminate TLS in front of the MCP server; MCP authorization requires HTTPS for all non-loopback endpoints.", owasp: ["MCP07"] });
  } else passed.push("transport");

  // 2. Unauthenticated access
  const init = await rpc("initialize", 1);
  if (!init) {
    add({ rule: "MDT-R000", severity: "info", title: "Server unreachable", detail: `No response from ${target} within ${timeout} ms.`, fix: "Check the URL and network access.", owasp: [] });
    return { target, kind: "remote", scanned_at: new Date().toISOString(), findings, passed, info };
  }
  info.unauthenticated_status = init.status;
  let wwwAuth = init.headers.get("www-authenticate");
  if (init.status === 200) {
    const sid = init.headers.get("mcp-session-id");
    const list = await req(target, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(sid ? { "mcp-session-id": sid } : {}) },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
    });
    const tools = list ? await parseRpcTools(list) : null;
    if (tools) {
      info.exposed_tools = tools.map((t) => t.name);
      add({
        rule: "MDT-R002", severity: "critical", title: "Tools exposed without authentication",
        detail: `tools/list answered without any credentials and exposed ${tools.length} tools (${tools.slice(0, 8).map((t) => t.name).join(", ")}${tools.length > 8 ? ", …" : ""}). 40.55% of public MCP servers are in this state.`,
        fix: "Require an OAuth bearer token on every MCP request (including initialize and tools/list) and return 401 with a resource_metadata challenge.",
        fixCode: FIX_PROTECT, owasp: ["MCP07", "ASI03"],
      });
      for (const t of tools) {
        const text = `${t.description ?? ""} ${JSON.stringify(t.inputSchema ?? {})}`;
        const hit = POISON_PATTERNS.find(([re]) => re.test(text));
        if (hit) add({
          rule: "MDT-R013", severity: "high", title: `Possible tool poisoning in '${t.name}'`,
          detail: `The tool description contains a ${hit[1]} pattern — hidden instructions to the model are a known MCP attack (rug pull / tool poisoning).`,
          fix: "Review the tool description; pin tool definitions so changes are detected (`mandat pin <url>`).", owasp: ["MCP03", "ASI02"],
        });
      }
    } else {
      add({ rule: "MDT-R002", severity: "high", title: "MCP initialize succeeds without authentication", detail: "The server accepted an unauthenticated initialize request.", fix: "Authenticate every MCP request, not only tools/call.", fixCode: FIX_PROTECT, owasp: ["MCP07", "ASI03"] });
    }
  } else if (init.status === 401) {
    passed.push("auth-required");
  } else {
    info.note = `initialize without credentials returned ${init.status}`;
  }

  // 3. Garbage token must be rejected
  const bogus = await rpc("initialize", 3, "mandat-scan-invalid-token");
  if (bogus && bogus.status === 200 && init.status === 401) {
    add({ rule: "MDT-R012", severity: "critical", title: "Server accepts an invalid bearer token", detail: "Any non-empty Authorization header is accepted: the token is not validated.", fix: "Validate signature, issuer, audience (this server's URL) and expiry of every access token.", fixCode: FIX_PROTECT, owasp: ["MCP07", "ASI03"] });
  } else if (bogus && bogus.status === 401) passed.push("rejects-invalid-token");

  // 3b. CORS
  const pre = await req(target, { method: "OPTIONS", headers: { origin: "https://evil.mandat-scan.invalid", "access-control-request-method": "POST", "access-control-request-headers": "authorization,content-type" } });
  const acao = pre?.headers.get("access-control-allow-origin");
  const acac = pre?.headers.get("access-control-allow-credentials");
  if (acao === "https://evil.mandat-scan.invalid" || (acao === "*" && acac === "true"))
    add({ rule: "MDT-R010", severity: "high", title: "CORS reflects arbitrary origins", detail: `Access-Control-Allow-Origin: ${acao}${acac ? `, Allow-Credentials: ${acac}` : ""}. Any website can drive this MCP server from a victim's browser.`, fix: "Allow-list the exact origins of your web clients and validate the Origin header (DNS rebinding protection).", owasp: ["MCP07"] });
  else if (acao === "*") add({ rule: "MDT-R010", severity: "low", title: "CORS allows any origin", detail: "Access-Control-Allow-Origin: * on the MCP endpoint.", fix: "Restrict to known origins.", owasp: ["MCP07"] });
  else passed.push("cors");

  // 4. WWW-Authenticate + Protected Resource Metadata (RFC 9728)
  wwwAuth ??= bogus?.headers.get("www-authenticate") ?? null;
  info.www_authenticate = wwwAuth;
  let prmUrl = wwwAuth ? /resource_metadata="([^"]+)"/.exec(wwwAuth)?.[1] : undefined;
  if (init.status === 401 && !prmUrl) {
    add({ rule: "MDT-R003", severity: "high", title: "401 without resource_metadata challenge", detail: `WWW-Authenticate is ${wwwAuth ? `"${wwwAuth}"` : "missing"}; MCP clients cannot discover the authorization server.`, fix: 'Return `WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource"` on 401.', owasp: ["MCP07"] });
  }
  const candidates = [prmUrl, `${url.origin}/.well-known/oauth-protected-resource${url.pathname === "/" ? "" : url.pathname}`, `${url.origin}/.well-known/oauth-protected-resource`].filter(Boolean) as string[];
  let prm: Record<string, unknown> | null = null;
  for (const c of candidates) {
    const r = await req(c);
    if (r?.ok) { try { prm = (await r.json()) as Record<string, unknown>; prmUrl = c; break; } catch { /* not JSON */ } }
  }
  info.prm_url = prm ? prmUrl : null;
  if (!prm) {
    if (init.status !== 200 || findings.some((f) => f.rule === "MDT-R002"))
      add({ rule: "MDT-R004", severity: "high", title: "Protected Resource Metadata missing", detail: "No RFC 9728 document found; required by MCP Authorization (2025-06-18 and later).", fix: "Serve /.well-known/oauth-protected-resource with `resource` and `authorization_servers`.", fixCode: `app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json(guard.protectedResourceMetadata()));`, owasp: ["MCP07"] });
    return { target, kind: "remote", scanned_at: new Date().toISOString(), findings, passed, info };
  }
  passed.push("prm");
  const resource = String(prm.resource ?? "");
  if (resource && normalize(resource) !== normalize(target) && !normalize(target).startsWith(normalize(resource)))
    add({ rule: "MDT-R005", severity: "medium", title: "PRM `resource` does not match the endpoint", detail: `PRM resource is ${resource} but the endpoint is ${target}; clients bind tokens (RFC 8707) to the wrong audience.`, fix: "Set `resource` to the canonical MCP endpoint URL and validate `aud` against it.", owasp: ["MCP07"] });
  const asList = Array.isArray(prm.authorization_servers) ? (prm.authorization_servers as string[]) : [];
  if (!asList.length) {
    add({ rule: "MDT-R004", severity: "high", title: "PRM lists no authorization server", detail: "`authorization_servers` is empty or missing.", fix: "List your issuer in `authorization_servers`.", owasp: ["MCP07"] });
    return { target, kind: "remote", scanned_at: new Date().toISOString(), findings, passed, info };
  }

  // 5. Authorization server metadata (RFC 8414 / OIDC discovery)
  const issuer = asList[0]!;
  const iu = new URL(issuer);
  const asCandidates = [
    `${iu.origin}/.well-known/oauth-authorization-server${iu.pathname === "/" ? "" : iu.pathname}`,
    `${iu.origin}/.well-known/openid-configuration${iu.pathname === "/" ? "" : iu.pathname}`,
    `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
  ];
  let asm: Record<string, unknown> | null = null;
  for (const c of asCandidates) {
    const r = await req(c);
    if (r?.ok) { try { asm = (await r.json()) as Record<string, unknown>; info.as_metadata_url = c; break; } catch { /* ignore */ } }
  }
  if (!asm) {
    add({ rule: "MDT-R006", severity: "high", title: "Authorization server metadata not found", detail: `Could not fetch RFC 8414 / OIDC metadata for ${issuer}.`, fix: "Publish /.well-known/oauth-authorization-server on the issuer.", owasp: ["MCP07"] });
    return { target, kind: "remote", scanned_at: new Date().toISOString(), findings, passed, info };
  }
  passed.push("as-metadata");
  if (asm.issuer && asm.issuer !== issuer)
    add({ rule: "MDT-R009", severity: "medium", title: "Issuer mismatch in AS metadata", detail: `metadata issuer is ${String(asm.issuer)}, PRM says ${issuer}.`, fix: "The `issuer` value must exactly equal the URL listed in PRM.", owasp: ["MCP07"] });

  const pkce = (asm.code_challenge_methods_supported as string[] | undefined) ?? [];
  if (!pkce.includes("S256")) add({ rule: "MDT-R007", severity: "high", title: "PKCE S256 not advertised", detail: `code_challenge_methods_supported = ${JSON.stringify(pkce)}; MCP clients MUST refuse to proceed without S256.`, fix: 'Enforce PKCE and advertise `"code_challenge_methods_supported": ["S256"]`.', owasp: ["MCP07"] });
  else passed.push("pkce-s256");
  if (pkce.includes("plain")) add({ rule: "MDT-R007", severity: "medium", title: "PKCE downgrade to `plain` allowed", detail: "The AS accepts the plain method, which offers no protection against code interception.", fix: "Remove `plain`; accept S256 only.", owasp: ["MCP07"] });

  const grants = (asm.grant_types_supported as string[] | undefined) ?? [];
  for (const g of ["implicit", "password"]) if (grants.includes(g))
    add({ rule: "MDT-R014", severity: "medium", title: `Legacy grant '${g}' enabled`, detail: `OAuth 2.1 removes the ${g} grant.`, fix: `Disable the ${g} grant.`, owasp: ["MCP07"] });

  const cimd = asm.client_id_metadata_document_supported === true;
  if (asm.registration_endpoint && !cimd)
    add({ rule: "MDT-R008", severity: "low", title: "Dynamic Client Registration without CIMD", detail: "DCR is deprecated in MCP 2026-07-28 (removal no earlier than 2027-07-28); Client ID Metadata Documents are the recommended mechanism.", fix: "Support CIMD (fetch client metadata from the client_id URL with SSRF protection) and advertise `client_id_metadata_document_supported: true`.", owasp: ["MCP07"] });
  else if (cimd) passed.push("cimd");
  if (asm.authorization_response_iss_parameter_supported !== true)
    add({ rule: "MDT-R009", severity: "medium", title: "No `iss` in authorization responses (RFC 9207)", detail: "Without the iss parameter, clients using several authorization servers are exposed to mix-up attacks.", fix: "Return `iss` in authorization responses and advertise `authorization_response_iss_parameter_supported: true`.", owasp: ["MCP07"] });
  else passed.push("iss-rfc9207");

  // 7. Active: does DCR accept an arbitrary redirect URI from an anonymous registrant?
  if (opts.active && typeof asm.registration_endpoint === "string") {
    const r = await req(asm.registration_endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_name: "mandat-scan-probe", redirect_uris: ["https://attacker.mandat-scan.invalid/callback"], grant_types: ["authorization_code"], token_endpoint_auth_method: "none" }),
    });
    if (r && (r.status === 200 || r.status === 201))
      add({ rule: "MDT-R011", severity: "high", title: "Anonymous DCR accepts any redirect URI", detail: "The registration endpoint registered a client with an attacker-controlled redirect_uri (found on 114 of 119 OAuth MCP servers in the Fudan 2026 study). Combined with consent reuse this enables code theft.", fix: "Require initial access tokens or allow-list redirect URI hosts; prefer CIMD.", owasp: ["MCP07", "ASI03"] });
    else passed.push("dcr-redirect-allowlist");
  }

  return { target, kind: "remote", scanned_at: new Date().toISOString(), findings, passed, info };
}

function normalize(u: string): string {
  return u.replace(/\/+$/, "").toLowerCase();
}

async function parseRpcTools(res: Response): Promise<Array<{ name: string; description?: string; inputSchema?: unknown }> | null> {
  if (!res.ok) return null;
  const text = await res.text();
  const ct = res.headers.get("content-type") ?? "";
  let msg: any = null;
  try {
    if (ct.includes("text/event-stream")) {
      const data = text.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).find((l) => l.includes('"tools"'));
      msg = data ? JSON.parse(data) : null;
    } else msg = JSON.parse(text);
  } catch { return null; }
  const tools = msg?.result?.tools;
  return Array.isArray(tools) ? tools : null;
}
