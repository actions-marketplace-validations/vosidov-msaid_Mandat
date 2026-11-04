// `mandat` command-line interface.

import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { parseArgs, type Args } from "./args.ts";
import { STARTER_POLICY, STARTER_TESTS, readmeSnippet } from "./templates.ts";
import { compilePolicy, runPolicyTests, PolicyError, type PolicyDocument, type PolicyTestCase } from "../policy/engine.ts";
import { formatHtml, formatSarif, formatText, shouldFail, type ScanReport, type Severity } from "../scan/findings.ts";
import { scanRemote } from "../scan/remote.ts";
import { scanConfigFile, scanSource } from "../scan/static.ts";
import { createScanWebServer } from "../scan/web.ts";
import { buildLock, diffLock, type LockFile, type ToolDefinition } from "../guard/pinning.ts";
import { readLedger, verifyLedger, queryRecords } from "../ledger/ledger.ts";
import { buildReport, reportToMarkdown } from "../ledger/report.ts";
import { describe, toOcsf, toOtelSpan } from "../ledger/export.ts";
import { createControlPlane } from "../controlplane/server.ts";
import { hashApiKey, loadConfig, type ControlPlaneConfig } from "../controlplane/config.ts";
import { Bridge } from "../bridge.ts";
import { clearSession, currentIdToken, discover, loadSession, login, openSystemBrowser, saveSession } from "../oidc.ts";
import { readJson, writeJsonAtomic } from "../util.ts";
import { VERSION } from "../version.ts";

const BOOLEANS = ["version", "login", "revoke-tokens", "allow-private", "trust-proxy", "no-browser", "disable-dev-idp", "active", "check", "force", "json", "tainted", "help", "h", "follow", "frozen", "no-color", "shadow"];

const HELP = `mandat ${VERSION} — authorization, delegation and audit for AI agent actions

Setup
  mandat init [--resource URL] [--force]        Create config, starter policy, keys and API credentials
  mandat serve [--config mandat.config.json]    Run the control plane (STS, approvals, ledger, console)

Scan  (US-1)
  mandat scan <url> [--active]                  Check a remote MCP server's authorization surface
  mandat scan-config [files...] [--src DIR]     Static scan of MCP client configs (auto-detects known paths) and server source
      --format text|json|sarif|html  --out FILE  --fail-on critical|high|medium|low|none (default high)
  mandat web [--port 7800] [--host 127.0.0.1] [--allow-private] [--trust-proxy]
      Scanner web page: paste a server URL or client config, get a shareable report.
      Private addresses are blocked unless --allow-private (use only on a trusted network).

Tool pinning  (US-9)
  mandat pin <url> [--token T] [--lock mandat.lock.json] [--check]   Pin / verify tool definitions of an MCP server

Policy
  mandat policy check [mandat.policy.json]
  mandat policy test [policy] [tests.json]      Run decision tests (writes mandat.policy.test.json on first run)
  mandat policy eval [policy] --tool T --args JSON [--agent A] [--tainted]
  mandat bench [policy]                         PDP latency (p50/p99)

Agents, approvals, revocation  (talk to the control plane: --url, --key or MANDAT_URL / MANDAT_API_KEY,
                               or --login to act as the person signed in with "mandat login")
  mandat agents list
  mandat agents add <id> --tools a,b [--resources URL,...] [--versions 1.0.0,...] [--name N]
  mandat agents rotate-secret <id> [--revoke-tokens]   New client secret (old one stops working)
  mandat agents remove <id>                            Delete the agent and revoke its tokens
  mandat approvals list [--status pending]
  mandat approvals approve|deny <id> [--comment C]
  mandat revoke --agent ID [--version V] | --user SUB | --task ID | --tenant T | --jti ID  [--reason R]
  mandat token --agent ID --secret S --user SUB --resource URL [--tools a,b] [--version V]   Dev: mint a task token

Real users (OIDC: Auth0, Okta, Entra ID, Keycloak)
  mandat idp add --issuer URL --client-id ID [--tenant-claim CLAIM] [--disable-dev-idp]   Trust an IdP (edits mandat.config.json)
  mandat idp list
  mandat login --issuer URL --client-id ID [--port 8765] [--organization ORG] [--no-browser]   Browser login (PKCE)
  mandat login status | mandat logout
  mandat users list
  mandat users grant --email E | --sub SUB --roles approver[,admin,auditor]   Give a signed-in person a role
  mandat users revoke <email-or-sub>

Connect real agents (Claude Code, Codex, Cursor, Claude Desktop)
  mandat bridge --url MCP_URL --agent ID [--mandat URL] [--login | --user SUB] [--version V] [--tools a,b]
      stdio MCP server that acts as agent ID and refreshes task tokens automatically.
      --login acts for the user signed in with "mandat login"; --user uses the dev IdP.
      Secret: env MANDAT_AGENT_SECRET (or --secret). Raw IdP token instead: env MANDAT_SUBJECT_TOKEN.

Ledger  (US-6, US-8)
  mandat ledger verify [file]                   Verify the hash chain
  mandat ledger tail [file] [-n 20]
  mandat ledger report [file] [--from ISO] [--to ISO] [--format md|json] [--retention DAYS]
  mandat ledger export [file] --format ocsf|otel
`;

export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv, BOOLEANS);
  const [cmd, sub] = args._;
  if (args.bool("version") || cmd === "version") { console.log(VERSION); return 0; }
  if (!cmd || args.bool("help") || args.bool("h")) { process.stdout.write(HELP); return 0; }
  switch (cmd) {
    case "init": return init(args);
    case "serve": return serve(args);
    case "scan": return scan(args);
    case "scan-config": return scanConfig(args);
    case "web": return web(args);
    case "pin": return pin(args);
    case "policy": return policyCmd(sub, args);
    case "bench": return bench(args);
    case "ledger": return ledgerCmd(sub, args);
    case "agents": return agentsCmd(sub, args);
    case "approvals": return approvalsCmd(sub, args);
    case "revoke": return revoke(args);
    case "token": return token(args);
    case "bridge": return bridge(args);
    case "login": return loginCmd(args);
    case "logout": console.log(clearSession() ? "✓ Logged out" : "Not logged in."); return 0;
    case "idp": return idpCmd(sub, args);
    case "users": return usersCmd(sub, args);
    default:
      console.error(`Unknown command '${cmd}'. Run \`mandat --help\`.`);
      return 2;
  }
}

// ---------- init / serve ----------

function newKey(): string {
  return "mdt_" + randomBytes(24).toString("base64url");
}

function init(args: Args): number {
  const dir = resolve(args.str("dir", ".")!);
  const resource = args.str("resource", "http://127.0.0.1:7401/mcp")!;
  const port = args.num("port", 7400);
  const issuer = args.str("issuer", `http://127.0.0.1:${port}`)!;
  const cfgPath = join(dir, "mandat.config.json");
  if (existsSync(cfgPath) && !args.bool("force")) {
    console.error(`${cfgPath} already exists (use --force to overwrite).`);
    return 1;
  }
  const keys = { admin: newKey(), approver: newKey(), auditor: newKey(), service: newKey() };
  const config: ControlPlaneConfig = {
    issuer,
    port,
    host: "127.0.0.1",
    dataDir: ".mandat",
    policyFile: "mandat.policy.json",
    devIdp: true,
    tokenTtlSeconds: 300,
    maxTokenTtlSeconds: 900,
    trustedIssuers: [],
    apiKeys: [
      { id: "admin", hash: hashApiKey(keys.admin), roles: ["admin", "approver", "auditor"] },
      { id: "alice", hash: hashApiKey(keys.approver), roles: ["approver"] },
      { id: "auditor", hash: hashApiKey(keys.auditor), roles: ["auditor"] },
      { id: "mcp-guard", hash: hashApiKey(keys.service), roles: ["service"] },
    ],
    approvals: { defaultTimeout: "10m", log: true },
    ledger: { retentionDays: 365 },
  };
  mkdirSync(join(dir, ".mandat"), { recursive: true });
  writeJsonAtomic(cfgPath, config);
  if (!existsSync(join(dir, "mandat.policy.json")) || args.bool("force")) writeJsonAtomic(join(dir, "mandat.policy.json"), STARTER_POLICY);
  if (!existsSync(join(dir, "mandat.policy.test.json")) || args.bool("force")) writeJsonAtomic(join(dir, "mandat.policy.test.json"), STARTER_TESTS);
  const credPath = join(dir, ".mandat", "credentials.json");
  writeFileSync(credPath, JSON.stringify({ url: issuer, keys }, null, 2) + "\n", { mode: 0o600 });
  const gi = join(dir, ".gitignore");
  const giText = existsSync(gi) ? readFileSync(gi, "utf8") : "";
  if (!/^\.mandat\/?$/m.test(giText)) appendFileSync(gi, (giText && !giText.endsWith("\n") ? "\n" : "") + ".mandat/\n");

  console.log(`✓ Created mandat.config.json, mandat.policy.json, mandat.policy.test.json
✓ API keys written to .mandat/credentials.json (git-ignored; shown once below)

  admin     ${keys.admin}
  approver  ${keys.approver}   (identity "alice")
  auditor   ${keys.auditor}
  service   ${keys.service}   (for Guards in your MCP servers)

Next:
  1. mandat policy test                 # check the starter policy
  2. mandat serve                       # control plane + console at ${issuer}/console
  3. mandat agents add support-bot --tools "lookup_*,refund,send_email" --resources ${resource}
${readmeSnippet(resource, issuer)}`);
  return 0;
}

async function serve(args: Args): Promise<number> {
  const cfgPath = args.str("config", "mandat.config.json")!;
  if (!existsSync(cfgPath)) { console.error(`${cfgPath} not found — run \`mandat init\` first.`); return 1; }
  const cfg = loadConfig(cfgPath);
  if (args.str("port")) cfg.port = args.num("port", cfg.port);
  const cp = createControlPlane(cfg);
  const addr = await cp.listen();
  console.log(`Mandat control plane listening on ${addr}
  issuer    ${cfg.issuer}
  console   ${cfg.issuer}/console
  token     ${cfg.issuer}/oauth/token   (RFC 8693 token exchange)
  jwks      ${cfg.issuer}/.well-known/jwks.json
  ledger    ${cp.ledger.path} (${cp.ledger.length} records)${cfg.devIdp ? "\n  ⚠ dev IdP enabled (POST /dev/login) — disable `devIdp` in production" : ""}`);
  await new Promise<void>((r) => { process.once("SIGINT", r); process.once("SIGTERM", r); });
  await cp.close();
  return 0;
}

// ---------- scanning ----------

function emit(reports: ScanReport[], args: Args): number {
  const fmt = args.str("format", "text");
  const text = fmt === "json" ? JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2)
    : fmt === "sarif" ? formatSarif(reports)
    : fmt === "html" ? formatHtml(reports)
    : formatText(reports, !args.bool("no-color") && !args.str("out") && process.stdout.isTTY);
  const out = args.str("out");
  if (out) { writeFileSync(out, text); console.error(`Report written to ${out}`); }
  else process.stdout.write(text.endsWith("\n") ? text : text + "\n");
  return shouldFail(reports, (args.str("fail-on", "high") as Severity | "none")) ? 1 : 0;
}

async function scan(args: Args): Promise<number> {
  const target = args._[1];
  if (!target) { console.error("Usage: mandat scan <url> [--active]"); return 2; }
  return emit([await scanRemote(target, { active: args.bool("active") })], args);
}

function knownConfigPaths(): string[] {
  const home = homedir();
  const appdata = process.env.APPDATA ?? join(home, "AppData", "Roaming");
  return [
    join(appdata, "Claude", "claude_desktop_config.json"),
    join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    join(home, ".config", "Claude", "claude_desktop_config.json"),
    join(home, ".cursor", "mcp.json"),
    join(home, ".codeium", "windsurf", "mcp_config.json"),
    join(home, ".claude.json"),
    ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json",
  ].filter((p) => existsSync(p));
}

function scanConfig(args: Args): number {
  const files = args._.slice(1);
  const reports: ScanReport[] = [];
  const targets = files.length ? files : args.str("src") ? [] : knownConfigPaths();
  for (const f of targets) reports.push(scanConfigFile(f));
  const src = args.str("src");
  if (src) reports.push(scanSource(src));
  if (!reports.length) { console.error("No MCP config files found. Pass paths explicitly or --src DIR."); return 2; }
  return emit(reports, args);
}

// ---------- pinning ----------

async function pin(args: Args): Promise<number> {
  const target = args._[1];
  if (!target) { console.error("Usage: mandat pin <url> [--token T] [--lock FILE] [--check]"); return 2; }
  const lockPath = args.str("lock", "mandat.lock.json")!;
  const tok = args.str("token") ?? process.env.MANDAT_TOKEN;
  const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json, text/event-stream", ...(tok ? { authorization: `Bearer ${tok}` } : {}) };
  const post = async (body: unknown, sid?: string | null) => {
    const r = await fetch(target, { method: "POST", headers: { ...headers, ...(sid ? { "mcp-session-id": sid } : {}) }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}${r.status === 401 ? " — pass --token" : ""}`);
    return r;
  };
  let tools: ToolDefinition[];
  try {
    const init = await post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2026-07-28", capabilities: {}, clientInfo: { name: "mandat-pin", version: VERSION } } });
    const sid = init.headers.get("mcp-session-id");
    await init.text();
    const res = await post({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, sid);
    const text = await res.text();
    const json = text.trimStart().startsWith("{") ? JSON.parse(text) : JSON.parse(text.split("\n").find((l) => l.startsWith("data:") && l.includes("tools"))!.slice(5));
    tools = json.result.tools;
  } catch (e) {
    console.error(`Could not list tools: ${(e as Error).message}`);
    return 1;
  }
  if (args.bool("check")) {
    if (!existsSync(lockPath)) { console.error(`${lockPath} not found — run without --check first.`); return 1; }
    const d = diffLock(readJson<LockFile>(lockPath), tools);
    if (d.clean) { console.log(`✓ ${tools.length} tool definitions match ${lockPath}`); return 0; }
    console.log(`✗ Tool definitions drifted from ${lockPath}:`);
    for (const c of d.changed) console.log(`  changed  ${c.name}\n           before: ${c.description_before ?? ""}\n           after:  ${c.description_after ?? ""}`);
    for (const a of d.added) console.log(`  added    ${a}`);
    for (const r of d.removed) console.log(`  removed  ${r}`);
    return 1;
  }
  writeJsonAtomic(lockPath, buildLock(tools, target));
  console.log(`✓ Pinned ${tools.length} tools of ${target} to ${lockPath}`);
  return 0;
}

// ---------- policy ----------

function loadPolicyFile(path: string) {
  return compilePolicy(readJson<PolicyDocument>(path));
}

function policyCmd(sub: string | undefined, args: Args): number {
  const file = args._[2] ?? "mandat.policy.json";
  try {
    if (sub === "check") {
      const p = loadPolicyFile(file);
      console.log(`✓ ${file} is valid — ${p.doc.rules.length} rules, ${Object.keys(p.doc.tools ?? {}).length} tool classifications, version ${p.version}`);
      return 0;
    }
    if (sub === "test") {
      const p = loadPolicyFile(file);
      const testsPath = args._[3] ?? file.replace(/\.json$/, ".test.json");
      if (!existsSync(testsPath)) { console.error(`${testsPath} not found.`); return 1; }
      const results = runPolicyTests(p, readJson<PolicyTestCase[]>(testsPath));
      for (const r of results) console.log(`${r.pass ? "✓" : "✗"} ${r.name}${r.pass ? "" : `  — expected ${r.expected}, got ${r.actual} (${r.reasons.join("; ")})`}`);
      const failed = results.filter((r) => !r.pass).length;
      console.log(`\n${results.length - failed}/${results.length} passed`);
      return failed ? 1 : 0;
    }
    if (sub === "eval") {
      const p = loadPolicyFile(file);
      const d = p.evaluate({
        principal: { sub: args.str("user", "cli-user")! },
        agent: { id: args.str("agent", "cli-agent")! },
        tool: { name: args.str("tool", "")! },
        args: JSON.parse(args.str("args", "{}")!),
        session: { tainted: args.bool("tainted") },
      });
      console.log(JSON.stringify(d, null, 2));
      return 0;
    }
  } catch (e) {
    console.error(e instanceof PolicyError ? e.message : `Error: ${(e as Error).message}`);
    return 1;
  }
  console.error("Usage: mandat policy check|test|eval [policy]");
  return 2;
}

function bench(args: Args): number {
  const p = loadPolicyFile(args._[1] ?? "mandat.policy.json");
  const inputs = [
    { tool: "refund", args: { amount: 20, currency: "EUR" } },
    { tool: "refund", args: { amount: 200, currency: "EUR" } },
    { tool: "send_email", args: { to: ["a@example.com", "b@x.test"], subject: "s", body: "b" } },
    { tool: "lookup_order", args: { order_id: "1" } },
  ];
  const n = args.num("n", 100_000);
  const lat: number[] = [];
  for (let i = 0; i < n; i++) {
    const inp = inputs[i % inputs.length]!;
    const t = process.hrtime.bigint();
    p.evaluate({ principal: { sub: "u" }, agent: { id: "a" }, tool: { name: inp.tool }, args: inp.args, session: { tainted: i % 2 === 0 } });
    lat.push(Number(process.hrtime.bigint() - t) / 1000);
  }
  lat.sort((a, b) => a - b);
  const q = (x: number) => lat[Math.floor(x * (lat.length - 1))]!.toFixed(1);
  console.log(`${n} decisions: p50 ${q(0.5)} µs · p99 ${q(0.99)} µs · p99.9 ${q(0.999)} µs · max ${lat.at(-1)!.toFixed(1)} µs  (target p99 < 5000 µs)`);
  return 0;
}

// ---------- ledger ----------

function ledgerPath(args: Args): string {
  if (args._[2]) return args._[2];
  if (existsSync("mandat.config.json")) return join(loadConfig("mandat.config.json").dataDir, "ledger.jsonl");
  return ".mandat/ledger.jsonl";
}

function ledgerCmd(sub: string | undefined, args: Args): number {
  const path = ledgerPath(args);
  if (sub === "verify") {
    const v = verifyLedger(path);
    if (v.ok) console.log(`✓ ${path}: hash chain intact — ${v.count} records${v.count ? `, ${v.first_ts} → ${v.last_ts}` : ""}\n  head ${v.head}`);
    else console.log(`✗ ${path}: ${v.error}`);
    return v.ok ? 0 : 1;
  }
  if (sub === "tail") {
    for (const r of queryRecords(readLedger(path), { limit: args.num("n", 20) }).reverse())
      console.log(`${r.ts}  #${r.seq}  ${describe(r)}`);
    return 0;
  }
  if (sub === "report") {
    const data = buildReport(readLedger(path), { from: args.str("from"), to: args.str("to"), retentionDays: args.str("retention") ? args.num("retention", 0) : undefined });
    const text = args.str("format") === "json" ? JSON.stringify(data, null, 2) : reportToMarkdown(data);
    const out = args.str("out");
    if (out) { writeFileSync(out, text); console.error(`Report written to ${out}`); } else console.log(text);
    return data.integrity.ok ? 0 : 1;
  }
  if (sub === "export") {
    const fmt = args.str("format", "ocsf");
    for (const r of readLedger(path)) console.log(JSON.stringify(fmt === "otel" ? toOtelSpan(r) : toOcsf(r)));
    return 0;
  }
  console.error("Usage: mandat ledger verify|tail|report|export [file]");
  return 2;
}

// ---------- control plane API ----------

function cpTarget(args: Args, role: "admin" | "approver" | "service" = "admin"): { url: string; key: string } {
  let url = args.str("url") ?? process.env.MANDAT_URL;
  let key = args.str("key") ?? process.env.MANDAT_API_KEY;
  const credPath = ".mandat/credentials.json";
  if ((!url || !key) && existsSync(credPath)) {
    const c = readJson<{ url: string; keys: Record<string, string> }>(credPath);
    url ??= c.url;
    key ??= c.keys[role] ?? c.keys.admin;
  }
  if (!url || !key) throw new Error("Control plane URL / API key missing: pass --url and --key, set MANDAT_URL / MANDAT_API_KEY, or run in a directory initialised with `mandat init`.");
  return { url: url.replace(/\/$/, ""), key: key! };
}

async function cp<T = any>(args: Args, method: string, path: string, body?: unknown, role?: "admin" | "approver"): Promise<T> {
  const t = args.bool("login") ? await loginTarget(args) : cpTarget(args, role);
  const res = await fetch(t.url + path, {
    method,
    headers: { authorization: `Bearer ${t.key}`, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${res.status}: ${(data as any).error_description ?? (data as any).error ?? res.statusText}`);
  return data as T;
}

/** `--login`: act as the person signed in with `mandat login` (their IdP ID token is the credential). */
async function loginTarget(args: Args): Promise<{ url: string; key: string }> {
  let url = args.str("url") ?? process.env.MANDAT_URL;
  if (!url && existsSync(".mandat/credentials.json")) url = readJson<{ url: string }>(".mandat/credentials.json").url;
  if (!url) throw new Error("Control plane URL missing: pass --url or set MANDAT_URL.");
  return { url: url.replace(/\/$/, ""), key: await currentIdToken() };
}

async function agentsCmd(sub: string | undefined, args: Args): Promise<number> {
  try {
    if (!sub || sub === "list") {
      const { agents } = await cp(args, "GET", "/api/agents");
      if (!agents.length) console.log("No agents registered.");
      for (const a of agents) console.log(`${a.revoked ? "⛔" : "●"} ${a.id.padEnd(20)} tools: ${a.allowed_tools.join(", ")}  resources: ${a.allowed_resources?.join(", ") || "any"}  versions: ${a.versions?.join(", ") || "any"}`);
      return 0;
    }
    if (sub === "rotate-secret") {
      const id = args._[2];
      if (!id) { console.error("Usage: mandat agents rotate-secret <id> [--revoke-tokens]"); return 2; }
      const r = await cp(args, "POST", `/api/agents/${encodeURIComponent(id)}/rotate-secret`, { revoke_tokens: args.bool("revoke-tokens") });
      console.log(`✓ New secret for ${r.id}\n  client_secret  ${r.client_secret}\n  (store it now; the old secret no longer works${args.bool("revoke-tokens") ? " and its tokens are revoked" : ""})`);
      return 0;
    }
    if (sub === "remove") {
      const id = args._[2];
      if (!id) { console.error("Usage: mandat agents remove <id>"); return 2; }
      await cp(args, "DELETE", `/api/agents/${encodeURIComponent(id)}`);
      console.log(`✓ Removed agent ${id}; its outstanding tokens are revoked.`);
      return 0;
    }
    if (sub === "add") {
      const id = args._[2];
      if (!id || !args.list("tools").length) { console.error("Usage: mandat agents add <id> --tools a,b [--resources URL] [--versions V]"); return 2; }
      const r = await cp(args, "POST", "/api/agents", { id, name: args.str("name"), allowed_tools: args.list("tools"), allowed_resources: args.list("resources"), versions: args.list("versions") });
      console.log(`✓ Registered agent ${r.id}\n  client_id      ${r.id}\n  client_secret  ${r.client_secret}\n  (store the secret now — it is not shown again)`);
      return 0;
    }
  } catch (e) { console.error((e as Error).message); return 1; }
  console.error("Usage: mandat agents list|add|rotate-secret|remove");
  return 2;
}

async function approvalsCmd(sub: string | undefined, args: Args): Promise<number> {
  try {
    if (!sub || sub === "list") {
      const status = args.str("status", "pending");
      const { approvals } = await cp(args, "GET", `/api/approvals${status === "all" ? "" : `?status=${status}`}`, undefined, "approver");
      if (!approvals.length) console.log(`No ${status} approvals.`);
      for (const a of approvals) {
        const c = a.context;
        console.log(`${a.id}  ${a.status.padEnd(8)} ${c.agent.id} → ${c.tool} for ${c.principal.email ?? c.principal.sub}  rule=${c.rule}  ${a.votes.length}/${a.required} votes  expires ${a.expires_at}`);
        console.log(`    args: ${JSON.stringify(c.args)}${c.session_tainted ? "  ⚠ tainted session" : ""}`);
      }
      return 0;
    }
    if (sub === "approve" || sub === "deny") {
      const id = args._[2];
      if (!id) { console.error(`Usage: mandat approvals ${sub} <id>`); return 2; }
      const r = await cp(args, "POST", `/api/approvals/${id}/${sub}`, { comment: args.str("comment") }, "approver");
      console.log(`✓ ${r.id} is now ${r.status} (${r.votes.filter((v: any) => v.decision === "approve").length}/${r.required} approvals)`);
      return 0;
    }
  } catch (e) { console.error((e as Error).message); return 1; }
  console.error("Usage: mandat approvals list|approve|deny");
  return 2;
}

async function revoke(args: Args): Promise<number> {
  const pairs: Array<[string, string]> = [["agent", "agent"], ["user", "subject"], ["task", "task"], ["tenant", "tenant"], ["jti", "jti"]];
  const hit = pairs.find(([flag]) => args.str(flag));
  if (!hit) { console.error("Usage: mandat revoke --agent ID [--version V] | --user SUB | --task ID | --tenant T | --jti ID [--reason R]"); return 2; }
  const type = hit[0] === "agent" && args.str("version") ? "agent_version" : hit[1];
  try {
    const t0 = Date.now();
    const r = await cp(args, "POST", "/api/revocations", { type, value: args.str(hit[0]), version: args.str("version"), reason: args.str("reason") });
    console.log(`✓ Revoked ${r.type} ${r.value}${r.version ? "@" + r.version : ""} (${r.id}) in ${Date.now() - t0} ms; guards enforce it within ~2 s.${r.blocks_issuance ? " New tokens are blocked until lifted." : ""}`);
    return 0;
  } catch (e) { console.error((e as Error).message); return 1; }
}

async function token(args: Args): Promise<number> {
  const t = cpTarget(args);
  const agent = args.str("agent"), secret = args.str("secret"), user = args.str("user"), resource = args.str("resource");
  if (!agent || !secret || !user || !resource) { console.error("Usage: mandat token --agent ID --secret S --user SUB --resource URL [--tools a,b] [--version V]"); return 2; }
  const login = await fetch(`${t.url}/dev/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sub: user, email: args.str("email"), tenant: args.str("tenant") }) });
  if (!login.ok) { console.error(`dev login failed: ${login.status}`); return 1; }
  const { id_token } = (await login.json()) as { id_token: string };
  const form = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: id_token,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    resource,
  });
  if (args.list("tools").length) form.set("authorization_details", JSON.stringify([{ type: "mandat_tool_call", tools: args.list("tools") }]));
  if (args.str("version")) form.set("mandat_agent_version", args.str("version")!);
  const res = await fetch(`${t.url}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + Buffer.from(`${encodeURIComponent(agent)}:${encodeURIComponent(secret)}`).toString("base64") }, body: form });
  const body = await res.json();
  if (!res.ok) { console.error(JSON.stringify(body)); return 1; }
  console.log(args.bool("json") ? JSON.stringify(body, null, 2) : body.access_token);
  return 0;
}

async function bridge(args: Args): Promise<number> {
  const url = args.str("url");
  const agent = args.str("agent");
  const secret = args.str("secret") ?? process.env.MANDAT_AGENT_SECRET;
  if (!url || !agent || !secret) {
    console.error("Usage: mandat bridge --url MCP_URL --agent ID [--mandat URL] [--user SUB] (secret in MANDAT_AGENT_SECRET)");
    return 2;
  }
  const b = new Bridge({
    url,
    mandatUrl: args.str("mandat") ?? process.env.MANDAT_URL ?? "http://127.0.0.1:7400",
    agentId: agent,
    agentSecret: secret,
    agentVersion: args.str("version"),
    subjectToken: process.env.MANDAT_SUBJECT_TOKEN,
    subjectTokenProvider: args.bool("login") ? () => currentIdToken() : undefined,
    user: { sub: args.str("user", "user:local")!, email: args.str("email"), tenant: args.str("tenant") },
    tools: args.list("tools"),
  });
  await b.run();
  return 0;
}

async function loginCmd(args: Args): Promise<number> {
  if (args._[1] === "status") {
    const s = loadSession();
    if (!s) { console.log("Not logged in."); return 1; }
    const left = s.expires_at - Math.floor(Date.now() / 1000);
    console.log(`Logged in as ${s.user.email ?? s.user.sub} (${s.user.sub})
  issuer   ${s.issuer}
  client   ${s.client_id}
  id token ${left > 0 ? `valid ${Math.round(left / 60)} min` : "expired"}${s.refresh_token ? ", refresh token stored" : ", no refresh token (log in again when it expires)"}`);
    return 0;
  }
  const issuer = args.str("issuer") ?? process.env.MANDAT_IDP_ISSUER;
  const clientId = args.str("client-id") ?? process.env.MANDAT_IDP_CLIENT_ID;
  if (!issuer || !clientId) { console.error("Usage: mandat login --issuer https://<tenant>.auth0.com/ --client-id <native app client id> [--port 8765]"); return 2; }
  const port = args.num("port", 8765);
  console.error(`Opening the browser to sign in. Callback: http://127.0.0.1:${port}/callback`);
  try {
    const s = await login({
      issuer, clientId, port,
      extraParams: args.str("organization") ? { organization: args.str("organization")! } : undefined,
      openBrowser: (url) => {
        console.error(`If the browser does not open, visit:
  ${url}`);
        if (!args.bool("no-browser")) openSystemBrowser(url);
      },
    });
    saveSession(s);
    console.log(`✓ Logged in as ${s.user.email ?? s.user.sub} (${s.user.sub})`);
    if (!s.refresh_token) console.log("  Note: no refresh token was issued; run `mandat login` again when the session expires.");
    return 0;
  } catch (e) {
    console.error(`Login failed: ${(e as Error).message}`);
    return 1;
  }
}

async function idpCmd(sub: string | undefined, args: Args): Promise<number> {
  const cfgPath = args.str("config", "mandat.config.json")!;
  if (!existsSync(cfgPath)) { console.error(`${cfgPath} not found — run \`mandat init\` first.`); return 1; }
  // Edit the raw file (not loadConfig) so ${env:…} placeholders are preserved.
  const raw = readJson<ControlPlaneConfig>(cfgPath);
  if (!sub || sub === "list") {
    const list = raw.trustedIssuers ?? [];
    if (!list.length) console.log("No trusted identity providers.");
    for (const t of list) console.log(`● ${t.issuer}
    audience ${JSON.stringify(t.audience)}  jwks ${t.jwks_uri}${t.tenant_claim ? `  tenant claim ${t.tenant_claim}` : ""}`);
    console.log(`Dev IdP: ${raw.devIdp ? "ENABLED (anyone can mint user tokens)" : "disabled"}`);
    return 0;
  }
  if (sub === "add") {
    const issuer = args.str("issuer");
    const clientId = args.str("client-id");
    if (!issuer || !clientId) { console.error("Usage: mandat idp add --issuer URL --client-id ID [--tenant-claim CLAIM] [--disable-dev-idp]"); return 2; }
    let meta;
    try { meta = await discover(issuer); } catch (e) { console.error((e as Error).message); return 1; }
    const entry = { issuer: meta.issuer, jwks_uri: meta.jwks_uri, audience: clientId, ...(args.str("tenant-claim") ? { tenant_claim: args.str("tenant-claim") } : {}) };
    raw.trustedIssuers = [...(raw.trustedIssuers ?? []).filter((t) => t.issuer !== meta.issuer), entry];
    if (args.bool("disable-dev-idp")) raw.devIdp = false;
    writeJsonAtomic(cfgPath, raw);
    console.log(`✓ Trusting ${meta.issuer} (ID tokens for client ${clientId})${args.bool("disable-dev-idp") ? "; dev IdP disabled" : ""}
  Restart \`mandat serve\` to apply.`);
    return 0;
  }
  console.error("Usage: mandat idp add|list");
  return 2;
}

async function usersCmd(sub: string | undefined, args: Args): Promise<number> {
  try {
    if (!sub || sub === "list") {
      const r = await cp(args, "GET", "/api/users");
      console.log(`Console sign-in: ${r.login.enabled ? `enabled (${r.login.issuer})` : "disabled (run mandat idp add)"}`);
      if (!r.users.length) console.log("No people have roles yet. Grant one: mandat users grant --email you@example.com --roles admin,approver");
      for (const u of r.users) console.log(`● ${u.id.padEnd(32)} ${u.roles.join(", ")}${u.sub && u.sub !== u.id ? `  (sub ${u.sub})` : ""}  granted by ${u.by}`);
      return 0;
    }
    if (sub === "grant") {
      const roles = args.list("roles");
      if ((!args.str("email") && !args.str("sub")) || !roles.length) { console.error("Usage: mandat users grant --email E | --sub SUB --roles approver[,admin,auditor]"); return 2; }
      const u = await cp(args, "POST", "/api/users", { email: args.str("email"), sub: args.str("sub"), roles });
      console.log(`✓ ${u.id} now has: ${u.roles.join(", ")}`);
      return 0;
    }
    if (sub === "revoke") {
      const id = args._[2];
      if (!id) { console.error("Usage: mandat users revoke <email-or-sub>"); return 2; }
      const r = await cp(args, "DELETE", `/api/users/${encodeURIComponent(id)}`);
      console.log(`✓ Removed access for ${r.removed}`);
      return 0;
    }
  } catch (e) { console.error((e as Error).message); return 1; }
  console.error("Usage: mandat users list|grant|revoke");
  return 2;
}

async function web(args: Args): Promise<number> {
  const port = args.num("port", 7800);
  const host = args.str("host", "127.0.0.1")!;
  const site = createScanWebServer({
    port, host,
    allowPrivate: args.bool("allow-private"),
    trustProxy: args.bool("trust-proxy"),
    rateLimit: { max: args.num("rate", 10), windowMs: 10 * 60_000 },
  });
  const addr = await site.listen();
  console.log(`Mandat MCP Scanner at ${addr}`);
  if (args.bool("allow-private")) console.log("  ⚠ private addresses allowed (--allow-private): do not expose this to the internet");
  await new Promise<void>((r) => { process.once("SIGINT", r); process.once("SIGTERM", r); });
  await site.close();
  return 0;
}
