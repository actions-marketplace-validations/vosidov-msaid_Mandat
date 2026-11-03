// Static analysis of MCP client configurations (Claude Desktop, Cursor, VS Code, Windsurf…) and of
// MCP server source code. Detects supply-chain, command-execution and exfiltration risks.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";
import type { Finding, ScanReport } from "./findings.ts";

interface ServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  serverUrl?: string;
  type?: string;
  headers?: Record<string, string>;
}

/** Popular legitimate MCP packages, used for typosquat distance checks. */
const KNOWN_PACKAGES = [
  "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-postgres",
  "@modelcontextprotocol/server-slack", "@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-brave-search", "@modelcontextprotocol/server-google-maps", "@modelcontextprotocol/server-everything",
  "@modelcontextprotocol/server-sequential-thinking", "@modelcontextprotocol/inspector", "@playwright/mcp", "@supabase/mcp-server-supabase",
  "@notionhq/notion-mcp-server", "@stripe/mcp", "@sentry/mcp-server", "@azure-devops/mcp", "@cloudflare/mcp-server-cloudflare",
  "mcp-server-fetch", "mcp-server-git", "mcp-server-time", "mcp-server-sqlite", "firecrawl-mcp", "figma-developer-mcp", "mcp-remote",
];

/** Package versions publicly reported as malicious. */
const MALICIOUS: Array<{ pkg: string; versions: (v: string | null) => boolean; why: string }> = [
  { pkg: "postmark-mcp", versions: (v) => !v || cmpVersion(v, "1.0.16") >= 0, why: "versions >= 1.0.16 silently BCC every e-mail to an attacker address (Sep 2025)" },
  { pkg: "litellm", versions: (v) => !v || ["1.82.7", "1.82.8", "1.107.0"].includes(v), why: "1.82.7, 1.82.8 and 1.107.0 were published from stolen CI credentials with a credential stealer (2026)" },
];

const RUNNERS: Record<string, { pinned: (spec: string) => boolean; eco: "npm" | "pypi" }> = {
  npx: { pinned: (s) => /^(@[^/]+\/)?[^@]+@\d+\.\d+\.\d+/.test(s), eco: "npm" },
  bunx: { pinned: (s) => /^(@[^/]+\/)?[^@]+@\d+\.\d+\.\d+/.test(s), eco: "npm" },
  pnpx: { pinned: (s) => /^(@[^/]+\/)?[^@]+@\d+\.\d+\.\d+/.test(s), eco: "npm" },
  uvx: { pinned: (s) => /==\d/.test(s) || /@\d+\.\d+/.test(s), eco: "pypi" },
  pipx: { pinned: (s) => /==\d/.test(s), eco: "pypi" },
};

const SHELLS = ["sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"];
const SECRET_ENV = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|CREDENTIALS?)/i;

export function scanConfigFile(path: string): ScanReport {
  const text = readFileSync(path, "utf8");
  let json: any;
  try {
    json = JSON.parse(stripJsonComments(text));
  } catch (e) {
    return { target: path, kind: "config", scanned_at: new Date().toISOString(), passed: [], findings: [{ rule: "MDT-C000", severity: "info", title: "Not valid JSON", detail: (e as Error).message, fix: "Fix the JSON syntax.", owasp: [], location: { file: path } }] };
  }
  const servers: Record<string, ServerEntry> = json.mcpServers ?? json.servers ?? json.mcp?.servers ?? json.context_servers ?? {};
  return scanServers(servers, path, text);
}

export function scanServers(servers: Record<string, ServerEntry>, file: string, rawText = ""): ScanReport {
  const findings: Finding[] = [];
  const lineOf = (needle: string) => {
    const i = rawText.indexOf(needle);
    return i < 0 ? undefined : rawText.slice(0, i).split("\n").length;
  };
  for (const [name, s] of Object.entries(servers)) {
    const location = { file, server: name, line: lineOf(`"${name}"`) };
    const add = (f: Omit<Finding, "location">) => findings.push({ ...f, location });
    const cmd = (s.command ?? "").split(/[\\/]/).pop()!.toLowerCase();
    const args = (s.args ?? []).map(String);
    const all = [s.command ?? "", ...args].join(" ");

    // Package runners: pinning, malicious versions, typosquats
    const runner = RUNNERS[cmd.replace(/\.(cmd|exe)$/, "")];
    if (runner) {
      const spec = args.find((a) => !a.startsWith("-"));
      if (spec) {
        const { pkg, version } = parseSpec(spec, runner.eco);
        if (!runner.pinned(spec) || /@latest\b/.test(spec)) {
          add({
            rule: "MDT-C001", severity: "high", title: `Unpinned package '${pkg}' executed by ${cmd}`,
            detail: `${cmd}${args.includes("-y") || args.includes("--yes") ? " -y" : ""} fetches and runs whatever version is current. A compromised maintainer account ships code straight to this machine (postmark-mcp, LiteLLM 2026).`,
            fix: `Pin an exact, reviewed version and verify provenance.`,
            fixCode: `"args": ["-y", "${pkg}@<exact-version>"]`,
            owasp: ["ASI04", "MCP04"],
          });
        }
        const bad = MALICIOUS.find((m) => m.pkg === pkg && m.versions(version));
        if (bad) add({ rule: "MDT-C002", severity: "critical", title: `Known-malicious package '${pkg}${version ? "@" + version : ""}'`, detail: bad.why, fix: "Remove it, rotate every credential it could access, and audit outbound traffic.", owasp: ["ASI04", "MCP04"] });
        const squat = KNOWN_PACKAGES.find((k) => k !== pkg && levenshtein(k, pkg) <= 2 && pkg.length > 5);
        if (squat) add({ rule: "MDT-C003", severity: "high", title: `Possible typosquat: '${pkg}' looks like '${squat}'`, detail: "Package names one or two characters away from popular MCP servers are a common supply-chain lure.", fix: `Verify the publisher; did you mean '${squat}'?`, owasp: ["ASI04", "MCP04"] });
      }
    }

    // Shell interpreters / remote code
    if (SHELLS.includes(cmd) && args.some((a) => ["-c", "/c", "-command", "-encodedcommand", "/k"].includes(a.toLowerCase()))) {
      add({ rule: "MDT-C004", severity: "high", title: "MCP server launched through a shell", detail: `'${all.slice(0, 120)}' runs an arbitrary shell string. stdio transports execute whatever command they are given (CVE-2026-30623 class).`, fix: "Invoke the server binary directly with an argument array; never build stdio commands from untrusted input.", owasp: ["ASI05", "MCP05"] });
    }
    if (/(curl|wget|iwr|invoke-webrequest)[^|]*\|\s*(sh|bash|iex|python)/i.test(all) || /\beval\b/.test(all)) {
      add({ rule: "MDT-C005", severity: "critical", title: "Remote code piped into an interpreter", detail: `'${all.slice(0, 120)}' downloads and executes code at every start.`, fix: "Install a pinned, verified artifact instead.", owasp: ["ASI04", "ASI05", "MCP05"] });
    }

    // Containers
    if (cmd === "docker" || cmd === "podman") {
      if (args.includes("--privileged")) add({ rule: "MDT-C010", severity: "high", title: "Container runs --privileged", detail: "A privileged container is effectively root on the host.", fix: "Drop --privileged; grant only needed capabilities.", owasp: ["ASI05"] });
      const mount = args.find((a, i) => (args[i - 1] === "-v" || args[i - 1] === "--volume") && /^(\/|~|[A-Za-z]:\\?):/.test(a));
      if (mount) add({ rule: "MDT-C010", severity: "high", title: "Container mounts the host root / home", detail: `Volume '${mount}' exposes the whole filesystem to the tool.`, fix: "Mount only the directories the server needs, read-only where possible.", owasp: ["ASI02", "MCP10"] });
      if (args.some((a, i) => a === "--network=host" || (a === "--network" && args[i + 1] === "host"))) add({ rule: "MDT-C010", severity: "medium", title: "Container shares the host network", detail: "--network host lets the tool reach every local service.", fix: "Use an isolated network.", owasp: ["ASI02"] });
      const img = args.find((a) => /^[\w.\-/]+(:[\w.\-]+)?(@sha256:[a-f0-9]{64})?$/.test(a) && a.includes("/") && !a.startsWith("-"));
      if (img && !img.includes("@sha256:")) add({ rule: "MDT-C001", severity: "medium", title: `Container image '${img}' not pinned by digest`, detail: "Tags are mutable; the image can change under you.", fix: "Reference the image by digest (image@sha256:…).", owasp: ["ASI04", "MCP04"] });
    }

    // Filesystem breadth
    if (/server-filesystem|filesystem/i.test(all)) {
      const broad = args.find((a) => ["/", "~", "$HOME", "%USERPROFILE%", "C:\\", "C:/", "/Users", "/home"].includes(a.replace(/[\\/]+$/, "") || "/"));
      if (broad) add({ rule: "MDT-C009", severity: "medium", title: `Filesystem server exposes '${broad}'`, detail: "Agents can read SSH keys, cloud credentials and other configs, then exfiltrate them via another tool.", fix: "Allow-list only project directories.", owasp: ["ASI02", "MCP10"] });
    }

    // Network binding
    if (/0\.0\.0\.0|--host[= ]::(\s|$)/.test(all) || Object.values(s.env ?? {}).some((v) => v === "0.0.0.0"))
      add({ rule: "MDT-C008", severity: "medium", title: "Server binds to all interfaces", detail: "0.0.0.0 exposes a local MCP server to the LAN — often without authentication.", fix: "Bind to 127.0.0.1 for local servers.", owasp: ["MCP07", "MCP09"] });

    // Secrets
    for (const [k, v] of Object.entries(s.env ?? {})) {
      if (SECRET_ENV.test(k) && typeof v === "string" && v.length >= 8 && !/^\$\{|^\$[A-Z_]|^%[A-Z_]+%$|^<.*>$|^op:\/\/|^env:/.test(v))
        add({ rule: "MDT-C006", severity: "medium", title: `Plain-text secret in env '${k}'`, detail: "Long-lived credentials stored in a config file are readable by every tool that can read files.", fix: "Reference a secret manager or environment variable (e.g. \"${env:" + k + "}\"); prefer short-lived OAuth tokens.", owasp: ["MCP01", "ASI03"] });
    }
    for (const [k, v] of Object.entries(s.headers ?? {})) {
      if (/^authorization$/i.test(k) && /^Bearer\s+[A-Za-z0-9._~+/-]{12,}/.test(v) && !/\$\{/.test(v))
        add({ rule: "MDT-C011", severity: "medium", title: "Static bearer token in remote server config", detail: "Static tokens (29% of MCP servers) never expire and are not bound to a user or task.", fix: "Use the MCP OAuth flow so tokens are short-lived and audience-bound.", owasp: ["MCP01", "MCP07"] });
    }

    // Remote transport
    const remote = s.url ?? s.serverUrl;
    if (remote) {
      try {
        const u = new URL(remote);
        if (u.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(u.hostname))
          add({ rule: "MDT-C007", severity: "high", title: "Remote MCP server over plain HTTP", detail: `${remote} — tokens and tool data in clear text.`, fix: "Use https://.", owasp: ["MCP07"] });
      } catch { /* not a URL */ }
    }
  }
  const passed = findings.length ? [] : ["no-issues"];
  return { target: file, kind: "config", scanned_at: new Date().toISOString(), findings, passed, info: { servers: Object.keys(servers) } };
}

// ---------- source scan ----------

const SOURCE_RULES: Array<{ rule: string; severity: Finding["severity"]; ext: string[]; re: RegExp; title: string; fix: string; owasp: string[] }> = [
  { rule: "MDT-S001", severity: "high", ext: [".js", ".mjs", ".cjs", ".ts", ".mts"], re: /(?<![.\w])eval\s*\((?!\s*\w+\s*:)|new\s+Function\s*\(/, title: "Dynamic code evaluation", fix: "Never evaluate model- or user-provided strings.", owasp: ["ASI05", "MCP05"] },
  { rule: "MDT-S002", severity: "high", ext: [".js", ".mjs", ".cjs", ".ts", ".mts"], re: /(?<![.\w])(exec|execSync)\s*\(\s*[`'"][^`'"]*\$\{|(?<![.\w])(exec|execSync)\s*\(\s*[a-zA-Z_]+\s*[+,)]|spawn\s*\([^)]*shell\s*:\s*true/, title: "Shell command built from variables", fix: "Use execFile/spawn with an argument array and an allow-list of commands.", owasp: ["ASI05", "MCP05"] },
  { rule: "MDT-S002", severity: "high", ext: [".py"], re: /subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(/, title: "Shell command execution", fix: "Use subprocess.run([...], shell=False) with validated arguments.", owasp: ["ASI05", "MCP05"] },
  { rule: "MDT-S001", severity: "high", ext: [".py"], re: /(?<![.\w])(eval|exec)\s*\((?!\s*\))/, title: "Dynamic code evaluation", fix: "Never evaluate model- or user-provided strings.", owasp: ["ASI05", "MCP05"] },
  { rule: "MDT-S003", severity: "medium", ext: [".js", ".mjs", ".cjs", ".ts", ".mts", ".py"], re: /(listen\s*\([^)]*|host\s*[:=]\s*)["']0\.0\.0\.0["']/i, title: "Listens on all interfaces", fix: "Bind to 127.0.0.1 unless behind an authenticating reverse proxy.", owasp: ["MCP07", "MCP09"] },
  { rule: "MDT-S004", severity: "high", ext: [".js", ".mjs", ".cjs", ".ts", ".mts"], re: /authorization\s*:\s*(req|request|extra|ctx)\.(headers\.authorization|authInfo\.token|headers\[["']authorization["']\])/i, title: "Token passthrough to downstream API", fix: "Forbidden by the MCP spec: exchange for a downstream token (RFC 8693) instead of forwarding the client's token.", owasp: ["MCP01", "ASI03"] },
  { rule: "MDT-S004", severity: "high", ext: [".py"], re: /["']Authorization["']\s*:\s*request\.headers\[["']Authorization["']\]/, title: "Token passthrough to downstream API", fix: "Exchange for a downstream token instead of forwarding the client's token.", owasp: ["MCP01", "ASI03"] },
  { rule: "MDT-S005", severity: "info", ext: [".js", ".mjs", ".ts", ".mts"], re: /StreamableHTTPServerTransport|SSEServerTransport/, title: "HTTP MCP transport — check authentication", fix: "Ensure every request passes bearer authentication (requireBearerAuth + guard.sdkTokenVerifier()).", owasp: ["MCP07"] },
];

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".venv", "venv", "__pycache__", ".mandat", "coverage"]);

export function scanSource(dir: string, maxFiles = 5000): ScanReport {
  const findings: Finding[] = [];
  let files = 0;
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      if (files >= maxFiles) return;
      const p = join(d, name);
      const st = statSync(p);
      if (st.isDirectory()) { if (!SKIP_DIRS.has(name)) walk(p); continue; }
      const ext = extname(name);
      const rules = SOURCE_RULES.filter((r) => r.ext.includes(ext));
      if (!rules.length || st.size > 1_000_000) continue;
      files++;
      const lines = readFileSync(p, "utf8").split("\n");
      const hasAuth = lines.some((l) => /requireBearerAuth|sdkTokenVerifier|McpHttpServer|guard\.verify/.test(l));
      lines.forEach((line, i) => {
        if (/^\s*(\/\/|#|\/?\*)/.test(line)) return;
        for (const r of rules) {
          if (!r.re.test(line)) continue;
          if (r.rule === "MDT-S005" && hasAuth) continue;
          findings.push({ rule: r.rule, severity: r.severity, title: r.title, detail: line.trim().slice(0, 160), fix: r.fix, owasp: r.owasp, location: { file: relative(process.cwd(), p) || p, line: i + 1 } });
        }
      });
    }
  };
  walk(dir);
  return { target: dir, kind: "source", scanned_at: new Date().toISOString(), findings, passed: findings.length ? [] : ["no-issues"], info: { files } };
}

// ---------- helpers ----------

function parseSpec(spec: string, eco: "npm" | "pypi"): { pkg: string; version: string | null } {
  if (eco === "pypi") {
    const m = /^([A-Za-z0-9_.\-[\]]+?)(?:==|@)([\w.]+)?$/.exec(spec);
    return m ? { pkg: m[1]!.toLowerCase(), version: m[2] ?? null } : { pkg: spec.toLowerCase(), version: null };
  }
  const at = spec.lastIndexOf("@");
  if (at > 0) return { pkg: spec.slice(0, at), version: spec.slice(at + 1) || null };
  return { pkg: spec, version: null };
}

function cmpVersion(a: string, b: string): number {
  const pa = a.split(".").map((x) => parseInt(x, 10) || 0), pb = b.split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
}

export function levenshtein(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 3) return 99;
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0]!;
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j]!;
      dp[j] = Math.min(dp[j]! + 1, dp[j - 1]! + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length]!;
}

function stripJsonComments(s: string): string {
  // JSONC (VS Code / Cursor): drop // and /* */ comments outside strings, and trailing commas.
  let out = "", inStr = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!, n = s[i + 1];
    if (inStr) { out += c; if (c === "\\") { out += n ?? ""; i++; } else if (c === '"') inStr = false; continue; }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === "/" && n === "/") { while (i < s.length && s[i] !== "\n") i++; out += "\n"; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++; i++; continue; }
    out += c;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}
