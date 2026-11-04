// Public scanner page: paste an MCP server URL (or an MCP client config) and get the report in the browser,
// with a shareable link. The "scanner as a magnet" of the PRD (section 12).
//
// Safe to host: every outbound request goes through the SSRF-safe fetch (no private or reserved addresses,
// no redirects, capped bodies), the intrusive DCR probe is never run, and scans are rate-limited per client.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { scanRemote } from "./remote.ts";
import { scanServers } from "./static.ts";
import { createSafeFetch } from "./safe-fetch.ts";
import { sortFindings, type ScanReport, type Severity } from "./findings.ts";
import { HttpError, randomId, readBody, sendJson } from "../util.ts";

export interface ScanWebOptions {
  port: number;
  host?: string;
  /** Allow scanning private / loopback addresses. Only for self-hosting on a trusted network. */
  allowPrivate?: boolean;
  /** Scans per client IP per window. Default 10 per 10 minutes. */
  rateLimit?: { max: number; windowMs: number };
  /** Concurrent scans across all clients. Default 4. */
  maxConcurrent?: number;
  /** Use the first X-Forwarded-For address as the client IP (behind a reverse proxy). */
  trustProxy?: boolean;
  /** Header set by your platform's proxy with the client IP, e.g. "fly-client-ip" on Fly.io. Preferred over trustProxy. */
  clientIpHeader?: string;
  /** How many reports to keep for share links (in memory). Default 1000. */
  maxReports?: number;
}

export interface StoredScan { id: string; created: string; grade: string; report: ScanReport }

const WEB_DIR = fileURLToPath(new URL("./web/", import.meta.url));
const asset = (name: string) => readFileSync(join(WEB_DIR, name), "utf8");
const REPORT_TTL_MS = 7 * 86_400_000;

/** A (clean) .. F (critical finding); "?" when the server could not be reached. */
export function grade(report: ScanReport): string {
  if (report.findings.some((f) => f.rule === "MDT-R000")) return "?";
  const order: Array<[Severity, string]> = [["critical", "F"], ["high", "D"], ["medium", "C"], ["low", "B"]];
  for (const [sev, g] of order) if (report.findings.some((f) => f.severity === sev)) return g;
  return "A";
}

export function createScanWebServer(o: ScanWebOptions): { server: Server; listen(): Promise<string>; close(): Promise<void>; reports: Map<string, StoredScan> } {
  const safeFetch = createSafeFetch({ allowPrivate: o.allowPrivate });
  const limit = o.rateLimit ?? { max: 10, windowMs: 10 * 60_000 };
  const maxConcurrent = o.maxConcurrent ?? 4;
  const maxReports = o.maxReports ?? 1000;
  const reports = new Map<string, StoredScan>();
  const hits = new Map<string, number[]>();
  let running = 0;

  const clientIp = (req: IncomingMessage) => {
    const platform = o.clientIpHeader ? req.headers[o.clientIpHeader.toLowerCase()] : undefined;
    if (typeof platform === "string" && platform) return platform.trim();
    const fwd = req.headers["x-forwarded-for"];
    if (o.trustProxy && typeof fwd === "string") return fwd.split(",")[0]!.trim();
    return req.socket.remoteAddress ?? "unknown";
  };

  const rateLimited = (ip: string) => {
    const now = Date.now();
    const recent = (hits.get(ip) ?? []).filter((t) => now - t < limit.windowMs);
    if (recent.length >= limit.max) { hits.set(ip, recent); return true; }
    recent.push(now);
    hits.set(ip, recent);
    if (hits.size > 50_000) hits.clear();
    return false;
  };

  const store = (report: ScanReport): StoredScan => {
    const now = Date.now();
    for (const [k, v] of reports) if (now - Date.parse(v.created) > REPORT_TTL_MS || reports.size >= maxReports) reports.delete(k); else break;
    const s: StoredScan = { id: randomId("", 9), created: new Date(now).toISOString(), grade: grade(report), report: { ...report, findings: sortFindings(report.findings) } };
    reports.set(s.id, s);
    return s;
  };

  const page = (res: ServerResponse) => {
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    });
    res.end(asset("index.html"));
  };

  const guardedScan = async <T>(req: IncomingMessage, fn: () => Promise<T>): Promise<T> => {
    if (rateLimited(clientIp(req))) throw new HttpError(429, "rate_limited", `Too many scans: at most ${limit.max} per ${Math.round(limit.windowMs / 60_000)} minutes. Try again later.`);
    if (running >= maxConcurrent) throw new HttpError(503, "busy", "The scanner is busy, try again in a few seconds.");
    running++;
    try { return await fn(); } finally { running--; }
  };

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://scanner");
      const p = url.pathname;
      const m = req.method ?? "GET";
      if (m === "GET" && (p === "/" || /^\/r\/[\w-]+$/.test(p))) return page(res);
      if (m === "GET" && p === "/app.js") { res.writeHead(200, { "content-type": "text/javascript; charset=utf-8" }); res.end(asset("app.js")); return; }
      if (m === "GET" && p === "/app.css") { res.writeHead(200, { "content-type": "text/css; charset=utf-8" }); res.end(asset("app.css")); return; }
      if (m === "GET" && p === "/favicon.ico") { res.writeHead(204).end(); return; }
      if (m === "GET" && p === "/healthz") return sendJson(res, 200, { ok: true, reports: reports.size, running });

      const body = async () => {
        try { return JSON.parse(await readBody(req, 200_000)) as Record<string, unknown>; } catch { throw new HttpError(400, "invalid_json", "Body must be JSON"); }
      };

      if (m === "POST" && p === "/api/scan") {
        const b = await body();
        const target = String(b.url ?? "").trim();
        let parsed: URL;
        try { parsed = new URL(target); } catch { throw new HttpError(400, "invalid_url", "Enter a full URL, e.g. https://mcp.example.com/mcp"); }
        if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new HttpError(400, "invalid_url", "Only http(s) URLs can be scanned");
        if (parsed.username || parsed.password) throw new HttpError(400, "invalid_url", "URLs with credentials are not accepted");
        const report = await guardedScan(req, async () => {
          // The target itself must be public; the safe fetch then also guards every discovered URL.
          try { await safeFetch(parsed.origin, { method: "HEAD", signal: AbortSignal.timeout(8000) }); } catch (e) {
            if ((e as Error).name === "BlockedAddressError" || /private or reserved|not allowed/.test((e as Error).message))
              throw new HttpError(400, "blocked_target", `${parsed.hostname} is a private or reserved address. This page only scans public servers; scan local servers with \`npx mandat scan <url>\`.`);
          }
          return scanRemote(parsed.toString(), { active: false, timeoutMs: 8000, fetch: safeFetch });
        });
        return sendJson(res, 200, store(report));
      }

      if (m === "POST" && p === "/api/scan-config") {
        const b = await body();
        const text = String(b.config ?? "");
        if (!text.trim()) throw new HttpError(400, "invalid_request", "Paste the contents of an MCP client config (claude_desktop_config.json, .mcp.json, …)");
        let json: any;
        try { json = JSON.parse(text.replace(/^\s*\/\/.*$/gm, "").replace(/,(\s*[}\]])/g, "$1")); } catch (e) { throw new HttpError(400, "invalid_json", `Not valid JSON: ${(e as Error).message}`); }
        const servers = json.mcpServers ?? json.servers ?? json.mcp?.servers ?? json.context_servers;
        if (!servers || typeof servers !== "object") throw new HttpError(400, "invalid_request", 'No MCP servers found: expected an "mcpServers" (or "servers") object');
        const report = await guardedScan(req, async () => scanServers(servers, "pasted config", text));
        return sendJson(res, 200, store(report));
      }

      const get = /^\/api\/scan\/([\w-]+)$/.exec(p);
      if (m === "GET" && get) {
        const s = reports.get(get[1]!);
        if (!s) throw new HttpError(404, "not_found", "This report has expired or never existed. Run the scan again.");
        return sendJson(res, 200, s);
      }
      throw new HttpError(404, "not_found", "Not found");
    } catch (e) {
      if (e instanceof HttpError) return sendJson(res, e.status, { error: e.code, error_description: e.message });
      console.error("[mandat web]", e);
      return sendJson(res, 500, { error: "server_error", error_description: "Internal error" });
    }
  });

  return {
    server,
    reports,
    listen: () => new Promise((resolve, reject) => {
      server.once("error", (e: NodeJS.ErrnoException) => reject(e.code === "EADDRINUSE" ? new Error(`Port ${o.port} is already in use. Use --port.`) : e));
      server.listen(o.port, o.host ?? "127.0.0.1", () => {
        const a = server.address();
        resolve(typeof a === "object" && a ? `http://${o.host ?? "127.0.0.1"}:${a.port}` : "");
      });
    }),
    close: () => new Promise((r) => { server.close(() => r()); server.closeAllConnections(); }),
  };
}
