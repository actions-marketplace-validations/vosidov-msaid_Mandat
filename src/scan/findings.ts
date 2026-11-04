// Finding model + output formats (text, JSON, SARIF 2.1.0, HTML).

import { VERSION } from "../version.ts";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
  fixCode?: string;
  /** OWASP Top 10 for Agentic Applications (ASIxx) / OWASP MCP Top 10 (MCPxx) references. */
  owasp: string[];
  location?: { url?: string; file?: string; line?: number; server?: string };
}

export interface ScanReport {
  target: string;
  kind: "remote" | "config" | "source";
  scanned_at: string;
  findings: Finding[];
  passed: string[];
  info?: Record<string, unknown>;
}

export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

export function sortFindings(f: Finding[]): Finding[] {
  return [...f].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

export function shouldFail(reports: ScanReport[], failOn: Severity | "none"): boolean {
  if (failOn === "none") return false;
  return reports.some((r) => r.findings.some((f) => severityRank(f.severity) <= severityRank(failOn)));
}

const COLORS: Record<Severity, string> = { critical: "\x1b[41m\x1b[97m", high: "\x1b[31m", medium: "\x1b[33m", low: "\x1b[36m", info: "\x1b[90m" };
const RESET = "\x1b[0m";

export function formatText(reports: ScanReport[], color = process.stdout.isTTY): string {
  const c = (s: Severity, t: string) => (color ? `${COLORS[s]}${t}${RESET}` : t);
  const out: string[] = [];
  for (const r of reports) {
    out.push(`\nMandat scan — ${r.kind}: ${r.target}`);
    out.push("─".repeat(72));
    if (!r.findings.length) out.push("  No findings.");
    for (const f of sortFindings(r.findings)) {
      const loc = f.location?.file ? ` (${f.location.file}${f.location.line ? `:${f.location.line}` : ""})` : f.location?.server ? ` [${f.location.server}]` : "";
      out.push(`  ${c(f.severity, f.severity.toUpperCase().padEnd(8))} ${f.rule}  ${f.title}${loc}`);
      out.push(`           ${f.detail}`);
      out.push(`           Fix: ${f.fix}`);
      if (f.fixCode) out.push(f.fixCode.split("\n").map((l) => `             ${l}`).join("\n"));
      if (f.owasp.length) out.push(`           OWASP: ${f.owasp.join(", ")}`);
      out.push("");
    }
    if (r.passed.length) out.push(`  Passed: ${r.passed.join(" · ")}`);
    const counts = SEVERITIES.map((s) => [s, r.findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n);
    out.push(`  Summary: ${counts.length ? counts.map(([s, n]) => `${n} ${s}`).join(", ") : "clean"}`);
  }
  return out.join("\n") + "\n";
}

export function formatSarif(reports: ScanReport[]): string {
  const rules = new Map<string, Finding>();
  for (const r of reports) for (const f of r.findings) if (!rules.has(f.rule)) rules.set(f.rule, f);
  const level = (s: Severity) => (s === "critical" || s === "high" ? "error" : s === "medium" ? "warning" : "note");
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "mandat-scan",
          version: VERSION,
          rules: [...rules.values()].map((f) => ({
            id: f.rule,
            name: f.title.replace(/[^A-Za-z0-9]+/g, ""),
            shortDescription: { text: f.title },
            help: { text: f.fix + (f.fixCode ? "\n\n" + f.fixCode : "") },
            properties: { tags: ["security", ...f.owasp], "security-severity": { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "0.0" }[f.severity] },
          })),
        },
      },
      results: reports.flatMap((r) => r.findings.map((f) => ({
        ruleId: f.rule,
        level: level(f.severity),
        message: { text: `${f.title}: ${f.detail}` },
        locations: [{
          physicalLocation: f.location?.file
            ? { artifactLocation: { uri: f.location.file.replace(/\\/g, "/") }, region: { startLine: f.location.line ?? 1 } }
            : { artifactLocation: { uri: f.location?.url ?? r.target } },
        }],
      }))),
    }],
  };
  return JSON.stringify(sarif, null, 2);
}

const esc = (s: string) => s.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);

export function formatHtml(reports: ScanReport[]): string {
  const body = reports.map((r) => `
  <section>
    <h2>${esc(r.kind)} · ${esc(r.target)}</h2>
    <p class="meta">Scanned ${esc(r.scanned_at)} · ${r.findings.length} findings · passed: ${esc(r.passed.join(", ") || "—")}</p>
    ${sortFindings(r.findings).map((f) => `
    <article class="f ${f.severity}">
      <header><span class="sev">${f.severity}</span> <code>${esc(f.rule)}</code> <strong>${esc(f.title)}</strong></header>
      <p>${esc(f.detail)}</p>
      <p><b>Fix:</b> ${esc(f.fix)}</p>
      ${f.fixCode ? `<pre>${esc(f.fixCode)}</pre>` : ""}
      ${f.owasp.length ? `<p class="meta">OWASP: ${esc(f.owasp.join(", "))}</p>` : ""}
    </article>`).join("")}
  </section>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mandat scan report</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1d1d1f;background:#fafafa}
h1{font-size:1.6rem}h2{font-size:1.15rem;margin-top:2rem}.meta{color:#666;font-size:.85rem}
.f{background:#fff;border:1px solid #e3e3e3;border-left:5px solid #999;border-radius:6px;padding:.75rem 1rem;margin:.75rem 0}
.f.critical{border-left-color:#b00020}.f.high{border-left-color:#e53935}.f.medium{border-left-color:#f9a825}.f.low{border-left-color:#039be5}
.sev{text-transform:uppercase;font-size:.75rem;font-weight:700;letter-spacing:.04em}
pre{background:#f3f3f3;padding:.6rem;border-radius:4px;overflow-x:auto;font-size:.82rem}
</style></head><body><h1>Mandat scan report</h1>${body}</body></html>`;
}
