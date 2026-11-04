// Mandat MCP Scanner page. Report text can come from the scanned server, so it is only ever
// inserted as text nodes (never innerHTML).
"use strict";

const $ = (s) => document.querySelector(s);

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
  return el;
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const GRADE_TEXT = {
  A: "No issues found by the passive checks.",
  B: "Minor issues worth fixing.",
  C: "Moderate issues: fix them before production.",
  D: "Serious issues: agents or attackers can likely misuse this server.",
  F: "Critical: tools or data are exposed right now.",
  "?": "The server could not be reached.",
};

// ---------- tabs ----------
function selectTab(which) {
  const url = which === "url";
  $("#tab-url").setAttribute("aria-selected", String(url));
  $("#tab-config").setAttribute("aria-selected", String(!url));
  $("#form-url").hidden = !url;
  $("#form-config").hidden = url;
}
$("#tab-url").addEventListener("click", () => selectTab("url"));
$("#tab-config").addEventListener("click", () => selectTab("config"));

// ---------- scanning ----------
async function run(path, body, button) {
  const status = $("#status");
  button.disabled = true;
  status.className = "status busy";
  status.textContent = path === "/api/scan" ? "Scanning… this takes up to 20 seconds." : "Checking…";
  try {
    const res = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error_description || "Scan failed");
    status.className = "status";
    status.textContent = "";
    history.pushState({ id: data.id }, "", "/r/" + data.id);
    render(data);
  } catch (e) {
    status.className = "status error";
    status.textContent = e.message;
  } finally {
    button.disabled = false;
  }
}

$("#form-url").addEventListener("submit", (e) => {
  e.preventDefault();
  run("/api/scan", { url: $("#url").value.trim() }, e.submitter || $("#form-url .go"));
});
$("#form-config").addEventListener("submit", (e) => {
  e.preventDefault();
  run("/api/scan-config", { config: $("#config").value }, e.submitter || $("#form-config .go"));
});

// ---------- rendering ----------
function render(scan) {
  const r = scan.report;
  const counts = SEVERITIES.map((s) => [s, r.findings.filter((f) => f.severity === s).length]).filter(([, n]) => n);
  const shareUrl = location.origin + "/r/" + scan.id;
  const copy = h("button", { class: "ghost", type: "button", onclick: async () => {
    try { await navigator.clipboard.writeText(shareUrl); copy.textContent = "Link copied"; } catch { copy.textContent = shareUrl; }
    setTimeout(() => (copy.textContent = "Copy share link"), 2500);
  } }, "Copy share link");

  const head = h("div", { class: "verdict" },
    h("div", { class: "stamp g" + (scan.grade === "?" ? "x" : scan.grade), role: "img", "aria-label": "Grade " + scan.grade }, scan.grade),
    h("div", { class: "vtext" },
      h("p", { class: "kind" }, r.kind === "remote" ? "MCP server" : "Client configuration"),
      h("h2", { class: "target" }, r.target),
      h("p", {}, GRADE_TEXT[scan.grade] || ""),
      h("p", { class: "counts" }, counts.length ? counts.map(([s, n]) => h("span", { class: "pill " + s }, n + " " + s)) : h("span", { class: "pill ok" }, "no findings")),
      h("p", { class: "meta" }, "Scanned " + new Date(r.scanned_at).toLocaleString(), " · ", copy),
    ),
  );

  const findings = r.findings.length
    ? h("ol", { class: "findings" }, r.findings.map((f) =>
        h("li", { class: "finding " + f.severity },
          h("div", { class: "fhead" },
            h("span", { class: "pill " + f.severity }, f.severity),
            h("code", { class: "rule" }, f.rule),
            f.location && f.location.server ? h("span", { class: "where" }, "server: " + f.location.server) : null),
          h("h3", {}, f.title),
          h("p", {}, f.detail),
          h("p", { class: "fix" }, h("b", {}, "Fix: "), f.fix),
          f.fixCode ? h("pre", {}, h("code", {}, f.fixCode)) : null,
          f.owasp && f.owasp.length ? h("p", { class: "owasp" }, f.owasp.map((o) => h("span", { class: "tag" }, "OWASP " + o))) : null,
        )))
    : h("p", { class: "clean" }, "Nothing to report. Keep it that way: pin tool definitions and check every release with `mandat scan-config` in CI.");

  const passed = r.passed && r.passed.length && !r.passed.includes("no-issues")
    ? h("div", { class: "passed" }, h("h3", {}, "Passed"), h("p", {}, r.passed.map((p) => h("span", { class: "tag ok" }, "✓ " + p))))
    : null;

  const el = $("#result");
  el.replaceChildren(head, findings, passed || "");
  el.hidden = false;
  el.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function loadFromPath() {
  const m = /^\/r\/([\w-]+)$/.exec(location.pathname);
  if (!m) { $("#result").hidden = true; return; }
  try {
    const res = await fetch("/api/scan/" + m[1]);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error_description);
    if (data.report.kind === "remote") $("#url").value = data.report.target;
    render(data);
  } catch (e) {
    $("#status").className = "status error";
    $("#status").textContent = e.message;
  }
}
window.addEventListener("popstate", loadFromPath);
loadFromPath();
