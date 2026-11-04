// Mandat console — vanilla JS, no dependencies, no innerHTML with data (XSS-safe DOM building).
"use strict";

const $ = (s) => document.querySelector(s);
const state = { key: "", me: null, tab: "approvals", focus: location.hash.slice(1) || null, policyDirty: false };
let removeArmed = null;

try { state.key = sessionStorage.getItem("mandat.key") || ""; } catch { /* storage unavailable */ }

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
const pill = (t, cls) => h("span", { class: "pill " + (cls || t) }, t);
const ago = (iso) => {
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 0) return "in " + fmtDur(-s);
  return fmtDur(s) + " ago";
};
const fmtDur = (s) => (s < 60 ? s + "s" : s < 3600 ? Math.round(s / 60) + "m" : s < 86400 ? Math.round(s / 3600) + "h" : Math.round(s / 86400) + "d");
const can = (...roles) => state.me && state.me.roles.some((r) => roles.includes(r));

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => (t.hidden = true), 4000);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    // Without an API key the browser's sign-in session cookie authenticates; the header proves same-origin JS.
    headers: {
      "x-requested-with": "mandat",
      ...(state.key ? { authorization: "Bearer " + state.key } : {}),
      ...(opts.body ? { "content-type": "application/json" } : {}),
      ...(opts.headers || {}),
    },
  });
  const ct = res.headers.get("content-type") || "";
  const body = ct.includes("json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error((body && body.error_description) || res.status + " " + res.statusText);
  return body;
}

// ---------- login ----------
$("#apikey").value = state.key;
$("#login").addEventListener("submit", async (e) => {
  e.preventDefault();
  state.key = $("#apikey").value.trim();
  try { sessionStorage.setItem("mandat.key", state.key); } catch { /* ignore */ }
  await connect();
});

async function connect() {
  let sso = { enabled: false, issuer: null };
  try { sso = await (await fetch("/auth/config")).json(); } catch { /* older control plane */ }
  if (sso.enabled) {
    const a = $("#sso");
    a.hidden = false;
    a.textContent = "Sign in with " + new URL(sso.issuer).host;
  }
  try {
    // With no API key this succeeds only if a sign-in session cookie exists.
    state.me = await api("/api/whoami");
    const me = state.me;
    const how = me.via === "session" ? "signed in via " + new URL(sso.issuer).host : me.via === "api_key" ? "API key" : me.via;
    $("#who").textContent = (me.email || me.id) + " · " + me.roles.join(", ") + " · " + how;
    $("#logout").hidden = me.via !== "session";
    if (me.via === "session") { $("#sso").hidden = true; $("#apikey").hidden = true; $("#login button[type=submit]").hidden = true; }
    refresh();
  } catch (e) {
    state.me = null;
    $("#who").textContent = state.key || !sso.enabled
      ? (state.key ? "⚠ " + e.message : "Enter an API key (see .mandat/credentials.json)")
      : /no role/i.test(e.message) ? "⚠ " + e.message : "Sign in, or use an API key";
  }
}

$("#logout").addEventListener("click", async () => {
  await fetch("/auth/logout", { method: "POST", headers: { "x-requested-with": "mandat" } });
  location.reload();
});

// ---------- tabs ----------
document.querySelectorAll(".tabs button").forEach((b) =>
  b.addEventListener("click", () => {
    state.tab = b.dataset.tab;
    document.querySelectorAll(".tabs button").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    document.querySelectorAll(".panel").forEach((p) => (p.hidden = p.id !== "tab-" + state.tab));
    refresh();
  }),
);

async function refresh() {
  if (!state.me) return;
  try {
    await Promise.all([loadStats(), ({ approvals: loadApprovals, activity: loadActivity, agents: loadAgents, revocations: loadRevocations, policy: loadPolicy, audit: loadAudit })[state.tab]()]);
  } catch (e) {
    toast(e.message);
  }
}
setInterval(() => { if (state.tab !== "policy" && state.tab !== "audit") refresh(); }, 3000);

async function loadStats() {
  const s = await api("/api/stats");
  const items = [
    ["Tool calls (24h)", s.last_24h.calls],
    ["Allowed", s.last_24h.allowed],
    ["Denied", s.last_24h.denied],
    ["Pending approvals", s.pending_approvals],
    ["Agents", s.agents],
    ["Active revocations", s.active_revocations],
    ["PDP p99", (s.last_24h.p99_decision_us / 1000).toFixed(2) + " ms"],
    ["Ledger records", s.ledger.records],
  ];
  $("#stats").replaceChildren(...items.map(([l, v]) => h("div", { class: "stat" }, h("div", { class: "v" }, v), h("div", { class: "l" }, l))));
  const b = $("#badge");
  b.hidden = !s.pending_approvals;
  b.textContent = s.pending_approvals;
}

// ---------- approvals ----------
async function loadApprovals() {
  const { approvals } = await api("/api/approvals");
  const pending = approvals.filter((a) => a.status === "pending");
  const recent = approvals.filter((a) => a.status !== "pending").slice(0, 15);
  const el = $("#tab-approvals");
  el.replaceChildren(
    h("h2", {}, "Waiting for a decision"),
    pending.length ? h("div", {}, pending.map(approvalCard)) : h("p", { class: "empty" }, "Nothing waiting. Agents are within policy."),
    h("h2", {}, "Recently decided"),
    recent.length ? h("div", {}, recent.map(approvalCard)) : h("p", { class: "empty" }, "No decisions yet."),
  );
  if (state.focus) {
    const f = document.getElementById(state.focus);
    if (f) { f.scrollIntoView({ block: "center" }); state.focus = null; }
  }
}

function approvalCard(a) {
  const c = a.context;
  const chain = [c.principal.email || c.principal.sub].concat((c.actor_chain || []).slice().reverse()).join(" → ");
  const approvals = a.votes.filter((v) => v.decision === "approve").length;
  const decide = async (d) => {
    try {
      await api("/api/approvals/" + a.id + "/" + d, { method: "POST", body: JSON.stringify({}) });
      toast((d === "approve" ? "Approved " : "Denied ") + a.id);
      refresh();
    } catch (e) { toast(e.message); }
  };
  return h("article", { class: "card " + a.status + (state.focus === a.id ? " focus" : ""), id: a.id },
    h("h3", {}, c.agent.id, c.agent.version ? " v" + c.agent.version : "", " → ", h("code", {}, c.tool), " ", pill(a.status)),
    h("div", { class: "meta" },
      h("span", {}, "on behalf of ", h("b", {}, c.principal.email || c.principal.sub), c.principal.tenant ? " (" + c.principal.tenant + ")" : ""),
      h("span", {}, "risk: ", c.risk || "unclassified"),
      h("span", {}, "rule: ", h("code", {}, c.rule)),
      h("span", {}, "requested ", ago(a.created_at)),
      a.status === "pending" ? h("span", {}, "expires ", ago(a.expires_at)) : h("span", {}, "decided ", a.decided_at ? ago(a.decided_at) : "—"),
      h("span", { class: "mono" }, a.id),
    ),
    h("div", { class: "chain" }, "Delegation: ", chain),
    c.session_tainted ? h("div", { class: "warn" }, "⚠ This session processed untrusted content (possible prompt injection). Check the arguments carefully.") : null,
    h("div", { class: "meta" }, c.reasons.join(" · ")),
    h("pre", {}, JSON.stringify(c.args, null, 2)),
    a.status === "pending"
      ? h("div", { class: "actions" },
          can("approver", "admin") ? h("button", { class: "allow", onclick: () => decide("approve") }, "Approve") : null,
          can("approver", "admin") ? h("button", { class: "deny", onclick: () => decide("deny") }, "Deny") : null,
          h("span", { class: "meta" }, approvals + " of " + a.required + " approvals" + (a.required > 1 ? " (four-eyes)" : "")))
      : h("div", { class: "meta" }, a.votes.map((v) => (v.decision === "approve" ? "✓ " : "✗ ") + v.by + " via " + v.via).join(" · ") || "No votes (expired)"),
  );
}

// ---------- activity ----------
["#f-agent", "#f-tool", "#f-sub"].forEach((s) => $(s).addEventListener("change", loadActivity));
["#f-type", "#f-effect"].forEach((s) => $(s).addEventListener("change", loadActivity));

async function loadActivity() {
  const q = new URLSearchParams({ limit: "200" });
  const map = { agent: "#f-agent", tool: "#f-tool", sub: "#f-sub", type: "#f-type", effect: "#f-effect" };
  for (const [k, s] of Object.entries(map)) if ($(s).value.trim()) q.set(k, $(s).value.trim());
  const { records } = await api("/api/ledger?" + q);
  const rows = records.map((r) => {
    const d = r.decision;
    const final = d ? d.final : r.approval ? r.approval.status : "";
    return h("tr", { class: "click", onclick: () => { const p = $("#record"); p.hidden = false; p.textContent = JSON.stringify(r, null, 2); } },
      h("td", { title: r.ts }, new Date(r.ts).toLocaleTimeString()),
      h("td", {}, r.type),
      h("td", {}, r.principal ? r.principal.email || r.principal.sub : "—"),
      h("td", { class: "mono" }, (r.actor_chain || (r.agent ? [r.agent.id] : [])).join(" ← ") || "—"),
      h("td", { class: "mono" }, r.tool ? r.tool.name : "—"),
      h("td", {}, final ? pill(final) : "—", d && d.mode === "shadow" ? " " : "", d && d.mode === "shadow" ? pill("shadow", "pending") : ""),
      h("td", { class: "wrap" }, d ? d.rules.join(", ") : r.details ? JSON.stringify(r.details).slice(0, 90) : ""),
      h("td", {}, d && d.latency_us !== undefined ? (d.latency_us / 1000).toFixed(2) + " ms" : ""),
      h("td", { class: "mono", title: r.hash }, "#" + r.seq + " " + r.hash.slice(0, 10)),
    );
  });
  $("#activity").replaceChildren(
    h("thead", {}, h("tr", {}, ["Time", "Event", "On behalf of", "Agent chain", "Tool", "Decision", "Rules / details", "PDP", "Record"].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: "9", class: "empty" }, "No records match."))),
  );
}

// ---------- agents ----------
async function loadAgents() {
  const { agents } = await api("/api/agents");
  const kill = async (a) => {
    try {
      await api("/api/revocations", { method: "POST", body: JSON.stringify({ type: "agent", value: a.id, reason: "Kill switch from console" }) });
      toast("Kill switch: all tokens of " + a.id + " revoked; issuance blocked.");
      refresh();
    } catch (e) { toast(e.message); }
  };
  const rotate = async (a) => {
    try {
      const r = await api("/api/agents/" + encodeURIComponent(a.id) + "/rotate-secret", { method: "POST", body: JSON.stringify({ revoke_tokens: true }) });
      out.replaceChildren(h("p", {}, "New client secret for ", h("b", {}, r.id), " (shown once; the old one and its tokens no longer work):"), h("div", { class: "secret mono" }, r.client_secret));
      refresh();
    } catch (e) { toast(e.message); }
  };
  const remove = async (a) => {
    if (removeArmed !== a.id) { removeArmed = a.id; toast("Click Remove again to delete " + a.id + " and revoke its tokens."); return; }
    removeArmed = null;
    try { await api("/api/agents/" + encodeURIComponent(a.id), { method: "DELETE" }); toast("Removed " + a.id); refresh(); } catch (e) { toast(e.message); }
  };
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const list = (k) => String(f.get(k) || "").split(",").map((s) => s.trim()).filter(Boolean);
    try {
      const r = await api("/api/agents", { method: "POST", body: JSON.stringify({ id: f.get("id"), name: f.get("name") || undefined, allowed_tools: list("tools"), allowed_resources: list("resources"), versions: list("versions") }) });
      out.replaceChildren(h("p", {}, "Client secret for ", h("b", {}, r.id), " (shown once):"), h("div", { class: "secret mono" }, r.client_secret));
      e.target.reset();
      refresh();
    } catch (err) { toast(err.message); }
  } },
    h("label", {}, "Agent id", h("input", { name: "id", required: true, placeholder: "support-bot" })),
    h("label", {}, "Display name", h("input", { name: "name", placeholder: "Support assistant" })),
    h("label", {}, "Allowed tools (comma separated, globs ok)", h("input", { name: "tools", required: true, placeholder: "lookup_order, refund" })),
    h("label", {}, "Allowed resources (MCP server URLs)", h("input", { name: "resources", placeholder: "http://127.0.0.1:7401/mcp" })),
    h("label", {}, "Approved versions", h("input", { name: "versions", placeholder: "1.4.0, 1.4.1" })),
    h("button", { class: "primary", type: "submit", disabled: !can("admin") }, "Register agent"),
  );
  const out = h("div", {});
  $("#tab-agents").replaceChildren(
    h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Agent", "Owner", "Allowed tools", "Resources", "Versions", "Status", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, agents.length ? agents.map((a) => h("tr", {},
        h("td", {}, h("b", {}, a.id), a.name ? h("div", { class: "meta" }, a.name) : null),
        h("td", {}, a.owner || "—"),
        h("td", { class: "wrap mono" }, a.allowed_tools.join(", ")),
        h("td", { class: "wrap mono" }, (a.allowed_resources || []).join(", ") || "any"),
        h("td", { class: "mono" }, (a.versions || []).join(", ") || "any"),
        h("td", {}, a.disabled ? pill("disabled", "revoked") : a.revoked ? pill("revoked") : pill("active")),
        h("td", {}, h("div", { class: "row" },
          can("admin") && !a.revoked ? h("button", { class: "deny", onclick: () => kill(a) }, "Kill switch") : null,
          can("admin") ? h("button", { onclick: () => rotate(a) }, "Rotate secret") : null,
          can("admin") ? h("button", { onclick: () => remove(a) }, "Remove") : null)),
      )) : h("tr", {}, h("td", { colspan: "7", class: "empty" }, "No agents registered."))),
    )),
    h("div", { class: "grid2 mt" }, h("div", { class: "box" }, h("h3", {}, "Register an agent"), form, out)),
  );
}

// ---------- revocations ----------
async function loadRevocations() {
  const { revocations } = await api("/api/revocations");
  const lift = async (r) => {
    try { await api("/api/revocations/" + r.id, { method: "DELETE" }); toast("Issuance unblocked for " + r.value); refresh(); } catch (e) { toast(e.message); }
  };
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api("/api/revocations", { method: "POST", body: JSON.stringify({ type: f.get("type"), value: f.get("value"), version: f.get("version") || undefined, reason: f.get("reason") || undefined }) });
      toast("Revoked. Guards pick this up within seconds.");
      e.target.reset();
      refresh();
    } catch (err) { toast(err.message); }
  } },
    h("label", {}, "Type", h("select", { name: "type" }, ["agent", "agent_version", "subject", "task", "tenant", "jti"].map((t) => h("option", { value: t }, t)))),
    h("label", {}, "Value (agent id, user sub, task id, tenant, token jti)", h("input", { name: "value", required: true })),
    h("label", {}, "Version (for agent_version)", h("input", { name: "version" })),
    h("label", {}, "Reason", h("input", { name: "reason" })),
    h("button", { class: "deny", type: "submit", disabled: !can("admin") }, "Revoke"),
  );
  $("#tab-revocations").replaceChildren(
    h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Created", "Type", "Value", "Reason", "By", "Issuance", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, revocations.length ? revocations.slice().reverse().map((r) => h("tr", {},
        h("td", { title: r.created_at }, ago(r.created_at)),
        h("td", {}, r.type),
        h("td", { class: "mono" }, r.value + (r.version ? "@" + r.version : "")),
        h("td", { class: "wrap" }, r.reason || "—"),
        h("td", {}, r.by || "—"),
        h("td", {}, r.blocks_issuance ? pill("blocked", "revoked") : pill("allowed", "active")),
        h("td", {}, r.blocks_issuance && can("admin") ? h("button", { onclick: () => lift(r) }, "Allow new tokens") : null),
      )) : h("tr", {}, h("td", { colspan: "7", class: "empty" }, "No revocations."))),
    )),
    h("div", { class: "grid2 mt" }, h("div", { class: "box" }, h("h3", {}, "Revoke"), form)),
  );
}

// ---------- policy ----------
async function loadPolicy() {
  const p = await api("/api/policy");
  const ta = h("textarea", { rows: "28", spellcheck: "false" });
  ta.value = JSON.stringify(p.policy, null, 2);
  const status = h("span", { class: "meta" }, "version " + p.version);
  const save = async () => {
    let doc;
    try { doc = JSON.parse(ta.value); } catch (e) { toast("Invalid JSON: " + e.message); return; }
    try {
      const r = await api("/api/policy", { method: "PUT", body: JSON.stringify({ policy: doc, comment: "edited in console" }) });
      status.textContent = "saved · version " + r.version + " · guards reload within ~5 s";
      toast("Policy saved and recorded in the ledger.");
    } catch (e) { toast(e.message); }
  };
  $("#tab-policy").replaceChildren(
    h("div", { class: "row mb" }, h("button", { class: "primary", onclick: save, disabled: !can("admin") }, "Validate & save"), status),
    ta,
  );
}

// ---------- audit ----------
async function loadAudit() {
  const verifyOut = h("div", {});
  const reportOut = h("div", {});
  const verify = async () => {
    const v = await api("/api/ledger/verify");
    verifyOut.replaceChildren(v.ok
      ? h("p", { class: "ok" }, "✓ Hash chain intact — " + v.count + " records, head " + v.head.slice(0, 16) + "…")
      : h("p", { class: "bad" }, "✗ Chain broken at record " + v.broken_at + ": " + v.error));
  };
  const report = async () => {
    const md = await api("/api/report");
    reportOut.replaceChildren(h("div", { class: "md" }, md));
  };
  const download = async (fmt) => {
    const res = await fetch("/api/ledger/export?format=" + fmt, { headers: { authorization: "Bearer " + state.key } });
    if (!res.ok) { toast("Export failed: " + res.status); return; }
    const text = await res.text();
    const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: "application/x-ndjson" })), download: "mandat-" + fmt + ".ndjson" });
    document.body.append(a);
    a.click();
    a.remove();
  };
  $("#tab-audit").replaceChildren(
    h("div", { class: "grid2" },
      h("div", { class: "box" }, h("h3", {}, "Ledger integrity"), h("p", { class: "meta" }, "Recomputes every SHA-256 link of the append-only chain."), h("button", { class: "primary", onclick: verify }, "Verify chain"), verifyOut),
      h("div", { class: "box" }, h("h3", {}, "Export for SIEM"), h("p", { class: "meta" }, "NDJSON: OCSF API Activity events, OpenTelemetry GenAI spans, or raw Action Records."),
        h("div", { class: "row" }, h("button", { onclick: () => download("ocsf") }, "OCSF"), h("button", { onclick: () => download("otel") }, "OTel spans"), h("button", { onclick: () => download("raw") }, "Raw"))),
    ),
    h("div", { class: "box mt" }, h("h3", {}, "Oversight report (DPO / auditor)"), h("button", { class: "primary", onclick: report }, "Generate report"), reportOut),
  );
  verify().catch((e) => toast(e.message));
}

window.addEventListener("hashchange", () => { state.focus = location.hash.slice(1); refresh(); });
connect();
