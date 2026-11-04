// Mandat control plane: STS + approvals + revocation + policy distribution + ledger + console.
// The data plane (Guard) never needs it on the decision path except for approvals.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ControlPlaneConfig, Role } from "./config.ts";
import { HUMAN_ROLES, HumanAuth, type HumanUser, type Principal } from "./humans.ts";
import { hashApiKey } from "./config.ts";
import { Sts, OAuthError, hashSecret, GRANT_TOKEN_EXCHANGE, type AgentRecord } from "../sts/sts.ts";
import { loadOrCreateSigningKey, type SigningKey } from "../sts/jwt.ts";
import type { Revocation, RevocationType } from "../sts/revocation.ts";
import { JsonCollection } from "../store.ts";
import { FileLedger, queryRecords, verifyLedger, type ActionRecord, type LedgerQuery, type RecordInput } from "../ledger/ledger.ts";
import { OtlpExporter, toOcsf, toOtelSpan } from "../ledger/export.ts";
import { buildReport, reportToMarkdown } from "../ledger/report.ts";
import { ApprovalError, ApprovalService, ConsoleLogNotifier, SlackNotifier, WebhookNotifier, handleSlackInteraction, verifySlackSignature, type NewApproval, type Notifier } from "../approvals/approvals.ts";
import { compilePolicy, PolicyError, type PolicyDocument } from "../policy/engine.ts";
import { HttpError, RateGate, readBody, readJson, randomId, safeEqual, sendJson, writeJsonAtomic, parseDuration, nowSeconds } from "../util.ts";

export interface ControlPlane {
  server: Server;
  sts: Sts;
  approvals: ApprovalService;
  ledger: FileLedger;
  key: SigningKey;
  config: ControlPlaneConfig;
  listen(): Promise<string>;
  close(): Promise<void>;
}

const CONSOLE_DIR = fileURLToPath(new URL("./console/", import.meta.url));
const asset = (name: string) => readFileSync(join(CONSOLE_DIR, name), "utf8");

const REVOCATION_TYPES: RevocationType[] = ["jti", "agent", "agent_version", "subject", "task", "tenant"];

export function createControlPlane(config: ControlPlaneConfig): ControlPlane {
  const issuer = config.issuer.replace(/\/$/, "");
  const consoleUrl = `${issuer}/console`;
  const key = loadOrCreateSigningKey(join(config.dataDir, "keys"));
  const ledger = new FileLedger(join(config.dataDir, "ledger.jsonl"));
  const agents = new JsonCollection<AgentRecord>(join(config.dataDir, "agents.json"));
  const revocations = new JsonCollection<Revocation>(join(config.dataDir, "revocations.json"));
  const otlp = config.ledger?.otlp ? new OtlpExporter({ ...config.ledger.otlp, serviceName: "mandat-control-plane" }) : null;
  if (otlp) ledger.onAppend((r) => otlp.push(r));

  // Ids already in the ledger, so retried ingest batches are not duplicated (at-least-once -> exactly-once).
  const seen = new Set(ledger.read().map((r) => r.id));
  ledger.onAppend((r) => seen.add(r.id));

  if (!existsSync(config.policyFile)) throw new Error(`Policy file not found: ${config.policyFile} (run \`mandat init\`)`);
  let policyDoc = readJson<PolicyDocument>(config.policyFile);
  let policy = compilePolicy(policyDoc);

  const notifiers: Notifier[] = [];
  if (config.approvals?.log !== false) notifiers.push(new ConsoleLogNotifier());
  if (config.approvals?.slack?.webhookUrl) notifiers.push(new SlackNotifier({ webhookUrl: config.approvals.slack.webhookUrl, consoleUrl }));
  for (const w of config.approvals?.webhooks ?? []) notifiers.push(new WebhookNotifier({ ...w, consoleUrl }));
  const approvals = new ApprovalService({ path: join(config.dataDir, "approvals.json"), notifiers, ledger });

  const sts = new Sts({
    issuer,
    key,
    agents: () => agents.all(),
    revocations: () => revocations.all(),
    trustedIssuers: config.trustedIssuers ?? [],
    devIdp: config.devIdp,
    defaultTtlSeconds: config.tokenTtlSeconds,
    maxTtlSeconds: config.maxTokenTtlSeconds,
    onIssued: (t) => ledger.append({
      type: "token.issued",
      source: "control-plane",
      principal: { sub: t.sub, tenant: t.tenant },
      agent: { id: t.agent, version: t.agent_version },
      actor_chain: t.actor_chain,
      task_id: t.task_id,
      token_jti: t.jti,
      details: { aud: t.aud, exp: new Date(t.exp * 1000).toISOString(), authorization_details: t.authorization_details },
    }),
  });

  const keys = config.apiKeys;
  const loginCfg = config.consoleLogin
    ? { issuer: config.consoleLogin.issuer, clientId: config.consoleLogin.client_id }
    : (() => {
        const ti = (config.trustedIssuers ?? [])[0];
        const aud = Array.isArray(ti?.audience) ? ti.audience[0] : ti?.audience;
        return ti && aud ? { issuer: ti.issuer, clientId: aud } : null;
      })();
  const humans = new HumanAuth({ dataDir: config.dataDir, publicUrl: issuer, login: loginCfg });

  // Failed logins are audited, rate-limited per reason and source so a flood cannot flood the ledger.
  const rejectGate = new RateGate(10_000);
  const recordRejected = (type: "api.auth_rejected" | "token.denied", key: string, details: Record<string, unknown>) => {
    const suppressed = rejectGate.allow(`${type}|${key}`);
    if (suppressed !== null) ledger.append({ type, source: "control-plane", details: { ...details, suppressed_before: suppressed } });
  };
  const ipOf = (req: IncomingMessage) => req.socket.remoteAddress ?? "unknown";

  const withRejectAudit = (req: IncomingMessage, fn: () => Principal): Principal => {
    try {
      return fn();
    } catch (e) {
      if (e instanceof HttpError && e.code === "no_role")
        recordRejected("api.auth_rejected", `no_role|${e.message}`, { code: "no_role", reason: e.message, path: req.url, ip: ipOf(req) });
      throw e;
    }
  };

  /** Resolves the caller: console session cookie, IdP ID token (CLI `--login`), or API key. */
  const identify = async (req: IncomingMessage): Promise<Principal> => {
    const session = humans.session(req.headers.cookie);
    if (session) {
      // Cookies are sent automatically; require a header that cross-site forms cannot set.
      if (req.method !== "GET" && req.method !== "HEAD" && req.headers["x-requested-with"] !== "mandat")
        throw new HttpError(403, "csrf", "Missing X-Requested-With: mandat header");
      return withRejectAudit(req, () => humans.principal(session.sub, session.email, session.email_verified, "session"));
    }
    const h = req.headers.authorization;
    const token = h?.startsWith("Bearer ") ? h.slice(7).trim() : undefined;
    if (!token) throw new HttpError(401, "unauthorized", "Sign in or provide an API key", { "www-authenticate": 'Bearer realm="mandat"' });
    if (token.split(".").length === 3) {
      let u;
      try {
        u = await sts.verifyIdpToken(token);
      } catch (e) {
        recordRejected("api.auth_rejected", `invalid_id_token|${ipOf(req)}`, { code: "invalid_id_token", reason: (e as Error).message, path: req.url, ip: ipOf(req) });
        throw new HttpError(401, "unauthorized", `ID token rejected: ${(e as Error).message}`);
      }
      return withRejectAudit(req, () => humans.principal(u.sub, u.email, u.email_verified, "id_token"));
    }
    const hash = hashApiKey(token);
    const k = keys.find((x) => safeEqual(x.hash, hash));
    if (!k) {
      recordRejected("api.auth_rejected", `invalid_api_key|${ipOf(req)}`, { code: "invalid_api_key", reason: "Unknown API key", path: req.url, ip: ipOf(req) });
      throw new HttpError(401, "unauthorized", "Invalid API key");
    }
    return { id: k.id, roles: k.roles, via: "api_key" };
  };

  const authenticate = async (req: IncomingMessage, roles: Role[]): Promise<Principal> => {
    const p = await identify(req);
    if (!p.roles.some((r) => roles.includes(r))) throw new HttpError(403, "forbidden", `Requires role: ${roles.join(" or ")}`);
    return p;
  };

  const adminEvent = (type: RecordInput["type"], by: string, details: Record<string, unknown>) =>
    ledger.append({ type, source: "control-plane", principal: { sub: by }, details });

  const asMetadata = () => ({
    issuer,
    token_endpoint: `${issuer}/oauth/token`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    grant_types_supported: [GRANT_TOKEN_EXCHANGE],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    response_types_supported: [],
    code_challenge_methods_supported: ["S256"],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: false,
    authorization_details_types_supported: ["mandat_tool_call"],
    token_endpoint_auth_signing_alg_values_supported: [key.alg],
    service_documentation: `${issuer}/console`,
    mandat_api: `${issuer}/api`,
  });

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", issuer);
    const p = url.pathname;
    const m = req.method ?? "GET";
    const json = async <T>() => {
      const text = await readBody(req);
      try { return (text ? JSON.parse(text) : {}) as T; } catch { throw new HttpError(400, "invalid_json", "Body must be JSON"); }
    };

    // ----- public -----
    if (m === "GET" && p === "/favicon.ico") { res.writeHead(204).end(); return; }
    if (m === "GET" && p === "/healthz") return sendJson(res, 200, { ok: true, ledger: { records: ledger.length, head: ledger.headHash } });
    if (m === "GET" && (p === "/.well-known/oauth-authorization-server" || p === "/.well-known/openid-configuration")) return sendJson(res, 200, asMetadata(), { "cache-control": "public, max-age=300" });
    if (m === "GET" && p === "/.well-known/jwks.json") return sendJson(res, 200, { keys: [key.publicJwk] }, { "cache-control": "public, max-age=300" });
    if (m === "GET" && (p === "/" || p === "/console")) {
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
      });
      res.end(asset("index.html"));
      return;
    }
    if (m === "GET" && p === "/console.js") { res.writeHead(200, { "content-type": "text/javascript; charset=utf-8" }); res.end(asset("app.js")); return; }
    if (m === "GET" && p === "/console.css") { res.writeHead(200, { "content-type": "text/css; charset=utf-8" }); res.end(asset("app.css")); return; }

    if (m === "POST" && p === "/oauth/token") {
      const form = new URLSearchParams(await readBody(req));
      let id = form.get("client_id") ?? undefined;
      let secret = form.get("client_secret") ?? undefined;
      const basic = req.headers.authorization?.match(/^Basic\s+(.+)$/i)?.[1];
      if (basic) {
        const [u, s] = Buffer.from(basic, "base64").toString("utf8").split(":");
        id = decodeURIComponent(u ?? "");
        secret = decodeURIComponent(s ?? "");
      }
      try {
        return sendJson(res, 200, await sts.exchange(form, { id, secret }), { pragma: "no-cache" });
      } catch (e) {
        if (e instanceof OAuthError) {
          recordRejected("token.denied", `${e.error}|${id ?? "-"}`, { code: e.error, reason: e.message, client_id: id ?? null, ip: ipOf(req) });
          return sendJson(res, e.status, { error: e.error, error_description: e.message }, e.status === 401 ? { "www-authenticate": 'Basic realm="mandat"' } : {});
        }
        throw e;
      }
    }

    if (m === "POST" && p === "/dev/login") {
      if (!config.devIdp) throw new HttpError(404, "not_found", "Dev IdP disabled");
      const b = await json<{ sub?: string; email?: string; name?: string; tenant?: string }>();
      if (!b.sub) throw new HttpError(400, "invalid_request", "sub is required");
      return sendJson(res, 200, { id_token: sts.devLogin({ sub: b.sub, email: b.email, name: b.name, tenant: b.tenant }), token_type: "urn:ietf:params:oauth:token-type:id_token" });
    }

    if (m === "POST" && p === "/slack/interactions") {
      const raw = await readBody(req);
      const secret = config.approvals?.slack?.signingSecret;
      if (!secret || !verifySlackSignature(raw, req.headers["x-slack-request-timestamp"] as string, req.headers["x-slack-signature"] as string, secret))
        throw new HttpError(401, "bad_signature", "Invalid Slack signature");
      return sendJson(res, 200, handleSlackInteraction(approvals, raw, consoleUrl));
    }

    // ----- human sign-in (console) -----
    if (m === "GET" && p === "/auth/config") return sendJson(res, 200, { enabled: humans.loginEnabled, issuer: humans.loginIssuer });
    if (m === "GET" && p === "/auth/login") {
      res.writeHead(302, { location: await humans.startLogin(), "cache-control": "no-store" }).end();
      return;
    }
    if (m === "GET" && p === "/auth/callback") {
      const page = (title: string, msg: string, extraHead = "") =>
        `<!doctype html><meta charset="utf-8">${extraHead}<title>${title}</title><body style="font:16px system-ui;margin:3rem"><h2>${title}</h2><p>${msg}</p><p><a href="/console">Back to the console</a></p></body>`;
      try {
        const { sessionId } = await humans.finishLogin(url.searchParams);
        // An HTML hop (not a 302) makes the console load a same-site navigation, so the Strict cookie applies.
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "set-cookie": humans.sessionCookie(sessionId), "cache-control": "no-store" });
        res.end(page("Signed in", "Opening the console...", '<meta http-equiv="refresh" content="0;url=/console">'));
      } catch (e) {
        const msg = (e as Error).message.replace(/[<>&"]/g, "");
        res.writeHead(400, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        res.end(page("Sign-in failed", msg));
      }
      return;
    }
    if (m === "POST" && p === "/auth/logout") {
      humans.logout(req.headers.cookie);
      res.writeHead(204, { "set-cookie": humans.sessionCookie(null) }).end();
      return;
    }

    if (!p.startsWith("/api/")) throw new HttpError(404, "not_found", "Not found");

    // ----- API -----
    if (m === "GET" && p === "/api/whoami") {
      const k = await authenticate(req, ["admin", "approver", "auditor", "service"]);
      return sendJson(res, 200, { id: k.id, roles: k.roles, via: k.via, email: k.email ?? null, sub: k.sub ?? null, issuer });
    }

    if (p === "/api/revocations") {
      if (m === "GET") {
        await authenticate(req, ["service", "admin", "auditor"]);
        return sendJson(res, 200, { revocations: revocations.all(), now: nowSeconds() });
      }
      if (m === "POST") {
        const k = await authenticate(req, ["admin"]);
        const b = await json<{ type?: RevocationType; value?: string; version?: string; reason?: string; block_issuance?: boolean }>();
        if (!b.type || !REVOCATION_TYPES.includes(b.type)) throw new HttpError(400, "invalid_request", `type must be one of ${REVOCATION_TYPES.join(", ")}`);
        if (!b.value) throw new HttpError(400, "invalid_request", "value is required");
        if (b.type === "agent_version" && !b.version) throw new HttpError(400, "invalid_request", "version is required for agent_version");
        const r: Revocation = {
          id: randomId("rev_", 8), type: b.type, value: b.value, version: b.version,
          issued_before: nowSeconds(), blocks_issuance: b.block_issuance ?? b.type !== "jti",
          created_at: new Date().toISOString(), reason: b.reason, by: k.id,
        };
        revocations.put(r);
        adminEvent("revocation.created", k.id, { ...r });
        return sendJson(res, 201, r);
      }
    }
    const revMatch = /^\/api\/revocations\/([\w-]+)$/.exec(p);
    if (revMatch && m === "DELETE") {
      const k = await authenticate(req, ["admin"]);
      const r = revocations.update(revMatch[1]!, (x) => ({ ...x, blocks_issuance: false }));
      if (!r) throw new HttpError(404, "not_found", "Revocation not found");
      adminEvent("revocation.lifted", k.id, { id: r.id, type: r.type, value: r.value, note: "New tokens may be issued; tokens issued before the revocation stay invalid." });
      return sendJson(res, 200, r);
    }

    if (p === "/api/policy") {
      if (m === "GET") {
        await authenticate(req, ["service", "admin", "auditor"]);
        const etag = `"${policy.version}"`;
        if (req.headers["if-none-match"] === etag) { res.writeHead(304, { etag }).end(); return; }
        return sendJson(res, 200, { version: policy.version, policy: policyDoc }, { etag });
      }
      if (m === "PUT") {
        const k = await authenticate(req, ["admin"]);
        const b = await json<{ policy?: PolicyDocument; comment?: string }>();
        let next;
        try { next = compilePolicy(b.policy as PolicyDocument); } catch (e) {
          if (e instanceof PolicyError) throw new HttpError(422, "invalid_policy", e.message);
          throw e;
        }
        const before = policy.version;
        const beforeRules = new Set(policyDoc.rules.map((r) => r.id));
        const afterRules = new Set(b.policy!.rules.map((r) => r.id));
        writeJsonAtomic(config.policyFile, b.policy);
        policyDoc = b.policy!;
        policy = next;
        adminEvent("policy.changed", k.id, {
          from_version: before, to_version: next.version, comment: b.comment,
          rules_added: [...afterRules].filter((x) => !beforeRules.has(x)),
          rules_removed: [...beforeRules].filter((x) => !afterRules.has(x)),
        });
        return sendJson(res, 200, { version: next.version });
      }
    }

    if (p === "/api/agents") {
      if (m === "GET") {
        await authenticate(req, ["admin", "auditor", "approver"]);
        const revs = revocations.all();
        return sendJson(res, 200, {
          agents: agents.all().map(({ secret_hash: _s, ...a }) => ({
            ...a,
            revoked: revs.some((r) => r.blocks_issuance && (r.type === "agent" || r.type === "agent_version") && r.value === a.id),
          })),
        });
      }
      if (m === "POST") {
        const k = await authenticate(req, ["admin"]);
        const b = await json<Partial<AgentRecord>>();
        if (!b.id || !/^[a-z0-9][a-z0-9._-]{1,62}$/.test(b.id)) throw new HttpError(400, "invalid_request", "id must match ^[a-z0-9][a-z0-9._-]{1,62}$");
        if (agents.get(b.id)) throw new HttpError(409, "conflict", "Agent already exists");
        if (!Array.isArray(b.allowed_tools) || !b.allowed_tools.length) throw new HttpError(400, "invalid_request", "allowed_tools is required (least privilege)");
        const secret = `mdt_as_${randomId("", 24)}`;
        const rec: AgentRecord = {
          id: b.id, name: b.name, owner: b.owner ?? k.id, secret_hash: hashSecret(secret),
          allowed_tools: b.allowed_tools, allowed_resources: b.allowed_resources ?? [], versions: b.versions ?? [],
          max_ttl_seconds: b.max_ttl_seconds, created_at: new Date().toISOString(),
        };
        agents.put(rec);
        adminEvent("agent.registered", k.id, { agent: rec.id, allowed_tools: rec.allowed_tools, allowed_resources: rec.allowed_resources, versions: rec.versions });
        const { secret_hash: _s, ...pub } = rec;
        return sendJson(res, 201, { ...pub, client_secret: secret, note: "Store the client_secret now; it is not shown again." });
      }
    }
    const agentMatch = /^\/api\/agents\/([\w.-]+)$/.exec(p);
    if (agentMatch && m === "PATCH") {
      const k = await authenticate(req, ["admin"]);
      const b = await json<Partial<AgentRecord>>();
      const allowed: Array<keyof AgentRecord> = ["name", "allowed_tools", "allowed_resources", "versions", "max_ttl_seconds", "disabled"];
      const patch = Object.fromEntries(Object.entries(b).filter(([kk]) => allowed.includes(kk as keyof AgentRecord)));
      const r = agents.update(agentMatch[1]!, (a) => ({ ...a, ...patch }));
      if (!r) throw new HttpError(404, "not_found", "Agent not found");
      adminEvent("agent.updated", k.id, { agent: r.id, changes: patch });
      const { secret_hash: _s, ...pub } = r;
      return sendJson(res, 200, pub);
    }

    const rotateMatch = /^\/api\/agents\/([\w.-]+)\/rotate-secret$/.exec(p);
    if (rotateMatch && m === "POST") {
      const k = await authenticate(req, ["admin"]);
      const b = await json<{ revoke_tokens?: boolean }>();
      const secret = `mdt_as_${randomId("", 24)}`;
      const r = agents.update(rotateMatch[1]!, (a) => ({ ...a, secret_hash: hashSecret(secret) }));
      if (!r) throw new HttpError(404, "not_found", "Agent not found");
      if (b.revoke_tokens) {
        // Invalidate tokens minted with the old secret, but let the new secret mint new ones.
        revocations.put({ id: randomId("rev_", 8), type: "agent", value: r.id, issued_before: nowSeconds(), blocks_issuance: false, created_at: new Date().toISOString(), reason: "secret rotated", by: k.id });
      }
      adminEvent("agent.secret_rotated", k.id, { agent: r.id, revoked_existing_tokens: Boolean(b.revoke_tokens) });
      return sendJson(res, 200, { id: r.id, client_secret: secret, note: "Store the client_secret now; it is not shown again. The old secret no longer works." });
    }
    if (agentMatch && m === "DELETE") {
      const k = await authenticate(req, ["admin"]);
      const id = agentMatch[1]!;
      if (!agents.delete(id)) throw new HttpError(404, "not_found", "Agent not found");
      // Outstanding tokens die with the agent; a new agent with the same id needs the block lifted explicitly.
      revocations.put({ id: randomId("rev_", 8), type: "agent", value: id, issued_before: nowSeconds(), blocks_issuance: true, created_at: new Date().toISOString(), reason: "agent removed", by: k.id });
      adminEvent("agent.removed", k.id, { agent: id });
      return sendJson(res, 200, { removed: id });
    }

    if (p === "/api/users") {
      if (m === "GET") {
        await authenticate(req, ["admin", "auditor"]);
        return sendJson(res, 200, { users: humans.users.all(), login: { enabled: humans.loginEnabled, issuer: humans.loginIssuer } });
      }
      if (m === "POST") {
        const k = await authenticate(req, ["admin"]);
        const b = await json<{ email?: string; sub?: string; roles?: Role[] }>();
        if (!b.email && !b.sub) throw new HttpError(400, "invalid_request", "email or sub is required");
        const roles = b.roles ?? [];
        if (!roles.length || roles.some((r) => !HUMAN_ROLES.includes(r)))
          throw new HttpError(400, "invalid_request", `roles must be a non-empty subset of ${HUMAN_ROLES.join(", ")} (the service role is for machines: use an API key)`);
        const email = b.email?.trim().toLowerCase();
        const id = email ?? b.sub!;
        const user: HumanUser = { id, email, sub: b.sub, roles: [...new Set(roles)], created_at: humans.users.get(id)?.created_at ?? new Date().toISOString(), by: k.id };
        humans.users.put(user);
        adminEvent("user.granted", k.id, { user: id, roles: user.roles });
        return sendJson(res, 200, user);
      }
    }
    const userMatch = /^\/api\/users\/([^/]+)$/.exec(p);
    if (userMatch && m === "DELETE") {
      const k = await authenticate(req, ["admin"]);
      const raw = decodeURIComponent(userMatch[1]!);
      const target = humans.users.get(raw.toLowerCase()) ?? humans.users.all().find((u) => u.sub === raw);
      if (!target) throw new HttpError(404, "not_found", "User not found");
      if (target.id === k.id) throw new HttpError(409, "conflict", "You cannot remove your own access");
      humans.users.delete(target.id);
      adminEvent("user.revoked", k.id, { user: target.id, roles: target.roles });
      return sendJson(res, 200, { removed: target.id });
    }

    if (p === "/api/approvals") {
      if (m === "POST") {
        await authenticate(req, ["service"]);
        const b = await json<NewApproval>();
        if (!b.binding || !b.context?.tool || !b.context?.principal?.sub) throw new HttpError(400, "invalid_request", "binding and context are required");
        const timeoutMs = Math.min(b.timeoutMs ?? parseDuration(config.approvals?.defaultTimeout ?? "10m"), 24 * 3_600_000);
        return sendJson(res, 201, await approvals.create({ ...b, timeoutMs, required: b.required ?? 1, channels: b.channels ?? [] }));
      }
      if (m === "GET") {
        await authenticate(req, ["approver", "admin", "auditor", "service"]);
        const status = url.searchParams.get("status") as never;
        return sendJson(res, 200, { approvals: approvals.list(status || undefined).slice(0, 200) });
      }
    }
    const apr = /^\/api\/approvals\/([\w-]+)(?:\/(approve|deny|consume))?$/.exec(p);
    if (apr) {
      const [, id, action] = apr;
      if (!action && m === "GET") {
        await authenticate(req, ["approver", "admin", "auditor", "service"]);
        const wait = Math.min(Number(url.searchParams.get("wait") ?? 0) || 0, 30_000);
        const r = wait ? await approvals.wait(id!, wait) : approvals.get(id!);
        if (!r) throw new HttpError(404, "not_found", "Approval not found");
        return sendJson(res, 200, r);
      }
      if ((action === "approve" || action === "deny") && m === "POST") {
        const k = await authenticate(req, ["approver", "admin"]);
        const b = await json<{ comment?: string }>();
        const via = k.via === "session" ? "console" : k.via === "id_token" ? "cli" : "api-key";
        const identities = [...new Set([k.id, k.sub, k.email].filter((x): x is string => Boolean(x)))];
        return sendJson(res, 200, approvals.decide(id!, { by: k.id, decision: action, via, comment: b.comment, identities }));
      }
      if (action === "consume" && m === "POST") {
        await authenticate(req, ["service"]);
        return sendJson(res, 200, { consumed: approvals.consume(id!) });
      }
    }

    if (m === "POST" && p === "/api/ledger/ingest") {
      const k = await authenticate(req, ["service"]);
      const b = await json<{ records?: RecordInput[] }>();
      if (!Array.isArray(b.records) || b.records.length > 1000) throw new HttpError(400, "invalid_request", "records: array of <= 1000");
      let appended = 0;
      for (const r of b.records) {
        if (r.id && seen.has(r.id)) continue;
        if (!r.type) continue;
        ledger.append({ ...r, source: r.source ?? k.id });
        appended++;
      }
      return sendJson(res, 200, { appended, head: ledger.headHash });
    }
    if (m === "GET" && p === "/api/ledger") {
      await authenticate(req, ["auditor", "admin", "approver"]);
      const q: LedgerQuery = Object.fromEntries(url.searchParams) as LedgerQuery;
      q.limit = Math.min(Number(url.searchParams.get("limit") ?? 100) || 100, 1000);
      return sendJson(res, 200, { records: queryRecords(ledger.read(), q), head: ledger.headHash, count: ledger.length });
    }
    if (m === "GET" && p === "/api/ledger/verify") {
      await authenticate(req, ["auditor", "admin"]);
      return sendJson(res, 200, verifyLedger(ledger.path));
    }
    if (m === "GET" && p === "/api/ledger/export") {
      await authenticate(req, ["auditor", "admin"]);
      const fmt = url.searchParams.get("format") ?? "ocsf";
      const recs = queryRecords(ledger.read(), { ...Object.fromEntries(url.searchParams), order: "asc" } as LedgerQuery);
      const map = fmt === "otel" ? toOtelSpan : fmt === "raw" ? (r: ActionRecord) => r : toOcsf;
      res.writeHead(200, { "content-type": "application/x-ndjson", "content-disposition": `attachment; filename="mandat-${fmt}.ndjson"` });
      res.end(recs.map((r) => JSON.stringify(map(r))).join("\n") + "\n");
      return;
    }
    if (m === "GET" && p === "/api/report") {
      await authenticate(req, ["auditor", "admin"]);
      const data = buildReport(ledger.read(), { from: url.searchParams.get("from") ?? undefined, to: url.searchParams.get("to") ?? undefined, retentionDays: config.ledger?.retentionDays });
      if (url.searchParams.get("format") === "json") return sendJson(res, 200, data);
      res.writeHead(200, { "content-type": "text/markdown; charset=utf-8" });
      res.end(reportToMarkdown(data));
      return;
    }
    if (m === "GET" && p === "/api/stats") {
      await authenticate(req, ["auditor", "admin", "approver"]);
      const recs = ledger.read();
      const since = new Date(Date.now() - 24 * 3_600_000).toISOString();
      const calls = recs.filter((r) => r.type === "agent.tool_call" && r.ts >= since);
      return sendJson(res, 200, {
        last_24h: {
          calls: calls.length,
          allowed: calls.filter((c) => c.decision?.final === "allow").length,
          denied: calls.filter((c) => c.decision?.final === "deny").length,
          pending: calls.filter((c) => c.decision?.final === "pending").length,
          p99_decision_us: percentile(calls.map((c) => c.decision?.latency_us ?? 0), 0.99),
        },
        pending_approvals: approvals.list("pending").length,
        agents: agents.all().length,
        active_revocations: revocations.filter((r) => r.blocks_issuance).length,
        policy_version: policy.version,
        ledger: { records: ledger.length, head: ledger.headHash },
      });
    }
    throw new HttpError(404, "not_found", "Not found");
  }

  const server = createServer(async (req, res) => {
    try {
      await route(req, res);
    } catch (e) {
      if (e instanceof HttpError) return sendJson(res, e.status, { error: e.code, error_description: e.message }, e.headers);
      if (e instanceof ApprovalError) return sendJson(res, e.status, { error: "approval_error", error_description: e.message });
      console.error("[mandat] internal error:", e);
      return sendJson(res, 500, { error: "server_error", error_description: "Internal error" });
    }
  });

  return {
    server, sts, approvals, ledger, key, config,
    listen: () => new Promise((resolve, reject) => server.once("error", (e: NodeJS.ErrnoException) => reject(
      e.code === "EADDRINUSE" ? new Error(`Port ${config.port} is already in use (another \`mandat serve\`?). Use --port or change "port" in the config.`) : e,
    )).listen(config.port, config.host ?? "127.0.0.1", () => {
      const addr = server.address();
      resolve(typeof addr === "object" && addr ? `http://${config.host ?? "127.0.0.1"}:${addr.port}` : issuer);
    })),
    close: async () => {
      approvals.close();
      await otlp?.close();
      await new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections(); });
    },
  };
}

function percentile(xs: number[], p: number): number {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(p * s.length))]!;
}
