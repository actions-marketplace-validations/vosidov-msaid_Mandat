"""Mandat Guard for Python: the Policy Enforcement Point embedded in an MCP server. Port of src/guard/guard.ts.

For every tool call:
  1. verify the per-task bearer token (iss, aud = this resource, exp, typ at+jwt, signature via JWKS)
  2. reject revoked tokens / agents / versions / users
  3. reject tools whose definitions drifted from the pinned lockfile (block mode)
  4. evaluate policy in-process with args, delegation chain, capability and session taint
  5. require_approval -> create/await a human approval bound to this exact call
  6. run the handler, then write ONE Action Record with decision and outcome
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .jwt import JwksClient, JwtError, decode_jwt, verify_jwt
from .policy import HIGH_RISK, CompiledPolicy, Decision, canonical_json
from .redact import redact
from .remote import (
    ControlPlane,
    FilePolicy,
    HttpLedger,
    RemoteApprovals,
    RemotePolicy,
    RemoteRevocations,
)
from .revocation import actor_chain, match_revocation

__all__ = ["Guard", "AuthError", "GuardDenied", "VerifiedAuth", "create_guard", "tool_hash"]


def _read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

Log = Callable[[str], None]


class AuthError(Exception):
    """Token missing or refused. Map to HTTP 401 with a WWW-Authenticate challenge."""

    def __init__(self, code: str, message: str, status: int = 401, reason: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.reason = reason or code


class GuardDenied(Exception):
    """The call was not executed. `code`: denied, approval_pending, approval_denied, revoked, drift, fail_closed."""

    def __init__(self, code: str, message: str, decision: Decision | None, approval_id: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.decision = decision
        self.approval_id = approval_id


@dataclass
class VerifiedAuth:
    token: str
    claims: dict[str, Any]
    principal: dict[str, Any]
    agent: dict[str, Any]
    actor_chain: list[str]
    task_id: str | None
    session_id: str | None
    authorization_details: list[dict[str, Any]] | None


@dataclass
class _Session:
    tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)
    calls: int = 0
    touched: float = field(default_factory=time.monotonic)


class _RateGate:
    """One event per key per window; counts the rest (so floods of bad tokens don't flood the ledger)."""

    def __init__(self, window: float = 10) -> None:
        self.window = window
        self._seen: dict[str, list[float]] = {}

    def allow(self, key: str) -> int | None:
        now = time.monotonic()
        e = self._seen.get(key)
        if e and now - e[0] < self.window:
            e[1] += 1
            return None
        if len(self._seen) > 10_000:
            self._seen.clear()
        self._seen[key] = [now, 0]
        return int(e[1]) if e else 0


def tool_hash(t: dict[str, Any]) -> str:
    """sha256 over the tool definition; same format as the TypeScript lockfile (`mandat pin`)."""
    return "sha256:" + hashlib.sha256(canonical_json({
        "name": t.get("name"), "title": t.get("title"), "description": t.get("description"),
        "inputSchema": t.get("inputSchema"), "outputSchema": t.get("outputSchema"), "annotations": t.get("annotations"),
    }).encode()).hexdigest()


def approval_binding(sub: str, agent: str, tool: str, server: str | None, args: Any) -> str:
    return hashlib.sha256(canonical_json({"sub": sub, "agent": agent, "tool": tool, "server": server, "args": args or {}}).encode()).hexdigest()


class Guard:
    def __init__(
        self,
        *,
        resource: str,
        issuer: str,
        policy: Any,
        revocations: Any,
        approvals: Any,
        ledger: Any,
        jwks_uri: str | None = None,
        public_key: Any = None,
        mode: str = "enforce",
        approval_wait: float = 20.0,
        redaction: dict[str, Any] | None = None,
        pinning: dict[str, Any] | None = None,
        source: str | None = None,
        log: Log | None = None,
    ) -> None:
        self.resource = resource
        self.issuer = issuer
        self.policy = policy
        self.revocations = revocations
        self.approvals = approvals
        self.ledger = ledger
        self.mode = mode
        self.approval_wait = approval_wait
        self.redaction = redaction or {}
        self.pinning = pinning
        self.source = source
        self.log: Log = log or (lambda m: print(f"[mandat] {m}"))
        self._public_key = public_key
        self._jwks = None if public_key is not None else JwksClient(jwks_uri or f"{issuer.rstrip('/')}/.well-known/jwks.json")
        self._sessions: dict[str, _Session] = {}
        self._tool_defs: dict[str, str] = {}
        self._blocked: set[str] = set()
        self._reject_gate = _RateGate()

    # ---------- discovery ----------

    def protected_resource_metadata(self, **extra: Any) -> dict[str, Any]:
        """RFC 9728 Protected Resource Metadata for this server."""
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
            "resource_signing_alg_values_supported": ["ES256"],
            "authorization_details_types_supported": ["mandat_tool_call"],
            "resource_name": self.source or "MCP server protected by Mandat",
            **extra,
        }

    # ---------- authentication ----------

    async def verify(self, token: str | None) -> VerifiedAuth:
        try:
            return await self._verify(token)
        except AuthError as e:
            # A missing token is normal discovery; a refused one is audited.
            if token:
                self._record_rejected(token, e)
            raise

    async def _verify(self, token: str | None) -> VerifiedAuth:
        if not token:
            raise AuthError("invalid_token", "Bearer token required")
        try:
            resolver = (lambda h, p: self._public_key) if self._public_key is not None else (lambda h, p: self._jwks.get_key(h.get("kid")))  # type: ignore[union-attr]
            claims = await verify_jwt(token, resolver, issuer=self.issuer, audience=self.resource, typ="at+jwt", require_exp=True)
        except JwtError as e:
            raise AuthError("invalid_token", str(e), reason=e.code) from None
        except Exception as e:  # noqa: BLE001
            raise AuthError("invalid_token", f"Token verification failed: {e}", reason="verification_failed") from None
        chain = actor_chain(claims)
        if not chain:
            raise AuthError("invalid_token", "Token has no `act` claim: not a delegated agent token", reason="not_agent_token")
        revoked = self.revocations.check(claims)
        if revoked:
            note = f" - {revoked['reason']}" if revoked.get("reason") else ""
            raise AuthError("invalid_token", f"Token revoked ({revoked['type']}: {revoked['value']}{note})", reason="revoked")
        m = claims.get("mandat") or {}
        return VerifiedAuth(
            token=token,
            claims=claims,
            principal={"sub": str(claims.get("sub")), "tenant": m.get("tenant"), "email": claims.get("email")},
            agent={"id": chain[0]["sub"], "version": m.get("agent_version") or chain[0].get("mandat_agent_version"), "prompt_hash": m.get("prompt_hash")},
            actor_chain=[a["sub"] for a in chain],
            task_id=m.get("task_id"),
            session_id=m.get("session_id"),
            authorization_details=claims.get("authorization_details"),
        )

    def _record_rejected(self, token: str, e: AuthError) -> None:
        try:
            c = decode_jwt(token)[1]
        except JwtError:
            c = {}
        agent = (c.get("act") or {}).get("sub") if isinstance(c.get("act"), dict) else None
        suppressed = self._reject_gate.allow(f"{e.reason}|{agent}|{c.get('sub')}")
        if suppressed is None:
            return
        self._append({
            "type": "auth.rejected",
            "details": {
                "code": e.reason,
                "reason": str(e),
                "resource": self.resource,
                # From a token that failed verification: informative only, never proof of identity.
                "unverified_claims": {"iss": c.get("iss"), "sub": c.get("sub"), "agent": agent, "jti": c.get("jti"), "exp": c.get("exp")},
                "suppressed_before": suppressed,
            },
        })

    # ---------- tool pinning ----------

    def register_tools(self, defs: list[dict[str, Any]]) -> dict[str, Any] | None:
        for d in defs:
            self._tool_defs[d["name"]] = tool_hash(d)
        if not self.pinning:
            return None
        path, mode, frozen = self.pinning["lockfile"], self.pinning.get("mode", "warn"), self.pinning.get("frozen", False)
        if not os.path.exists(path):
            if frozen:
                drift = {"added": [d["name"] for d in defs], "removed": [], "changed": [], "clean": False}
            else:
                lock = {"version": 1, "server": self.resource, "pinned_at": _now_iso(),
                        "tools": {d["name"]: {"hash": tool_hash(d), "description": (d.get("description") or "")[:200]} for d in sorted(defs, key=lambda x: x["name"])}}
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(lock, f, indent=2)
                return {"added": [], "removed": [], "changed": [], "clean": True}
        else:
            lock = _read_json(path)
            now = {d["name"]: d for d in defs}
            changed = [n for n, d in now.items() if n in lock["tools"] and tool_hash(d) != lock["tools"][n]["hash"]]
            added = [n for n in now if n not in lock["tools"]]
            removed = [n for n in lock["tools"] if n not in now]
            drift = {"added": added, "removed": removed, "changed": changed, "clean": not (added or removed or changed)}
        self._blocked = set(drift["changed"] + drift["added"]) if mode == "block" else set()
        if not drift["clean"]:
            self.log(f"Tool definition drift: changed={drift['changed']} added={drift['added']} removed={drift['removed']}"
                     + (f" — blocked until re-pinned: {sorted(self._blocked)}" if self._blocked else ""))
            self._append({"type": "tool.drift", "tool": {"name": "*", "server": self.resource}, "details": {**drift, "mode": mode}})
        return drift

    # ---------- authorisation ----------

    async def execute(self, auth: VerifiedAuth, tool: str, args: dict[str, Any], handler: Callable[[], Any | Awaitable[Any]], session_id: str | None = None) -> Any:
        """Authorises and executes one tool call. Returns the handler's result or raises GuardDenied."""
        started = time.monotonic()
        policy: CompiledPolicy = self.policy.current()
        meta = policy.tool_meta(tool)
        risk = meta.get("risk")
        session_key = session_id or auth.session_id or auth.task_id or auth.claims.get("jti") or "anonymous"
        session = self._session(session_key)
        shadow = self.mode == "shadow"

        def record(decision: Decision | None, final: str, **extra: Any) -> dict[str, Any]:
            obligations = decision.obligations if decision else []
            return {
                "type": "agent.tool_call",
                "principal": auth.principal,
                "agent": auth.agent,
                "actor_chain": auth.actor_chain,
                "task_id": auth.task_id,
                "token_jti": auth.claims.get("jti"),
                "session": {"id": session_key, "tainted": session.tainted, "taint_sources": list(session.taint_sources)},
                "tool": {"name": tool, "server": self.resource, "risk": risk, "definition_hash": self._tool_defs.get(tool)},
                "args": self._redact_args(args, obligations),
                "decision": (
                    {"effect": decision.effect, "final": final, "rules": decision.matched, "reasons": decision.reasons, "obligations": decision.obligations,
                     "policy_version": decision.policy_version, "latency_us": round(decision.latency_us), "mode": self.mode}
                    if decision else {"effect": "deny", "final": final, "rules": [], "reasons": [], "mode": self.mode}
                ),
                "tags": [t for o in obligations if o.get("type") == "annotate" for t in o.get("tags", [])],
                **extra,
            }

        def deny(code: str, reason: str, decision: Decision | None, approval: dict[str, Any] | None = None) -> GuardDenied:
            self._append(record(decision, "deny", approval=approval, outcome={"status": "blocked", "error": reason, "duration_ms": _ms(started)}))
            return GuardDenied(code, reason, decision, approval["id"] if approval else None)

        revoked = self.revocations.check(auth.claims)
        if revoked:
            raise deny("revoked", f"Token revoked ({revoked['type']}: {revoked['value']})", None)
        if tool in self._blocked and not shadow:
            raise deny("drift", f"Tool '{tool}' changed since it was pinned; re-approve its definition with `mandat pin`", None)

        decision = policy.evaluate({
            "principal": {**auth.principal, **{k: auth.claims[k] for k in ("client_id", "email") if k in auth.claims}},
            "agent": auth.agent,
            "actor_chain": [{"sub": s} for s in auth.actor_chain],
            "tool": {"name": tool, "server": self.resource},
            "args": args,
            "session": {"id": session_key, "tainted": session.tainted, "taint_sources": list(session.taint_sources), "calls": session.calls},
            "task": {"id": auth.task_id, "authorization_details": auth.authorization_details},
        })

        if self.revocations.stale() and risk in HIGH_RISK and not shadow:
            raise deny("fail_closed", f"Control plane unreachable: '{risk}' tools fail closed", decision)

        approval_info: dict[str, Any] | None = None
        if not shadow and decision.effect == "deny":
            raise deny("denied", "; ".join(decision.reasons), decision)
        if not shadow and decision.effect == "require_approval":
            a = decision.approval or {}
            try:
                req = await self.approvals.request({
                    "binding": approval_binding(auth.principal["sub"], auth.agent["id"], tool, self.resource, args),
                    "required": a.get("approvers", 1),
                    "timeoutMs": a.get("timeoutMs"),
                    "channels": a.get("channels", []),
                    "context": {
                        "tool": tool, "server": self.resource, "risk": risk,
                        "args": self._redact_args(args, decision.obligations),
                        "principal": auth.principal, "agent": auth.agent, "actor_chain": auth.actor_chain,
                        "task_id": auth.task_id, "rule": a.get("rule"), "reasons": decision.reasons, "session_tainted": session.tainted,
                    },
                })
                if req["status"] == "pending":
                    req = await self.approvals.wait(req["id"], self.approval_wait)
            except GuardDenied:
                raise
            except Exception as e:  # noqa: BLE001
                raise deny("fail_closed", f"Approval service unavailable: {e}", decision) from None
            approval_info = {"id": req["id"], "status": req["status"], "required": req["required"],
                             "approvers": [v["by"] for v in req.get("votes", []) if v["decision"] == "approve"]}
            if req["status"] == "pending":
                self._append(record(decision, "pending", approval=approval_info, outcome={"status": "pending", "duration_ms": _ms(started)}))
                raise GuardDenied("approval_pending", f"Human approval required (request {req['id']}, expires {req['expires_at']}). Retry the same call once it is approved.", decision, req["id"])
            if req["status"] != "approved":
                raise deny("approval_denied", f"Approval {req['id']} was {req['status']}", decision, approval_info)
            if not await self.approvals.consume(req["id"]):
                raise deny("approval_denied", f"Approval {req['id']} was already used", decision, approval_info)

        session.calls += 1
        try:
            result = handler()
            if inspect.isawaitable(result):
                result = await result
        except Exception as e:
            self._append(record(decision, "allow", approval=approval_info, outcome={"status": "error", "error": str(e)[:500], "duration_ms": _ms(started)}))
            raise
        if meta.get("taints") and not session.tainted:
            session.tainted = True
            session.taint_sources.append(tool)
        self._append(record(decision, "allow", approval=approval_info, outcome={"status": "success", "duration_ms": _ms(started)}))
        return result

    def session_state(self, key: str) -> _Session | None:
        return self._sessions.get(key)

    def _session(self, key: str) -> _Session:
        s = self._sessions.get(key)
        if s is None:
            if len(self._sessions) > 10_000:
                cutoff = time.monotonic() - 6 * 3600
                self._sessions = {k: v for k, v in self._sessions.items() if v.touched > cutoff}
            s = self._sessions[key] = _Session()
        s.touched = time.monotonic()
        return s

    def _redact_args(self, args: dict[str, Any], obligations: list[dict[str, Any]]) -> Any:
        fields = [f for o in obligations if o.get("type") == "redact" for f in o.get("fields", [])]
        opts = dict(self.redaction)
        opts["fields"] = [*opts.get("fields", []), *fields]
        return redact(args, **opts)

    def _append(self, rec: dict[str, Any]) -> None:
        try:
            self.ledger.append({"source": self.source, **rec} if self.source else rec)
        except Exception as e:  # noqa: BLE001 - the ledger never breaks a call
            self.log(f"Ledger append failed: {e}")


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _now_iso() -> str:
    from .remote import now_iso
    return now_iso()


async def create_guard(
    *,
    resource: str,
    control_plane: str,
    api_key: str,
    policy_file: str | None = None,
    data_dir: str = ".mandat",
    mode: str = "enforce",
    approval_wait: float = 20.0,
    pinning: dict[str, Any] | None = None,
    redaction: dict[str, Any] | None = None,
    source: str | None = None,
    log: Log | None = None,
) -> Guard:
    """Creates a Guard wired to a Mandat control plane (same behaviour as createGuard in TypeScript).

    A rejected API key is a configuration error and raises; an unreachable control plane starts
    from the policy snapshot and retries in the background.
    """
    log = log or (lambda m: print(f"[mandat] {m}"))
    cp = ControlPlane(control_plane, api_key, log)
    try:
        me = await asyncio.to_thread(cp.call, "GET", "/api/whoami")
        if "service" not in me.get("roles", []):
            raise RuntimeError(f"API key '{me.get('id')}' lacks the \"service\" role required by a guard (it has: {', '.join(me.get('roles', []))}).")
    except Exception as e:  # noqa: BLE001
        status = getattr(e, "status", None)
        if status in (401, 403):
            raise RuntimeError(f"Mandat control plane at {cp.url} rejected the API key (HTTP {status}). "
                               "Use the \"service\" key from .mandat/credentials.json in the folder where `mandat serve` runs.") from None
        if isinstance(e, RuntimeError):
            raise
        log(f"Control plane {cp.url} is unreachable; starting from the last policy snapshot and retrying in the background.")

    try:
        meta = await asyncio.to_thread(cp.call, "GET", "/.well-known/oauth-authorization-server")
    except Exception:  # noqa: BLE001
        meta = {}
    revocations = RemoteRevocations(cp)
    await asyncio.to_thread(revocations.refresh)
    revocations.start()
    if policy_file:
        policy: Any = FilePolicy(policy_file, log)
    else:
        policy = RemotePolicy(cp, os.path.join(data_dir, "policy.snapshot.json"))
        await asyncio.to_thread(policy.refresh)
        policy.current()  # raises if neither the control plane nor a snapshot is available
    policy.start()
    return Guard(
        resource=resource,
        issuer=meta.get("issuer", cp.url),
        jwks_uri=meta.get("jwks_uri"),
        policy=policy,
        revocations=revocations,
        approvals=RemoteApprovals(cp),
        ledger=HttpLedger(cp),
        mode=mode,
        approval_wait=approval_wait,
        pinning=pinning,
        redaction=redaction,
        source=source,
        log=log,
    )


