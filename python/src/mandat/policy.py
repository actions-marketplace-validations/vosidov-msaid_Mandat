"""Policy Decision Point: a port of src/policy/engine.ts. Pure, synchronous, no I/O on the decision path.

Combining is order-independent "deny overrides": any matching deny -> deny; else any require_approval ->
require_approval; else any allow / allow_with_obligations -> allow (obligations merged); else the policy
default (deny unless configured). A condition that fails to evaluate counts as a MATCH for deny /
require_approval rules and as NO MATCH for allow rules: errors always fail closed.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .expr import CompiledExpr, compile_expr

__all__ = ["PolicyError", "Decision", "CompiledPolicy", "compile_policy", "check_capability", "parse_duration", "glob_match", "canonical_json", "HIGH_RISK"]

EFFECTS = ("allow", "deny", "require_approval", "allow_with_obligations")
RISKS = ("read", "write", "external_comm", "financial", "destructive")
HIGH_RISK = ("financial", "destructive")
DEFAULT_APPROVAL_TIMEOUT_MS = 10 * 60_000


class PolicyError(Exception):
    pass


def canonical_json(value: Any) -> str:
    """Deterministic JSON with sorted keys and JavaScript number formatting (matches canonicalJson in TS)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            return "null"
        return str(int(value)) if value.is_integer() else repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(k for k in value if value[k] is not _MISSING)
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical_json(value[k]) for k in keys) + "}"
    raise TypeError(f"Not JSON-serialisable: {type(value).__name__}")


_MISSING = object()


def parse_duration(value: str | int | float) -> float:
    """'300', '30s', '5m', '2h', '7d' -> milliseconds (bare numbers are seconds)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value * 1000
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?", str(value).strip())
    if not m:
        raise PolicyError(f"Invalid duration: {value}")
    mult = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}[m.group(2) or "s"]
    n = float(m.group(1)) * mult
    return int(n) if n.is_integer() else n


def glob_match(pattern: str, value: str) -> bool:
    if "*" not in pattern:
        return pattern == value
    return re.fullmatch(".*".join(re.escape(p) for p in pattern.split("*")), value, flags=re.S) is not None


def _get_path(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


@dataclass
class Decision:
    effect: str
    reasons: list[str]
    matched: list[str]
    obligations: list[dict[str, Any]]
    risk: str | None
    errors: list[str]
    policy_version: str
    latency_us: float
    approval: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class _Rule:
    doc: dict[str, Any]
    cond: CompiledExpr | None
    tools: list[str] | None
    agents: list[str] | None

    @property
    def id(self) -> str:
        return self.doc["id"]

    @property
    def effect(self) -> str:
        return self.doc["effect"]


@dataclass
class CompiledPolicy:
    doc: dict[str, Any]
    version: str
    _rules: list[_Rule] = field(repr=False)

    def tool_meta(self, name: str) -> dict[str, Any]:
        tools = self.doc.get("tools") or {}
        if name in tools:
            return tools[name]
        for k, v in tools.items():
            if "*" in k and glob_match(k, name):
                return v
        return {}

    def evaluate(self, inp: dict[str, Any]) -> Decision:
        t0 = time.perf_counter_ns()
        tool_name = inp["tool"]["name"]
        agent_id = inp["agent"]["id"]
        meta = self.tool_meta(tool_name)
        risk = meta.get("risk")
        ctx = _build_context(inp, meta)
        errors: list[str] = []

        def finish(effect: str, reasons: list[str], matched: list[str], obligations: list[dict[str, Any]], approval: dict[str, Any] | None = None) -> Decision:
            return Decision(effect, reasons, matched, obligations, risk, errors, self.version, (time.perf_counter_ns() - t0) / 1000, approval)

        cap = check_capability(inp)
        if cap:
            return finish("deny", [cap], ["@capability"], [])

        deny: list[_Rule] = []
        approval: list[_Rule] = []
        allow: list[_Rule] = []
        for r in self._rules:
            if r.tools is not None and not any(glob_match(p, tool_name) for p in r.tools):
                continue
            if r.agents is not None and not any(glob_match(p, agent_id) for p in r.agents):
                continue
            match = True
            if r.cond is not None:
                try:
                    v = r.cond.eval(ctx)
                    if not isinstance(v, bool):
                        raise ValueError(f"condition returned {_js_typeof(v)}, expected boolean")
                    match = v
                except Exception as e:  # noqa: BLE001 - any evaluation failure fails closed
                    errors.append(f"{r.id}: {e}")
                    match = r.effect in ("deny", "require_approval")
            if not match:
                continue
            if r.effect == "deny":
                deny.append(r)
            elif r.effect == "require_approval":
                approval.append(r)
            else:
                allow.append(r)

        base_obligations = [{"type": "redact", "fields": meta["redact"]}] if meta.get("redact") else []
        if deny:
            return finish("deny", [r.doc.get("reason") or f"Denied by rule {r.id}" for r in deny], [r.id for r in deny], base_obligations)
        if approval:
            approvers = max((r.doc.get("approval") or {}).get("approvers", 1) for r in approval)
            timeout = min(parse_duration(t) if (t := (r.doc.get("approval") or {}).get("timeout")) else DEFAULT_APPROVAL_TIMEOUT_MS for r in approval)
            channels: list[str] = []
            for r in approval:
                for ch in (r.doc.get("approval") or {}).get("channels", []):
                    if ch not in channels:
                        channels.append(ch)
            obligations = base_obligations + [o for r in allow for o in r.doc.get("obligations", [])]
            return finish(
                "require_approval",
                [r.doc.get("reason") or f"Approval required by rule {r.id}" for r in approval],
                [r.id for r in approval],
                obligations,
                {"approvers": approvers, "timeoutMs": timeout, "channels": channels, "rule": approval[0].id},
            )
        if allow:
            obligations = base_obligations + [o for r in allow for o in r.doc.get("obligations", [])]
            return finish(
                "allow_with_obligations" if obligations else "allow",
                [r.doc.get("reason") or f"Allowed by rule {r.id}" for r in allow],
                [r.id for r in allow],
                obligations,
            )
        default = self.doc.get("default", "deny")
        if default == "require_approval":
            return finish("require_approval", ["No rule matched; policy default requires approval"], ["@default"], base_obligations,
                          {"approvers": 1, "timeoutMs": DEFAULT_APPROVAL_TIMEOUT_MS, "channels": [], "rule": "@default"})
        return finish(
            "allow" if default == "allow" else "deny",
            ["No rule matched; policy default allows" if default == "allow" else "No rule matched; default deny"],
            ["@default"],
            base_obligations,
        )


def _js_typeof(v: Any) -> str:
    if v is None or isinstance(v, (dict, list)):
        return "object"
    if isinstance(v, (int, float)):
        return "number"
    return "string" if isinstance(v, str) else "undefined"


def _build_context(inp: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "principal": inp.get("principal", {}),
        "agent": inp.get("agent", {}),
        "actor_chain": inp.get("actor_chain") or [],
        "tool": {**inp["tool"], "risk": meta.get("risk"), "taints": meta.get("taints", False)},
        "args": inp.get("args") or {},
        "session": {"tainted": False, "taint_sources": [], "calls": 0, **(inp.get("session") or {})},
        "task": inp.get("task") or {},
        "env": {"hour_utc": now.hour, "weekday_utc": (now.weekday() + 1) % 7, **(inp.get("env") or {})},
    }


def check_capability(inp: dict[str, Any]) -> str | None:
    """Deny reason if the call exceeds the capability carried by the task token, else None."""
    details = (inp.get("task") or {}).get("authorization_details")
    if not details:
        return None
    relevant = [d for d in details if d.get("type") == "mandat_tool_call"]
    if not relevant:
        return "Task token carries no mandat_tool_call authorization_details"
    tool = inp["tool"]["name"]
    server = inp["tool"].get("server")
    covering = [
        d for d in relevant
        if (not d.get("tools") or any(glob_match(p, tool) for p in d["tools"]))
        and (not d.get("locations") or not server or server in d["locations"])
    ]
    if not covering:
        return f"Tool '{tool}' is outside the task's delegated capability"
    violations = []
    for d in covering:
        v = _limit_violation(d, inp.get("args") or {})
        if not v:
            return None
        violations.append(v)
    return f"Delegated capability limit exceeded: {violations[0]}"


def _limit_violation(d: dict[str, Any], args: dict[str, Any]) -> str | None:
    def is_num(x: Any) -> bool:
        return isinstance(x, (int, float)) and not isinstance(x, bool)

    for path, lim in (d.get("limits") or {}).items():
        v = _get_path(args, path)
        if "max" in lim and not (is_num(v) and v <= lim["max"]):
            return f"{path} must be <= {lim['max']}"
        if "min" in lim and not (is_num(v) and v >= lim["min"]):
            return f"{path} must be >= {lim['min']}"
        if "enum" in lim and not any(e == v and type(e) is type(v) for e in lim["enum"]):
            return f"{path} must be one of {json.dumps(lim['enum'], separators=(',', ':'))}"
        if "equals" in lim and not (v == lim["equals"] and type(v) is type(lim["equals"])):
            return f"{path} must equal {json.dumps(lim['equals'])}"
    return None


def compile_policy(doc: dict[str, Any]) -> CompiledPolicy:
    """Validates and compiles a policy. Raises PolicyError listing every problem found."""
    if not isinstance(doc, dict):
        raise PolicyError("Policy must be an object")
    problems: list[str] = []
    if doc.get("version") != 1:
        problems.append(f"Unsupported policy version {doc.get('version')} (expected 1)")
    if not isinstance(doc.get("rules"), list):
        problems.append("`rules` must be an array")
    if doc.get("default") and doc["default"] not in ("deny", "allow", "require_approval"):
        problems.append(f"Invalid default '{doc['default']}'")
    for name, meta in (doc.get("tools") or {}).items():
        if meta.get("risk") and meta["risk"] not in RISKS:
            problems.append(f"tools.{name}.risk: unknown risk '{meta['risk']}' (use {', '.join(RISKS)})")
    ids: set[str] = set()
    rules: list[_Rule] = []
    for i, r in enumerate(doc.get("rules") or []):
        where = f"rules[{i}]" + (f" ({r['id']})" if r.get("id") else "")
        if not r.get("id"):
            problems.append(f"{where}: missing id")
        elif r["id"] in ids:
            problems.append(f"{where}: duplicate id")
        ids.add(r.get("id", ""))
        if r.get("effect") not in EFFECTS:
            problems.append(f"{where}: invalid effect '{r.get('effect')}'")
        cond = None
        if "when" in r:
            try:
                cond = compile_expr(r["when"])
            except Exception as e:  # noqa: BLE001
                problems.append(f"{where}: {e}")
        if (r.get("approval") or {}).get("timeout"):
            try:
                parse_duration(r["approval"]["timeout"])
            except PolicyError as e:
                problems.append(f"{where}: {e}")
        for o in r.get("obligations", []):
            if o.get("type") not in ("redact", "annotate"):
                problems.append(f"{where}: unsupported obligation '{o.get('type')}'")
        tool = r.get("tool")
        agent = r.get("agent")
        rules.append(_Rule(r, cond, None if tool is None else (tool if isinstance(tool, list) else [tool]),
                           None if agent is None else (agent if isinstance(agent, list) else [agent])))
    if problems:
        raise PolicyError("Invalid policy:\n  - " + "\n  - ".join(problems))
    version = hashlib.sha256(canonical_json(doc).encode()).hexdigest()[:16]
    return CompiledPolicy(doc, version, rules)
