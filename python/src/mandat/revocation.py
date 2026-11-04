"""Revocation matching, a port of src/sts/revocation.ts.

A revocation invalidates every matching token issued at or before `issued_before`.
"""

from __future__ import annotations

from typing import Any, Iterable

__all__ = ["actor_chain", "match_revocation"]


def actor_chain(claims: dict[str, Any]) -> list[dict[str, Any]]:
    """Flattens the nested RFC 8693 `act` claim: [current actor, previous actor, ...]."""
    out: list[dict[str, Any]] = []
    a = claims.get("act")
    while isinstance(a, dict) and len(out) < 16:
        out.append(a)
        a = a.get("act")
    return out


def match_revocation(claims: dict[str, Any], revocations: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    iat = claims.get("iat") if isinstance(claims.get("iat"), (int, float)) else 0
    m = claims.get("mandat") or {}
    chain = actor_chain(claims)
    for r in revocations:
        if iat > r["issued_before"]:
            continue
        t, v = r["type"], r["value"]
        hit = (
            (t == "jti" and claims.get("jti") == v)
            or (t == "subject" and claims.get("sub") == v)
            or (t == "task" and m.get("task_id") == v)
            or (t == "tenant" and m.get("tenant") == v)
            or (t == "agent" and any(a.get("sub") == v for a in chain))
            or (t == "agent_version" and any(
                a.get("sub") == v and ((a.get("mandat_agent_version") or m.get("agent_version")) if i == 0 else a.get("mandat_agent_version")) == r.get("version")
                for i, a in enumerate(chain)
            ))
        )
        if hit:
            return r
    return None
