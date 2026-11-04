"""PII / secret redaction for tool arguments before they reach the ledger. Port of src/ledger/redact.ts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

__all__ = ["redact", "hash_value"]

SECRET_KEYS = ["password", "passwd", "secret", "token", "apikey", "api_key", "api-key", "authorization", "cookie", "private_key"]
SECRET_KEYS_EXACT = {"pin", "cvv", "cvc", "ssn"}


def _luhn(d: str) -> bool:
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _card(m: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    return f"[CARD ****{digits[-4:]}]" if _luhn(digits) else m.group(0)


# Same patterns and order as the TypeScript implementation; re.ASCII keeps \d, \w and \b ASCII-only like JavaScript.
PATTERNS: dict[str, tuple[re.Pattern[str], Any]] = {
    "jwt": (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", re.ASCII), "[JWT]"),
    "secret": (re.compile(r"\b(?:sk|pk|rk|xox[abpr]|ghp|gho|github_pat|AKIA)[-_A-Za-z0-9]{12,}\b", re.ASCII), "[SECRET]"),
    "email": (re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", re.ASCII), r"\1***@\2"),
    "iban": (re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b", re.ASCII), "[IBAN]"),
    "card": (re.compile(r"\b(?:\d[ -]?){13,19}\b", re.ASCII), _card),
    "phone": (re.compile(r"(?<![\w.])\+\d[\d\s().-]{8,16}\d\b", re.ASCII), "[PHONE]"),
}


def hash_value(v: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(v, separators=(",", ":"), ensure_ascii=False, default=str).encode()).hexdigest()[:16]


def _redact_string(s: str, patterns: Iterable[str] | None) -> str:
    for name in patterns or PATTERNS.keys():
        rx, repl = PATTERNS[name]
        s = rx.sub(repl, s)
    return s


def redact(value: Any, *, keys: Iterable[str] = (), patterns: Iterable[str] | None = None, fields: Iterable[str] = (), metadata_only: bool = False) -> Any:
    """Returns a copy of `value` with secrets removed, PII masked and `fields` (dotted arg paths) hashed."""
    key_list = [k.lower() for k in [*SECRET_KEYS, *keys]]
    field_set = set(fields)
    pats = list(patterns) if patterns is not None else None

    def walk(v: Any, path: str, depth: int) -> Any:
        if path in field_set:
            return f"[REDACTED {hash_value(v)}]"
        if depth > 12:
            return "[TRUNCATED]"
        if metadata_only and not isinstance(v, (dict, list)):
            return None if v is None else f"[{_js_type(v)} {hash_value(v)}]"
        if isinstance(v, str):
            return _redact_string(v[:4000] + "…[truncated]" if len(v) > 4000 else v, pats)
        if isinstance(v, list):
            return [walk(x, f"{path}.{i}" if path else str(i), depth + 1) for i, x in enumerate(v[:200])]
        if isinstance(v, dict):
            out: dict[str, Any] = {}
            for k, x in v.items():
                p = f"{path}.{k}" if path else str(k)
                lk = str(k).lower()
                secret = any(s in lk for s in key_list) or lk in SECRET_KEYS_EXACT
                out[k] = "[REDACTED]" if secret and p not in field_set else walk(x, p, depth + 1)
            return out
        return v

    return walk(value, "", 0)


def _js_type(v: Any) -> str:
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    return "string" if isinstance(v, str) else "object"
