"""Mandat policy expression language (CEL-flavoured), a port of src/policy/expr.ts.

    args.amount <= 50 && args.currency == 'EUR'
    session.tainted && !args.to.endsWith('@acme.com')
    args.recipients.all(r, r.endsWith('@acme.com'))

Parsed once into an AST; evaluation is a tree walk with no access to the Python runtime.
Semantics follow the TypeScript reference exactly (spec/conformance/policy.json): missing fields
are null, ordering comparisons with null are false, booleans are never numbers, `%` keeps the
sign of the dividend.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

__all__ = ["ExprError", "CompiledExpr", "compile_expr"]


class ExprError(Exception):
    pass


MAX_EXPR_LENGTH = 4096
MAX_REGEX_LENGTH = 256
OPS = ["&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "+", "-", "*", "/", "%", "(", ")", "[", "]", ".", ",", "?", ":"]
FUNCTIONS = {"size", "has", "int", "double", "string", "lower", "upper", "abs", "min", "max"}
METHODS = {"startsWith", "endsWith", "contains", "matches", "size", "lower", "upper", "trim", "keys"}
MACROS = {"all", "exists", "filter"}

_NUM = re.compile(r"\d+(\.\d+)?")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class Tok:
    t: str  # num | str | id | op | eof
    v: str
    pos: int


@dataclass
class Node:
    k: str
    v: Any = None
    name: str = ""
    op: str = ""
    fn: str = ""
    var: str = ""
    items: list["Node"] = field(default_factory=list)
    args: list["Node"] = field(default_factory=list)
    a: "Node | None" = None  # obj / left / condition / operand
    b: "Node | None" = None  # index / right / then / body
    c: "Node | None" = None  # else


def _tokenize(src: str) -> list[Tok]:
    if len(src) > MAX_EXPR_LENGTH:
        raise ExprError("Expression too long")
    toks: list[Tok] = []
    i = 0
    while i < len(src):
        ch = src[i]
        if ch.isspace():
            i += 1
            continue
        if ch.isdigit() and ch.isascii():
            m = _NUM.match(src, i)
            assert m
            toks.append(Tok("num", m.group(0), i))
            i = m.end()
            continue
        if ch in ("'", '"'):
            j = i + 1
            out = []
            while j < len(src) and src[j] != ch:
                if src[j] == "\\" and j + 1 < len(src):
                    n = src[j + 1]
                    out.append("\n" if n == "n" else "\t" if n == "t" else n)
                    j += 2
                else:
                    out.append(src[j])
                    j += 1
            if j >= len(src):
                raise ExprError(f"Unterminated string at {i}")
            toks.append(Tok("str", "".join(out), i))
            i = j + 1
            continue
        m = _IDENT.match(src, i)
        if m:
            toks.append(Tok("id", m.group(0), i))
            i = m.end()
            continue
        op = next((o for o in OPS if src.startswith(o, i)), None)
        if op is None:
            raise ExprError(f"Unexpected character '{ch}' at {i}")
        toks.append(Tok("op", op, i))
        i += len(op)
    toks.append(Tok("eof", "", len(src)))
    return toks


class _Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.toks = toks
        self.i = 0

    def peek(self) -> Tok:
        return self.toks[self.i]

    def next(self) -> Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def is_op(self, v: str) -> bool:
        t = self.peek()
        return t.t == "op" and t.v == v

    def expect(self, v: str) -> None:
        t = self.next()
        if t.t != "op" or t.v != v:
            raise ExprError(f"Expected '{v}' at {t.pos}, got '{t.v or 'end'}'")

    def parse(self) -> Node:
        n = self.ternary()
        if self.peek().t != "eof":
            raise ExprError(f"Unexpected '{self.peek().v}' at {self.peek().pos}")
        return n

    def ternary(self) -> Node:
        c = self.or_()
        if self.is_op("?"):
            self.next()
            t = self.ternary()
            self.expect(":")
            f = self.ternary()
            return Node("cond", a=c, b=t, c=f)
        return c

    def or_(self) -> Node:
        left = self.and_()
        while self.is_op("||"):
            self.next()
            left = Node("bin", op="||", a=left, b=self.and_())
        return left

    def and_(self) -> Node:
        left = self.cmp()
        while self.is_op("&&"):
            self.next()
            left = Node("bin", op="&&", a=left, b=self.cmp())
        return left

    def cmp(self) -> Node:
        left = self.add()
        t = self.peek()
        if (t.t == "op" and t.v in ("==", "!=", "<", "<=", ">", ">=")) or (t.t == "id" and t.v == "in"):
            self.next()
            return Node("bin", op=t.v, a=left, b=self.add())
        return left

    def add(self) -> Node:
        left = self.mul()
        while self.is_op("+") or self.is_op("-"):
            op = self.next().v
            left = Node("bin", op=op, a=left, b=self.mul())
        return left

    def mul(self) -> Node:
        left = self.unary()
        while self.is_op("*") or self.is_op("/") or self.is_op("%"):
            op = self.next().v
            left = Node("bin", op=op, a=left, b=self.unary())
        return left

    def unary(self) -> Node:
        if self.is_op("!"):
            self.next()
            return Node("un", op="!", a=self.unary())
        if self.is_op("-"):
            self.next()
            return Node("un", op="-", a=self.unary())
        return self.postfix()

    def postfix(self) -> Node:
        n = self.primary()
        while True:
            if self.is_op("."):
                self.next()
                name = self.next()
                if name.t != "id":
                    raise ExprError(f"Expected property name at {name.pos}")
                if self.is_op("("):
                    self.next()
                    if name.v in MACROS:
                        v = self.next()
                        if v.t != "id":
                            raise ExprError(f"{name.v}() expects a variable name at {v.pos}")
                        self.expect(",")
                        body = self.ternary()
                        self.expect(")")
                        n = Node("macro", a=n, fn=name.v, var=v.v, b=body)
                    else:
                        n = Node("method", a=n, fn=name.v, args=self.call_args())
                else:
                    n = Node("member", a=n, name=name.v)
            elif self.is_op("["):
                self.next()
                idx = self.ternary()
                self.expect("]")
                n = Node("index", a=n, b=idx)
            else:
                return n

    def call_args(self) -> list[Node]:
        out: list[Node] = []
        if self.is_op(")"):
            self.next()
            return out
        while True:
            out.append(self.ternary())
            if self.is_op(","):
                self.next()
                continue
            self.expect(")")
            return out

    def primary(self) -> Node:
        t = self.next()
        if t.t == "num":
            return Node("lit", v=float(t.v) if "." in t.v else int(t.v))
        if t.t == "str":
            return Node("lit", v=t.v)
        if t.t == "id":
            if t.v == "true":
                return Node("lit", v=True)
            if t.v == "false":
                return Node("lit", v=False)
            if t.v == "null":
                return Node("lit", v=None)
            if self.is_op("("):
                self.next()
                return Node("call", fn=t.v, args=self.call_args())
            return Node("id", name=t.v)
        if t.t == "op" and t.v == "(":
            n = self.ternary()
            self.expect(")")
            return n
        if t.t == "op" and t.v == "[":
            items: list[Node] = []
            if not self.is_op("]"):
                while True:
                    items.append(self.ternary())
                    if self.is_op(","):
                        self.next()
                        continue
                    break
            self.expect("]")
            return Node("list", items=items)
        raise ExprError(f"Unexpected '{t.v or 'end of expression'}' at {t.pos}")


def _validate(n: Node) -> None:
    if n.k == "call":
        if n.fn not in FUNCTIONS:
            raise ExprError(f"Unknown function {n.fn}()")
        if n.fn == "has" and (len(n.args) != 1 or n.args[0].k not in ("member", "index")):
            raise ExprError("has() expects a field selection, e.g. has(args.x)")
        for a in n.args:
            _validate(a)
    elif n.k == "method":
        if n.fn not in METHODS:
            raise ExprError(f"Unknown method .{n.fn}()")
        if n.fn == "matches":
            p = n.args[0] if n.args else None
            if p is None or p.k != "lit" or not isinstance(p.v, str):
                raise ExprError(".matches() requires a string literal pattern")
            if len(p.v) > MAX_REGEX_LENGTH:
                raise ExprError("Regex pattern too long")
            try:
                re.compile(p.v)
            except re.error as e:
                raise ExprError(f"Invalid regex: {e}") from e
        _validate(n.a)  # type: ignore[arg-type]
        for a in n.args:
            _validate(a)
    elif n.k in ("macro", "index", "bin"):
        _validate(n.a)  # type: ignore[arg-type]
        _validate(n.b)  # type: ignore[arg-type]
    elif n.k in ("member", "un"):
        _validate(n.a)  # type: ignore[arg-type]
    elif n.k == "list":
        for i in n.items:
            _validate(i)
    elif n.k == "cond":
        _validate(n.a)  # type: ignore[arg-type]
        _validate(n.b)  # type: ignore[arg-type]
        _validate(n.c)  # type: ignore[arg-type]


# ---------- values (JavaScript semantics) ----------

def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _type_name(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if _is_num(v):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "list"
    return "object"


def _prop(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(key) if key in obj else None
    if isinstance(obj, list):
        if key == "length":
            return len(obj)
        if key.isdigit() and int(key) < len(obj):
            return obj[int(key)]
    return None


def _truthy(v: Any) -> bool:
    if not isinstance(v, bool):
        raise ExprError(f"Expected boolean, got {_type_name(v)}")
    return v


def _equals(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_num(a) and _is_num(b):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_equals(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return len(a) == len(b) and all(k in b and _equals(a[k], b[k]) for k in a)
    if a is None or b is None:
        return a is b
    return type(a) is type(b) and a == b


def _size(v: Any) -> int:
    if isinstance(v, (str, list, dict)):
        return len(v)
    raise ExprError(f"size() of {_type_name(v)}")


def _str(v: Any, fn: str) -> str:
    if not isinstance(v, str):
        raise ExprError(f".{fn}() expects a string, got {_type_name(v)}")
    return v


def _js_number(v: Any) -> float:
    """JavaScript Number(v) for the value kinds policies see."""
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if v is None:
        return 0.0
    if _is_num(v):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return 0.0
        try:
            return float(s)
        except ValueError:
            return math.nan
    return math.nan


def _num_out(x: float) -> int | float:
    return int(x) if x.is_integer() else x


def _js_string(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "Infinity" if v > 0 else "-Infinity"
        return str(int(v)) if v.is_integer() else repr(v)
    if isinstance(v, (list, dict)):
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False)
    return str(v)


_regex_cache: dict[str, re.Pattern[str]] = {}


def _evaluate(n: Node, ctx: dict[str, Any], vars: dict[str, Any]) -> Any:
    k = n.k
    if k == "lit":
        return n.v
    if k == "id":
        return vars[n.name] if n.name in vars else _prop(ctx, n.name)
    if k == "list":
        return [_evaluate(i, ctx, vars) for i in n.items]
    if k == "member":
        return _prop(_evaluate(n.a, ctx, vars), n.name)  # type: ignore[arg-type]
    if k == "index":
        o = _evaluate(n.a, ctx, vars)  # type: ignore[arg-type]
        i = _evaluate(n.b, ctx, vars)  # type: ignore[arg-type]
        if isinstance(o, list) and _is_num(i):
            if float(i).is_integer() and 0 <= i < len(o):
                return o[int(i)]
            return None
        if isinstance(i, str):
            return _prop(o, i)
        return None
    if k == "cond":
        return _evaluate(n.b if _truthy(_evaluate(n.a, ctx, vars)) else n.c, ctx, vars)  # type: ignore[arg-type]
    if k == "un":
        x = _evaluate(n.a, ctx, vars)  # type: ignore[arg-type]
        if n.op == "!":
            return not _truthy(x)
        if not _is_num(x):
            raise ExprError(f"Unary minus on {_type_name(x)}")
        return -x
    if k == "bin":
        return _binary(n, ctx, vars)
    if k == "call":
        return _call(n, ctx, vars)
    if k == "method":
        return _method(n, ctx, vars)
    if k == "macro":
        o = _evaluate(n.a, ctx, vars)  # type: ignore[arg-type]
        items = [] if o is None else o
        if not isinstance(items, list):
            raise ExprError(f".{n.fn}() on {_type_name(o)}")

        def run(item: Any) -> Any:
            return _evaluate(n.b, ctx, {**vars, n.var: item})  # type: ignore[arg-type]

        if n.fn == "all":
            return all(_truthy(run(x)) for x in items)
        if n.fn == "exists":
            return any(_truthy(run(x)) for x in items)
        return [x for x in items if _truthy(run(x))]
    raise ExprError(f"Unknown node {k}")


def _binary(n: Node, ctx: dict[str, Any], vars: dict[str, Any]) -> Any:
    op = n.op
    if op == "&&":
        return _truthy(_evaluate(n.a, ctx, vars)) and _truthy(_evaluate(n.b, ctx, vars))  # type: ignore[arg-type]
    if op == "||":
        return _truthy(_evaluate(n.a, ctx, vars)) or _truthy(_evaluate(n.b, ctx, vars))  # type: ignore[arg-type]
    left = _evaluate(n.a, ctx, vars)  # type: ignore[arg-type]
    right = _evaluate(n.b, ctx, vars)  # type: ignore[arg-type]
    if op == "==":
        return _equals(left, right)
    if op == "!=":
        return not _equals(left, right)
    if op == "in":
        if isinstance(right, list):
            return any(_equals(x, left) for x in right)
        if isinstance(right, str) and isinstance(left, str):
            return left in right
        if isinstance(right, dict) and isinstance(left, str):
            return left in right
        return False
    if op in ("<", "<=", ">", ">="):
        if left is None or right is None:
            return False
        same = (_is_num(left) and _is_num(right)) or (isinstance(left, str) and isinstance(right, str))
        if not same:
            raise ExprError(f"Cannot compare {_type_name(left)} {op} {_type_name(right)}")
        return left < right if op == "<" else left <= right if op == "<=" else left > right if op == ">" else left >= right
    if op == "+":
        if _is_num(left) and _is_num(right):
            return left + right
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        if isinstance(left, list) and isinstance(right, list):
            return [*left, *right]
        raise ExprError(f"Cannot add {_type_name(left)} and {_type_name(right)}")
    if op in ("-", "*", "/", "%"):
        if not (_is_num(left) and _is_num(right)):
            raise ExprError(f"Arithmetic on {_type_name(left)}, {_type_name(right)}")
        if op in ("/", "%") and right == 0:
            raise ExprError("Division by zero")
        if op == "-":
            return left - right
        if op == "*":
            return left * right
        if op == "/":
            return _num_out(left / right)
        r = math.fmod(left, right)  # JavaScript: the result takes the sign of the dividend
        return int(r) if isinstance(left, int) and isinstance(right, int) else r
    raise ExprError(f"Unknown operator {op}")


def _call(n: Node, ctx: dict[str, Any], vars: dict[str, Any]) -> Any:
    if n.fn == "has":
        sel = n.args[0]
        base = _evaluate(sel.a, ctx, vars)  # type: ignore[arg-type]
        key = sel.name if sel.k == "member" else _evaluate(sel.b, ctx, vars)  # type: ignore[arg-type]
        if isinstance(base, dict):
            return _js_string(key) in base
        if isinstance(base, list):
            s = _js_string(key)
            return s.isdigit() and int(s) < len(base)
        return False
    a = [_evaluate(x, ctx, vars) for x in n.args]
    fn = n.fn
    if fn == "size":
        return _size(a[0] if a else None)
    if fn in ("int", "double"):
        v = _js_number(a[0] if a else None)
        if not math.isfinite(v):
            raise ExprError(f"{fn}() of non-number")
        return int(v) if fn == "int" else _num_out(v)
    if fn == "string":
        return _js_string(a[0] if a else None)
    if fn == "lower":
        return _str(a[0] if a else None, "lower").lower()
    if fn == "upper":
        return _str(a[0] if a else None, "upper").upper()
    if fn == "abs":
        if not a or not _is_num(a[0]):
            raise ExprError("abs() of non-number")
        return abs(a[0])
    if fn in ("min", "max"):
        nums = a[0] if len(a) == 1 and isinstance(a[0], list) else a
        if not nums or any(not _is_num(x) for x in nums):
            raise ExprError(f"{fn}() expects numbers")
        return min(nums) if fn == "min" else max(nums)
    raise ExprError(f"Unknown function {fn}")


def _method(n: Node, ctx: dict[str, Any], vars: dict[str, Any]) -> Any:
    o = _evaluate(n.a, ctx, vars)  # type: ignore[arg-type]
    a = [_evaluate(x, ctx, vars) for x in n.args]
    fn = n.fn
    arg0 = a[0] if a else None
    if fn == "startsWith":
        return _str(o, fn).startswith(_str(arg0, fn))
    if fn == "endsWith":
        return _str(o, fn).endswith(_str(arg0, fn))
    if fn == "contains":
        if isinstance(o, list):
            return any(_equals(x, arg0) for x in o)
        return _str(arg0, fn) in _str(o, fn)
    if fn == "matches":
        pattern = arg0
        rx = _regex_cache.get(pattern)
        if rx is None:
            rx = re.compile(pattern)
            _regex_cache[pattern] = rx
        return rx.search(_str(o, fn)[:10_000]) is not None
    if fn == "size":
        return _size(o)
    if fn == "lower":
        return _str(o, fn).lower()
    if fn == "upper":
        return _str(o, fn).upper()
    if fn == "trim":
        return _str(o, fn).strip()
    if fn == "keys":
        if isinstance(o, dict):
            return list(o.keys())
        raise ExprError(".keys() of non-map")
    raise ExprError(f"Unknown method {fn}")


@dataclass
class CompiledExpr:
    source: str
    ast: Node

    def eval(self, ctx: dict[str, Any]) -> Any:
        return _evaluate(self.ast, ctx, {})


def compile_expr(source: str) -> CompiledExpr:
    """Parses and statically validates an expression. Raises ExprError on bad syntax."""
    ast = _Parser(_tokenize(source)).parse()
    _validate(ast)
    return CompiledExpr(source, ast)
