// A small, safe, CEL-flavoured expression language for policy conditions.
//
//   args.amount <= 50 && args.currency == 'EUR'
//   session.tainted && !args.to.endsWith('@acme.com')
//   args.recipients.all(r, r.endsWith('@acme.com'))
//   tool.risk in ['destructive', 'financial']
//   has(args.dry_run) && args.dry_run == true
//
// Parsed once into an AST; evaluation is a tree walk with no access to the JS runtime.
// Missing fields evaluate to `null`; ordering comparisons involving null are false.

export type Node =
  | { k: "lit"; v: unknown }
  | { k: "id"; name: string }
  | { k: "list"; items: Node[] }
  | { k: "member"; obj: Node; prop: string }
  | { k: "index"; obj: Node; idx: Node }
  | { k: "call"; fn: string; args: Node[] }
  | { k: "method"; obj: Node; fn: string; args: Node[] }
  | { k: "macro"; obj: Node; fn: "all" | "exists" | "filter"; v: string; body: Node }
  | { k: "un"; op: "!" | "-"; x: Node }
  | { k: "bin"; op: string; l: Node; r: Node }
  | { k: "cond"; c: Node; t: Node; f: Node };

export class ExprError extends Error {}

type Tok = { t: "num" | "str" | "id" | "op" | "eof"; v: string; pos: number };

const OPS = ["&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "+", "-", "*", "/", "%", "(", ")", "[", "]", ".", ",", "?", ":"];
const MAX_EXPR_LENGTH = 4096;
const MAX_REGEX_LENGTH = 256;

function tokenize(src: string): Tok[] {
  if (src.length > MAX_EXPR_LENGTH) throw new ExprError("Expression too long");
  const toks: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (/\s/.test(c)) { i++; continue; }
    if (/[0-9]/.test(c)) {
      const m = /^\d+(\.\d+)?/.exec(src.slice(i))!;
      toks.push({ t: "num", v: m[0], pos: i });
      i += m[0].length;
      continue;
    }
    if (c === "'" || c === '"') {
      let j = i + 1;
      let out = "";
      while (j < src.length && src[j] !== c) {
        if (src[j] === "\\" && j + 1 < src.length) {
          const n = src[j + 1]!;
          out += n === "n" ? "\n" : n === "t" ? "\t" : n;
          j += 2;
        } else out += src[j++];
      }
      if (j >= src.length) throw new ExprError(`Unterminated string at ${i}`);
      toks.push({ t: "str", v: out, pos: i });
      i = j + 1;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i))!;
      toks.push({ t: "id", v: m[0], pos: i });
      i += m[0].length;
      continue;
    }
    const op = OPS.find((o) => src.startsWith(o, i));
    if (!op) throw new ExprError(`Unexpected character '${c}' at ${i}`);
    toks.push({ t: "op", v: op, pos: i });
    i += op.length;
  }
  toks.push({ t: "eof", v: "", pos: src.length });
  return toks;
}

class Parser {
  private i = 0;
  private toks: Tok[];
  constructor(toks: Tok[]) {
    this.toks = toks;
  }
  private peek(): Tok { return this.toks[this.i]!; }
  private next(): Tok { return this.toks[this.i++]!; }
  private isOp(v: string): boolean { const t = this.peek(); return t.t === "op" && t.v === v; }
  private isId(v: string): boolean { const t = this.peek(); return t.t === "id" && t.v === v; }
  private expect(v: string): void {
    const t = this.next();
    if (t.t !== "op" || t.v !== v) throw new ExprError(`Expected '${v}' at ${t.pos}, got '${t.v || "end"}'`);
  }

  parse(): Node {
    const n = this.ternary();
    if (this.peek().t !== "eof") throw new ExprError(`Unexpected '${this.peek().v}' at ${this.peek().pos}`);
    return n;
  }
  private ternary(): Node {
    const c = this.or();
    if (this.isOp("?")) {
      this.next();
      const t = this.ternary();
      this.expect(":");
      const f = this.ternary();
      return { k: "cond", c, t, f };
    }
    return c;
  }
  private or(): Node {
    let l = this.and();
    while (this.isOp("||")) { this.next(); l = { k: "bin", op: "||", l, r: this.and() }; }
    return l;
  }
  private and(): Node {
    let l = this.cmp();
    while (this.isOp("&&")) { this.next(); l = { k: "bin", op: "&&", l, r: this.cmp() }; }
    return l;
  }
  private cmp(): Node {
    const l = this.add();
    const t = this.peek();
    if ((t.t === "op" && ["==", "!=", "<", "<=", ">", ">="].includes(t.v)) || (t.t === "id" && t.v === "in")) {
      this.next();
      return { k: "bin", op: t.v, l, r: this.add() };
    }
    return l;
  }
  private add(): Node {
    let l = this.mul();
    while (this.isOp("+") || this.isOp("-")) { const op = this.next().v; l = { k: "bin", op, l, r: this.mul() }; }
    return l;
  }
  private mul(): Node {
    let l = this.unary();
    while (this.isOp("*") || this.isOp("/") || this.isOp("%")) { const op = this.next().v; l = { k: "bin", op, l, r: this.unary() }; }
    return l;
  }
  private unary(): Node {
    if (this.isOp("!")) { this.next(); return { k: "un", op: "!", x: this.unary() }; }
    if (this.isOp("-")) { this.next(); return { k: "un", op: "-", x: this.unary() }; }
    return this.postfix();
  }
  private postfix(): Node {
    let n = this.primary();
    for (;;) {
      if (this.isOp(".")) {
        this.next();
        const name = this.next();
        if (name.t !== "id") throw new ExprError(`Expected property name at ${name.pos}`);
        if (this.isOp("(")) {
          this.next();
          if (name.v === "all" || name.v === "exists" || name.v === "filter") {
            const v = this.next();
            if (v.t !== "id") throw new ExprError(`${name.v}() expects a variable name at ${v.pos}`);
            this.expect(",");
            const body = this.ternary();
            this.expect(")");
            n = { k: "macro", obj: n, fn: name.v, v: v.v, body };
          } else {
            n = { k: "method", obj: n, fn: name.v, args: this.args() };
          }
        } else n = { k: "member", obj: n, prop: name.v };
      } else if (this.isOp("[")) {
        this.next();
        const idx = this.ternary();
        this.expect("]");
        n = { k: "index", obj: n, idx };
      } else return n;
    }
  }
  private args(): Node[] {
    const out: Node[] = [];
    if (this.isOp(")")) { this.next(); return out; }
    for (;;) {
      out.push(this.ternary());
      if (this.isOp(",")) { this.next(); continue; }
      this.expect(")");
      return out;
    }
  }
  private primary(): Node {
    const t = this.next();
    if (t.t === "num") return { k: "lit", v: Number(t.v) };
    if (t.t === "str") return { k: "lit", v: t.v };
    if (t.t === "id") {
      if (t.v === "true") return { k: "lit", v: true };
      if (t.v === "false") return { k: "lit", v: false };
      if (t.v === "null") return { k: "lit", v: null };
      if (this.isOp("(")) { this.next(); return { k: "call", fn: t.v, args: this.args() }; }
      return { k: "id", name: t.v };
    }
    if (t.t === "op" && t.v === "(") { const n = this.ternary(); this.expect(")"); return n; }
    if (t.t === "op" && t.v === "[") {
      const items: Node[] = [];
      if (!this.isOp("]")) {
        for (;;) {
          items.push(this.ternary());
          if (this.isOp(",")) { this.next(); continue; }
          break;
        }
      }
      this.expect("]");
      return { k: "list", items };
    }
    throw new ExprError(`Unexpected '${t.v || "end of expression"}' at ${t.pos}`);
  }
}

const FUNCTIONS = new Set(["size", "has", "int", "double", "string", "lower", "upper", "abs", "min", "max"]);
const METHODS = new Set(["startsWith", "endsWith", "contains", "matches", "size", "lower", "upper", "trim", "keys"]);

export interface CompiledExpr {
  source: string;
  ast: Node;
  eval(ctx: Record<string, unknown>): unknown;
}

/** Parses and statically validates an expression. Throws ExprError on bad syntax. */
export function compileExpr(source: string): CompiledExpr {
  const ast = new Parser(tokenize(source)).parse();
  validate(ast);
  return { source, ast, eval: (ctx) => evaluate(ast, ctx, new Map()) };
}

function validate(n: Node): void {
  switch (n.k) {
    case "call":
      if (!FUNCTIONS.has(n.fn)) throw new ExprError(`Unknown function ${n.fn}()`);
      if (n.fn === "has" && (n.args.length !== 1 || (n.args[0]!.k !== "member" && n.args[0]!.k !== "index")))
        throw new ExprError("has() expects a field selection, e.g. has(args.x)");
      n.args.forEach(validate);
      return;
    case "method":
      if (!METHODS.has(n.fn)) throw new ExprError(`Unknown method .${n.fn}()`);
      if (n.fn === "matches") {
        const p = n.args[0];
        if (!p || p.k !== "lit" || typeof p.v !== "string") throw new ExprError(".matches() requires a string literal pattern");
        if (p.v.length > MAX_REGEX_LENGTH) throw new ExprError("Regex pattern too long");
        new RegExp(p.v); // syntax check at load time
      }
      validate(n.obj);
      n.args.forEach(validate);
      return;
    case "macro": validate(n.obj); validate(n.body); return;
    case "member": validate(n.obj); return;
    case "index": validate(n.obj); validate(n.idx); return;
    case "list": n.items.forEach(validate); return;
    case "un": validate(n.x); return;
    case "bin": validate(n.l); validate(n.r); return;
    case "cond": validate(n.c); validate(n.t); validate(n.f); return;
    default: return;
  }
}

const regexCache = new Map<string, RegExp>();

function prop(obj: unknown, key: string): unknown {
  if (obj === null || obj === undefined) return null;
  if (typeof obj === "object" && Object.prototype.hasOwnProperty.call(obj, key)) {
    const v = (obj as Record<string, unknown>)[key];
    return v === undefined ? null : v;
  }
  return null;
}

function truthy(v: unknown): boolean {
  if (typeof v !== "boolean") throw new ExprError(`Expected boolean, got ${typeName(v)}`);
  return v;
}

function typeName(v: unknown): string {
  return v === null ? "null" : Array.isArray(v) ? "list" : typeof v;
}

function equals(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => equals(x, b[i]));
  if (a && b && typeof a === "object" && typeof b === "object") {
    const ka = Object.keys(a), kb = Object.keys(b);
    return ka.length === kb.length && ka.every((k) => equals((a as any)[k], (b as any)[k]));
  }
  return false;
}

function size(v: unknown): number {
  if (typeof v === "string" || Array.isArray(v)) return v.length;
  if (v && typeof v === "object") return Object.keys(v).length;
  throw new ExprError(`size() of ${typeName(v)}`);
}

function str(v: unknown, fn: string): string {
  if (typeof v !== "string") throw new ExprError(`.${fn}() expects a string, got ${typeName(v)}`);
  return v;
}

function evaluate(n: Node, ctx: Record<string, unknown>, vars: Map<string, unknown>): unknown {
  switch (n.k) {
    case "lit": return n.v;
    case "id": return vars.has(n.name) ? vars.get(n.name) : prop(ctx, n.name);
    case "list": return n.items.map((i) => evaluate(i, ctx, vars));
    case "member": return prop(evaluate(n.obj, ctx, vars), n.prop);
    case "index": {
      const o = evaluate(n.obj, ctx, vars);
      const i = evaluate(n.idx, ctx, vars);
      if (Array.isArray(o) && typeof i === "number") return o[i] ?? null;
      if (typeof i === "string") return prop(o, i);
      return null;
    }
    case "cond": return truthy(evaluate(n.c, ctx, vars)) ? evaluate(n.t, ctx, vars) : evaluate(n.f, ctx, vars);
    case "un": {
      const x = evaluate(n.x, ctx, vars);
      if (n.op === "!") return !truthy(x);
      if (typeof x !== "number") throw new ExprError(`Unary minus on ${typeName(x)}`);
      return -x;
    }
    case "bin": {
      if (n.op === "&&") return truthy(evaluate(n.l, ctx, vars)) && truthy(evaluate(n.r, ctx, vars));
      if (n.op === "||") return truthy(evaluate(n.l, ctx, vars)) || truthy(evaluate(n.r, ctx, vars));
      const l = evaluate(n.l, ctx, vars);
      const r = evaluate(n.r, ctx, vars);
      switch (n.op) {
        case "==": return equals(l, r);
        case "!=": return !equals(l, r);
        case "in":
          if (Array.isArray(r)) return r.some((x) => equals(x, l));
          if (typeof r === "string" && typeof l === "string") return r.includes(l);
          if (r && typeof r === "object" && typeof l === "string") return Object.prototype.hasOwnProperty.call(r, l);
          return false;
        case "<": case "<=": case ">": case ">=": {
          if (l === null || r === null) return false;
          if (typeof l !== typeof r || (typeof l !== "number" && typeof l !== "string"))
            throw new ExprError(`Cannot compare ${typeName(l)} ${n.op} ${typeName(r)}`);
          const a = l as number, b = r as number;
          return n.op === "<" ? a < b : n.op === "<=" ? a <= b : n.op === ">" ? a > b : a >= b;
        }
        case "+":
          if (typeof l === "number" && typeof r === "number") return l + r;
          if (typeof l === "string" && typeof r === "string") return l + r;
          if (Array.isArray(l) && Array.isArray(r)) return [...l, ...r];
          throw new ExprError(`Cannot add ${typeName(l)} and ${typeName(r)}`);
        case "-": case "*": case "/": case "%": {
          if (typeof l !== "number" || typeof r !== "number") throw new ExprError(`Arithmetic on ${typeName(l)}, ${typeName(r)}`);
          if ((n.op === "/" || n.op === "%") && r === 0) throw new ExprError("Division by zero");
          return n.op === "-" ? l - r : n.op === "*" ? l * r : n.op === "/" ? l / r : l % r;
        }
      }
      throw new ExprError(`Unknown operator ${n.op}`);
    }
    case "call": {
      if (n.fn === "has") {
        const sel = n.args[0]!;
        const base = evaluate(sel.k === "member" ? sel.obj : (sel as { obj: Node }).obj, ctx, vars);
        const key = sel.k === "member" ? sel.prop : evaluate((sel as { idx: Node }).idx, ctx, vars);
        return base !== null && typeof base === "object" && Object.prototype.hasOwnProperty.call(base, String(key))
          && (base as Record<string, unknown>)[String(key)] !== undefined;
      }
      const a = n.args.map((x) => evaluate(x, ctx, vars));
      switch (n.fn) {
        case "size": return size(a[0]);
        case "int": { const v = Number(a[0]); if (!Number.isFinite(v)) throw new ExprError("int() of non-number"); return Math.trunc(v); }
        case "double": { const v = Number(a[0]); if (!Number.isFinite(v)) throw new ExprError("double() of non-number"); return v; }
        case "string": return a[0] === null ? "null" : typeof a[0] === "object" ? JSON.stringify(a[0]) : String(a[0]);
        case "lower": return str(a[0], "lower").toLowerCase();
        case "upper": return str(a[0], "upper").toUpperCase();
        case "abs": if (typeof a[0] !== "number") throw new ExprError("abs() of non-number"); return Math.abs(a[0]);
        case "min": case "max": {
          const nums = (a.length === 1 && Array.isArray(a[0]) ? a[0] : a) as unknown[];
          if (!nums.length || nums.some((x) => typeof x !== "number")) throw new ExprError(`${n.fn}() expects numbers`);
          return n.fn === "min" ? Math.min(...(nums as number[])) : Math.max(...(nums as number[]));
        }
      }
      throw new ExprError(`Unknown function ${n.fn}`);
    }
    case "method": {
      const o = evaluate(n.obj, ctx, vars);
      const a = n.args.map((x) => evaluate(x, ctx, vars));
      switch (n.fn) {
        case "startsWith": return str(o, n.fn).startsWith(str(a[0], n.fn));
        case "endsWith": return str(o, n.fn).endsWith(str(a[0], n.fn));
        case "contains":
          if (Array.isArray(o)) return o.some((x) => equals(x, a[0]));
          return str(o, n.fn).includes(str(a[0], n.fn));
        case "matches": {
          const p = a[0] as string;
          let re = regexCache.get(p);
          if (!re) { re = new RegExp(p); regexCache.set(p, re); }
          return re.test(str(o, n.fn).slice(0, 10_000));
        }
        case "size": return size(o);
        case "lower": return str(o, n.fn).toLowerCase();
        case "upper": return str(o, n.fn).toUpperCase();
        case "trim": return str(o, n.fn).trim();
        case "keys": if (o && typeof o === "object" && !Array.isArray(o)) return Object.keys(o); throw new ExprError(".keys() of non-map");
      }
      throw new ExprError(`Unknown method ${n.fn}`);
    }
    case "macro": {
      const o = evaluate(n.obj, ctx, vars);
      const list = o === null ? [] : o;
      if (!Array.isArray(list)) throw new ExprError(`.${n.fn}() on ${typeName(o)}`);
      const run = (item: unknown) => {
        const inner = new Map(vars);
        inner.set(n.v, item);
        return evaluate(n.body, ctx, inner);
      };
      if (n.fn === "all") return list.every((x) => truthy(run(x)));
      if (n.fn === "exists") return list.some((x) => truthy(run(x)));
      return list.filter((x) => truthy(run(x)));
    }
  }
}
