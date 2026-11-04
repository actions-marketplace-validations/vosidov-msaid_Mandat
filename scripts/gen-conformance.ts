// Generates spec/conformance/policy.json from the TypeScript engine (the reference implementation).
// The TypeScript and Python test suites both replay it, so every SDK decides exactly the same way.
//   node scripts/gen-conformance.ts          (re-run after changing the language or the engine)

import { writeFileSync, mkdirSync } from "node:fs";
import { compileExpr } from "../src/policy/expr.ts";
import { compilePolicy, type PolicyDocument, type PolicyInput } from "../src/policy/engine.ts";
import { STARTER_POLICY } from "../src/cli/templates.ts";

type ExprCase = { expr: string; ctx?: Record<string, unknown>; expect?: unknown; error?: true; compile_error?: true };

const ctx = { args: { amount: 50, currency: "EUR", to: ["a@acme.test", "b@acme.test"], subject: "Hello World", tags: { vip: true }, n: -7 }, session: { tainted: true } };
const exprs: Array<[string, Record<string, unknown>?]> = [
  ["1 + 2 * 3 == 7"], ["(1 + 2) * 3"], ["7 / 2"], ["args.n % 3", ctx], ["-args.n", ctx], ["!(1 < 2) || false"], ["true ? 'a' : 'b'"],
  ["args.amount <= 50 && args.currency == 'EUR'", ctx], ["args.amount > 50", ctx], ["args.missing > 5", ctx], ["args.missing <= 5", ctx],
  ["args.missing == null", ctx], ["args.missing.deeper == null", ctx], ["has(args.subject) && !has(args.missing)", ctx],
  ["args.to.all(r, r.endsWith('@acme.test'))", ctx], ["args.to.exists(r, r.startsWith('b'))", ctx], ["size(args.to.filter(r, r.contains('a@')))", ctx],
  ["'vip' in args.tags", ctx], ["'x' in ['x', 'y']"], ["'ell' in 'hello'"], ["args.subject.lower().matches('^hello')", ctx], ["args.subject.upper()", ctx],
  ["' x '.trim()"], ["args.tags.keys()", ctx], ["max(1, 5, 3) + min([4, 2])"], ["abs(-3)"], ["int(3.9)"], ["int(-3.9)"], ["double(2)"], ["string(12)"],
  ["args.to[1]", ctx], ["args.to[9]", ctx], ["args['currency']", ctx], ["size('hello') + args.to.size()", ctx], ["[1, 2] + [3]"], ["'a' + 'b'"],
  ["[1, 2] == [1, 2]"], ["{} == {}"], ["1 == 1.0"], ["true == 1"], ["null == false"], ["'a' < 'b'"], ["session.tainted && true", ctx],
  ["args.constructor", ctx], ["args.__proto__", ctx], ["args.toString", ctx],
  ["'a' < 1"], ["1 && true"], ["!5"], ["1 / 0"], ["'x' - 1"], ["size(5)"], ["args.amount.lower()", ctx],
];
const compileErrors = ["1 +", "'unterminated", "args.x.matches(args.y)", "process.exit(1)", "args.x.call()", "eval('1')", "has(1)", "1 $ 2"];

const exprCases: ExprCase[] = [];
for (const [expr, c] of exprs) {
  try {
    exprCases.push({ expr, ...(c ? { ctx: c } : {}), expect: compileExpr(expr).eval(c ?? {}) });
  } catch {
    exprCases.push({ expr, ...(c ? { ctx: c } : {}), error: true });
  }
}
for (const expr of compileErrors) exprCases.push({ expr, compile_error: true });

const FAIL_CLOSED: PolicyDocument = {
  version: 1,
  rules: [
    { id: "allow-if-small", tool: "t", when: "args.amount.size() < 3", effect: "allow" },
    { id: "deny-if-weird", tool: "t", when: "args.amount.lower() == 'x'", effect: "deny" },
    { id: "approve-odd", tool: "u", when: "args.amount.lower() == 'x'", effect: "require_approval" },
    { id: "ok-u", tool: "u", effect: "allow" },
  ],
};
const GLOBS: PolicyDocument = {
  version: 1,
  default: "require_approval",
  tools: { "crm.*": { risk: "write", redact: ["ssn"] } },
  rules: [
    { id: "crm", tool: "crm.*", agent: "sales-*", effect: "allow_with_obligations", obligations: [{ type: "annotate", tags: ["crm"] }] },
    { id: "night", tool: "crm.delete", when: "env.hour_utc >= 0", effect: "deny" },
  ],
};

const base = (tool: string, args: Record<string, unknown>, more: Partial<PolicyInput> = {}): PolicyInput =>
  ({ principal: { sub: "u" }, agent: { id: "a" }, tool: { name: tool }, args, ...more });
const cap = (tools: string[], limits?: Record<string, unknown>) => ({ authorization_details: [{ type: "mandat_tool_call", tools, ...(limits ? { limits } : {}) }] });

const policies: Array<{ name: string; policy: PolicyDocument; inputs: PolicyInput[] }> = [
  {
    name: "starter",
    policy: STARTER_POLICY,
    inputs: [
      base("refund", { amount: 20, currency: "EUR" }), base("refund", { amount: 50, currency: "EUR" }), base("refund", { amount: 120, currency: "EUR" }),
      base("refund", { amount: 900, currency: "EUR" }), base("refund", { amount: 20, currency: "USD" }), base("refund", { currency: "EUR" }),
      base("lookup_order", { order_id: "A1" }), base("read_inbox", {}),
      base("send_email", { to: ["ops@example.com"], subject: "s", body: "b" }),
      base("send_email", { to: ["x@evil.test"], subject: "s", body: "b" }),
      base("send_email", { to: ["x@evil.test"], subject: "s", body: "b" }, { session: { tainted: true } }),
      base("send_email", { to: ["ops@example.com"], subject: "s", body: "b" }, { session: { tainted: true } }),
      base("send_email", { to: "not-a-list", subject: "s", body: "b" }),
      base("delete_customer", { customer_id: "C1" }), base("drop_database", {}),
      base("refund", { amount: 10, currency: "EUR" }, { task: cap(["lookup_order"]) }),
      base("refund", { amount: 25, currency: "EUR" }, { task: cap(["refund"], { amount: { max: 30 } }) }),
      base("refund", { amount: 40, currency: "EUR" }, { task: cap(["refund"], { amount: { max: 30 } }) }),
      base("refund", { amount: 40, currency: "USD" }, { task: cap(["refund"], { currency: { enum: ["EUR"] } }) }),
      base("lookup_order", {}, { task: { authorization_details: [{ type: "other" }] } }),
    ],
  },
  { name: "fail-closed", policy: FAIL_CLOSED, inputs: [base("t", { amount: 5 }), base("t", { amount: "ab" }), base("u", { amount: 5 })] },
  {
    name: "globs-and-default",
    policy: GLOBS,
    inputs: [
      { ...base("crm.update", {}), agent: { id: "sales-bot" } }, { ...base("crm.update", {}), agent: { id: "other" } },
      { ...base("crm.delete", {}), agent: { id: "sales-bot" } }, base("unknown", {}),
    ],
  },
];

const out = {
  $comment: "Generated by scripts/gen-conformance.ts from the TypeScript reference engine. Do not edit by hand.",
  expressions: exprCases,
  policies: policies.map((p) => {
    const compiled = compilePolicy(p.policy);
    return {
      name: p.name,
      policy: p.policy,
      cases: p.inputs.map((input) => {
        const d = compiled.evaluate(input);
        return {
          input,
          effect: d.effect,
          matched: d.matched,
          obligations: d.obligations,
          approval: d.approval ? { approvers: d.approval.approvers, timeoutMs: d.approval.timeoutMs, channels: d.approval.channels, rule: d.approval.rule } : null,
          risk: d.risk,
          error_count: d.errors.length,
        };
      }),
    };
  }),
};

mkdirSync("spec/conformance", { recursive: true });
writeFileSync("spec/conformance/policy.json", JSON.stringify(out, null, 2) + "\n");
console.log(`spec/conformance/policy.json: ${exprCases.length} expression cases, ${out.policies.reduce((n, p) => n + p.cases.length, 0)} policy decisions`);
