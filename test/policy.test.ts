import { test } from "node:test";
import assert from "node:assert/strict";
import { compileExpr, ExprError } from "../src/policy/expr.ts";
import { compilePolicy, PolicyError, runPolicyTests, type PolicyInput } from "../src/policy/engine.ts";
import { STARTER_POLICY, STARTER_TESTS } from "../src/cli/templates.ts";
import { REFUND_POLICY } from "./helpers.ts";

const ev = (src: string, ctx: Record<string, unknown> = {}) => compileExpr(src).eval(ctx);

test("expressions: arithmetic, comparison, logic, precedence", () => {
  assert.equal(ev("1 + 2 * 3 == 7"), true);
  assert.equal(ev("(1 + 2) * 3"), 9);
  assert.equal(ev("args.amount <= 50 && args.currency == 'EUR'", { args: { amount: 50, currency: "EUR" } }), true);
  assert.equal(ev("!(1 < 2) || false"), false);
  assert.equal(ev("true ? 'a' : 'b'"), "a");
  assert.equal(ev("-args.x > -10", { args: { x: 3 } }), true);
});

test("expressions: strings, lists, macros, functions", () => {
  const ctx = { args: { to: ["a@acme.test", "b@acme.test"], subject: "Hello World", tags: { vip: true } } };
  assert.equal(ev("args.to.all(r, r.endsWith('@acme.test'))", ctx), true);
  assert.equal(ev("args.to.exists(r, r.startsWith('b'))", ctx), true);
  assert.equal(ev("size(args.to.filter(r, r.contains('a@')))", ctx), 1);
  assert.equal(ev("'vip' in args.tags", ctx), true);
  assert.equal(ev("'x' in ['x', 'y']"), true);
  assert.equal(ev("args.subject.lower().matches('^hello')", ctx), true);
  assert.equal(ev("has(args.subject) && !has(args.missing)", ctx), true);
  assert.equal(ev("max(1, 5, 3) + min([4, 2])"), 7);
  assert.equal(ev("args.to[1]", ctx), "b@acme.test");
});

test("expressions: missing data is null and ordering comparisons with null are false", () => {
  assert.equal(ev("args.nope.deeper == null", { args: {} }), true);
  assert.equal(ev("args.amount > 5", { args: {} }), false);
  assert.equal(ev("args.amount <= 5", { args: {} }), false);
});

test("expressions: no access to JS internals", () => {
  assert.equal(ev("args.constructor", { args: {} }), null);
  assert.equal(ev("args.__proto__", { args: {} }), null);
  assert.equal(ev("args.toString", { args: {} }), null);
  assert.throws(() => compileExpr("process.exit(1)"), ExprError);
  assert.throws(() => compileExpr("args.x.call()"), /Unknown method/);
  assert.throws(() => compileExpr("eval('1')"), /Unknown function/);
});

test("expressions: syntax and type errors", () => {
  assert.throws(() => compileExpr("1 +"), ExprError);
  assert.throws(() => compileExpr("'unterminated"), ExprError);
  assert.throws(() => compileExpr("args.x.matches(args.y)"), /string literal/);
  assert.throws(() => ev("'a' < 1"), ExprError);
  assert.throws(() => ev("1 && true"), /Expected boolean/);
});

const input = (tool: string, args: Record<string, unknown>, more: Partial<PolicyInput> = {}): PolicyInput => ({
  principal: { sub: "u" }, agent: { id: "a" }, tool: { name: tool }, args, ...more,
});

test("policy: deny overrides, approval, allow, default deny", () => {
  const p = compilePolicy(REFUND_POLICY);
  assert.equal(p.evaluate(input("refund", { amount: 10 })).effect, "allow");
  const a = p.evaluate(input("refund", { amount: 100 }));
  assert.equal(a.effect, "require_approval");
  assert.equal(a.approval?.timeoutMs, 300_000);
  assert.equal(p.evaluate(input("refund", { amount: 1000 })).effect, "deny");
  assert.deepEqual(p.evaluate(input("refund", { amount: 1000 })).reasons, ["too much"]);
  assert.equal(p.evaluate(input("unknown_tool", {})).effect, "deny");
  // email allowed, but deny wins once the session is tainted
  assert.equal(p.evaluate(input("send_email", { to: "x@evil.test", body: "b" })).effect, "allow_with_obligations");
  assert.equal(p.evaluate(input("send_email", { to: "x@evil.test" }, { session: { tainted: true } })).effect, "deny");
  assert.equal(p.evaluate(input("send_email", { to: "y@acme.test" }, { session: { tainted: true } })).effect, "allow_with_obligations");
});

test("policy: evaluation errors fail closed", () => {
  const p = compilePolicy({
    version: 1,
    rules: [
      { id: "allow-if-small", tool: "t", when: "args.amount.size() < 3", effect: "allow" },
      { id: "deny-if-weird", tool: "t", when: "args.amount.lower() == 'x'", effect: "deny" },
    ],
  });
  const d = p.evaluate(input("t", { amount: 5 }));
  assert.equal(d.effect, "deny");
  assert.equal(d.errors.length, 2);
});

test("policy: capability from task token (authorization_details) is enforced before rules", () => {
  const p = compilePolicy(REFUND_POLICY);
  const task = { authorization_details: [{ type: "mandat_tool_call", tools: ["refund"], limits: { amount: { max: 30 } } }] };
  assert.equal(p.evaluate(input("refund", { amount: 20 }, { task })).effect, "allow");
  const over = p.evaluate(input("refund", { amount: 40 }, { task }));
  assert.equal(over.effect, "deny");
  assert.match(over.reasons[0]!, /amount must be <= 30/);
  assert.equal(p.evaluate(input("lookup", {}, { task })).effect, "deny");
});

test("policy: validation reports all problems", () => {
  assert.throws(
    () => compilePolicy({ version: 1, rules: [{ id: "a", effect: "maybe" as never }, { id: "a", when: "1 +", effect: "allow" }] }),
    (e: Error) => e instanceof PolicyError && /invalid effect/.test(e.message) && /duplicate id/.test(e.message) && /Unexpected/.test(e.message),
  );
});

test("policy: agent and glob tool matching, obligations merge", () => {
  const p = compilePolicy({
    version: 1,
    tools: { "crm.*": { risk: "write", redact: ["ssn"] } },
    rules: [
      { id: "crm", tool: "crm.*", agent: "sales-*", effect: "allow_with_obligations", obligations: [{ type: "annotate", tags: ["crm"] }] },
    ],
  });
  const d = p.evaluate({ ...input("crm.update", {}), agent: { id: "sales-bot" } });
  assert.equal(d.effect, "allow_with_obligations");
  assert.equal(d.risk, "write");
  assert.deepEqual(d.obligations.map((o) => o.type).sort(), ["annotate", "redact"]);
  assert.equal(p.evaluate({ ...input("crm.update", {}), agent: { id: "other" } }).effect, "deny");
});

test("starter policy passes its own test suite", () => {
  const results = runPolicyTests(compilePolicy(STARTER_POLICY), STARTER_TESTS as never);
  assert.deepEqual(results.filter((r) => !r.pass), []);
});

test("PDP latency: p99 < 5 ms, p50 < 0.5 ms", () => {
  const p = compilePolicy(STARTER_POLICY);
  const lat: number[] = [];
  for (let i = 0; i < 20_000; i++) {
    const t = process.hrtime.bigint();
    p.evaluate(input(i % 2 ? "refund" : "send_email", i % 2 ? { amount: i % 700, currency: "EUR" } : { to: ["a@example.com", "x@y.test"] }, { session: { tainted: i % 3 === 0 } }));
    lat.push(Number(process.hrtime.bigint() - t) / 1e6);
  }
  lat.sort((a, b) => a - b);
  assert.ok(lat[Math.floor(lat.length * 0.5)]! < 0.5, `p50 ${lat[Math.floor(lat.length * 0.5)]} ms`);
  assert.ok(lat[Math.floor(lat.length * 0.99)]! < 5, `p99 ${lat[Math.floor(lat.length * 0.99)]} ms`);
});
