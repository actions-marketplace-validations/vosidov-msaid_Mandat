// Replays spec/conformance/policy.json, the cases every Mandat SDK (TypeScript, Python, …) must agree on.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { compileExpr } from "../src/policy/expr.ts";
import { compilePolicy } from "../src/policy/engine.ts";

const spec = JSON.parse(readFileSync(new URL("../spec/conformance/policy.json", import.meta.url), "utf8"));

test("conformance: expression language", () => {
  for (const c of spec.expressions) {
    if (c.compile_error) { assert.throws(() => compileExpr(c.expr), Error, c.expr); continue; }
    if (c.error) { assert.throws(() => compileExpr(c.expr).eval(c.ctx ?? {}), Error, c.expr); continue; }
    assert.deepEqual(compileExpr(c.expr).eval(c.ctx ?? {}), c.expect, c.expr);
  }
});

test("conformance: policy decisions", () => {
  for (const p of spec.policies) {
    const policy = compilePolicy(p.policy);
    for (const c of p.cases) {
      const d = policy.evaluate(c.input);
      const label = `${p.name}: ${c.input.tool.name} ${JSON.stringify(c.input.args)}`;
      assert.equal(d.effect, c.effect, label);
      assert.deepEqual(d.matched, c.matched, label);
      assert.deepEqual(d.obligations, c.obligations, label);
      assert.equal(d.errors.length, c.error_count, label);
    }
  }
});
