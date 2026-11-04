"""Replays spec/conformance/policy.json: the Python SDK must decide exactly like the TypeScript reference."""

import json
import unittest
from pathlib import Path

from mandat.expr import compile_expr
from mandat.policy import compile_policy

SPEC = json.loads((Path(__file__).resolve().parents[2] / "spec" / "conformance" / "policy.json").read_text(encoding="utf-8"))


def same(a, b) -> bool:
    """JSON equality with JavaScript number semantics (3 == 3.0) but booleans never equal numbers."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    return a == b


class Conformance(unittest.TestCase):
    def test_expressions(self):
        for c in SPEC["expressions"]:
            with self.subTest(expr=c["expr"]):
                if c.get("compile_error"):
                    with self.assertRaises(Exception):
                        compile_expr(c["expr"])
                elif c.get("error"):
                    with self.assertRaises(Exception):
                        compile_expr(c["expr"]).eval(c.get("ctx", {}))
                else:
                    got = compile_expr(c["expr"]).eval(c.get("ctx", {}))
                    self.assertTrue(same(got, c["expect"]), f"{c['expr']}: got {got!r}, expected {c['expect']!r}")

    def test_policy_decisions(self):
        for p in SPEC["policies"]:
            policy = compile_policy(p["policy"])
            for c in p["cases"]:
                label = f"{p['name']}: {c['input']['tool']['name']} {json.dumps(c['input']['args'])}"
                with self.subTest(case=label):
                    d = policy.evaluate(c["input"])
                    self.assertEqual(d.effect, c["effect"], label)
                    self.assertEqual(d.matched, c["matched"], label)
                    self.assertTrue(same(d.obligations, c["obligations"]), label)
                    self.assertEqual(len(d.errors), c["error_count"], f"{label}: {d.errors}")
                    if c["approval"]:
                        self.assertTrue(same(d.approval, c["approval"]), f"{label}: {d.approval}")

    def test_policy_version_matches_typescript(self):
        # Same canonical JSON -> same policy version in both SDKs' ledger records.
        import subprocess
        out = subprocess.run(
            ["node", "-e", "import('./src/policy/engine.ts').then(function(m){const s=require('./spec/conformance/policy.json');console.log(s.policies.map(function(p){return m.compilePolicy(p.policy).version}).join(','))})"],
            cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, check=True,
        ).stdout.strip()
        py = ",".join(compile_policy(p["policy"]).version for p in SPEC["policies"])
        self.assertEqual(py, out)


if __name__ == "__main__":
    unittest.main()
