# Policies

A policy is a JSON file (`mandat.policy.json`), distributed by the control plane to every guard and evaluated in-process on each tool call.

```jsonc
{
  "version": 1,
  "default": "deny",
  "tools": {
    "refund":     { "risk": "financial" },
    "read_inbox": { "risk": "read", "taints": true },
    "send_email": { "risk": "external_comm", "redact": ["body"] }
  },
  "rules": [
    { "id": "refund-auto",     "tool": "refund", "when": "args.amount <= 50", "effect": "allow" },
    { "id": "refund-approval", "tool": "refund", "when": "args.amount > 50 && args.amount <= 500",
      "effect": "require_approval", "approval": { "approvers": 1, "timeout": "15m", "channels": ["slack"] } },
    { "id": "refund-limit",    "tool": "refund", "when": "args.amount > 500", "effect": "deny",
      "reason": "Refunds above €500 go through finance" },
    { "id": "no-exfil", "tool": "send_email",
      "when": "session.tainted && !args.to.all(r, r.endsWith('@example.com'))", "effect": "deny" }
  ]
}
```

`mandat init` writes a complete starter policy with tests.

## How decisions are made

- **Deny overrides.** Any matching `deny` wins. Otherwise any `require_approval` wins. Otherwise `allow`, with obligations merged. Otherwise the policy `default`, which is `deny` unless set. Rule order doesn't matter.
- **Errors fail closed.** A condition that can't be evaluated (type error, missing data) counts as a match for `deny` and `require_approval` rules, and as no match for `allow` rules.
- **The token's capability comes first.** A call outside the task token's delegated tools, locations or argument limits is denied before any rule runs.
- **Taint.** A tool with `taints: true` marks the session as having seen untrusted content; rules can check `session.tainted`.
- **Fail modes.** If the guard can't refresh revocations for 15 seconds, `financial` and `destructive` tools fail closed. Policy keeps working from the last snapshot.
- **Speed.** Decisions take microseconds (p50 about 14 µs, p99 about 70 µs on a laptop).

## The expression language

`when` is a small, safe expression language similar to CEL. It never evaluates code and can't reach the runtime.

- **Context:** `principal.{sub, tenant, email, client_id}`, `agent.{id, version, prompt_hash}`, `actor_chain[]`, `tool.{name, server, risk}`, `args.*`, `session.{tainted, taint_sources, calls}`, `task.{id, authorization_details}`, `env.{hour_utc, weekday_utc}`.
- **Operators:** `== != < <= > >= in && || ! ?: + - * / %`
- **Functions:** `size has int double string lower upper abs min max`
- **Methods:** `startsWith endsWith contains matches size lower upper trim keys`
- **Macros:** `list.all(x, …)`, `list.exists(x, …)`, `list.filter(x, …)`
- **Missing fields** are `null`, and ordering comparisons with `null` are false. Booleans never equal numbers.

## Rule fields

| Field | Meaning |
|---|---|
| `id` | Unique name, recorded with every decision |
| `tool`, `agent` | Name, glob (`crm.*`) or list; omitted means all |
| `when` | Condition; omitted means always |
| `effect` | `allow`, `deny`, `require_approval` or `allow_with_obligations` |
| `reason` | Shown to the agent and stored in the ledger |
| `approval` | `approvers` (2 = four-eyes), `timeout`, `channels` |
| `obligations` | `{ "type": "redact", "fields": [...] }` or `{ "type": "annotate", "tags": [...] }` |

Tool classes (`tools`) set `risk` (`read`, `write`, `external_comm`, `financial` or `destructive`), `taints` and always-redacted fields.

## Test and roll out

```bash
mandat policy check                    # validate
mandat policy test                     # run mandat.policy.test.json (expected decisions)
mandat policy eval --tool refund --args '{"amount":120}'
mandat bench                           # decision latency
```

To try a new policy without blocking anything, run guards in **shadow mode** (`mode: "shadow"`). They record what they *would* have decided, and the audit report counts the calls that would have been blocked.
