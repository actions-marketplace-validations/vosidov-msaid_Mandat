# Run the control plane

The control plane runs as one process, `mandat serve`. It provides:
- **token exchange:** issues agents their task tokens;
- **agents:** the registry of agents and their secrets;
- **approvals:** human-in-the-loop decisions;
- **revocation:** the kill switch;
- **policy distribution** to every guard;
- **the audit ledger;**
- **a web console.**

## Setup

```bash
mandat init          # mandat.config.json, starter policy + tests, signing key, API keys in .mandat/credentials.json
mandat policy test   # run the starter policy's decision tests
mandat serve         # http://127.0.0.1:7400, console at /console
```

`mandat init` creates four API keys:
- **admin:** full control;
- **approver:** identity `alice`;
- **auditor:** read-only access to the ledger and reports;
- **service:** for guards.

Keep `.mandat/` private; it is git-ignored. Before real use, connect an identity provider and switch off the test login; see [Identity](identity.md).

## Agents

```bash
mandat agents add support-bot --tools "lookup_*,refund" --resources https://mcp.example.com/mcp --versions 1.4.0
mandat agents list
mandat agents rotate-secret support-bot --revoke-tokens   # new secret; the old one and its tokens stop working
mandat agents remove support-bot                          # delete the agent and revoke its tokens
```

An agent can only ever be delegated the tools it is registered for. Each task token can narrow that further (tools, argument limits), and a sub-agent's token can only narrow its parent's.

## Approvals

A call that needs approval appears:
- in the console (**Approvals** tab);
- in `mandat approvals list`;
- in every configured channel.

Each approval is bound to the exact call (user, agent, tool, server, arguments), can be used once, and expires (deny) after its timeout. `approvers: 2` in a rule means four-eyes. Nobody can approve an action their own agent took for them.

```bash
mandat approvals list
mandat approvals approve apr_… [--login]
mandat approvals deny apr_…
```

Channels are configured in `mandat.config.json`:

```jsonc
"approvals": {
  "defaultTimeout": "10m",
  "slack": { "webhookUrl": "${env:SLACK_WEBHOOK_URL}", "signingSecret": "${env:SLACK_SIGNING_SECRET}" },
  "webhooks": [{ "name": "pager", "url": "https://hooks.example.com/mandat", "secret": "${env:MANDAT_WEBHOOK_SECRET}" }]
}
```

- **Slack:** messages arrive through an app's incoming webhook. To approve straight from Slack with buttons, enable *Interactivity* on that Slack app and set its request URL to `https://<control-plane>/slack/interactions`. The signing secret verifies those requests.
- **Webhooks:** each receives a signed JSON `POST`. The header is `X-Mandat-Signature: sha256=HMAC(secret, timestamp + "." + body)`, and `X-Mandat-Timestamp` carries the timestamp.
- **Rules can target channels:** `approval.channels`, for example `["slack"]`.

## Revocation (kill switch)

```bash
mandat revoke --agent support-bot --reason "incident 42"   # every token of the agent, including sub-agents it delegated to
mandat revoke --agent support-bot --version 1.4.0          # one agent version
mandat revoke --user user:maria | --task <id> | --tenant <id> | --jti <token id>
```

Guards poll revocations every 2 seconds, so a revoked agent is locked out within seconds. Revoking an agent, user or tenant also blocks new tokens until you lift it (console → **Revocations**).

## Audit ledger

Every tool call, approval, token issuance, revocation, policy change and rejected login becomes one record in a hash-chained ledger, `.mandat/ledger.jsonl`. Editing, deleting or reordering any past record breaks the chain.

```bash
mandat ledger verify                       # recompute the hash chain
mandat ledger tail -n 20
mandat ledger report --retention 365       # oversight report for auditors / DPOs (Markdown or --format json)
mandat ledger export --format ocsf         # OCSF API Activity events (or --format otel)
```

Arguments are redacted before they are stored:
- secrets by key name (`password`, `token`, …);
- e-mail addresses, phone numbers, card numbers (Luhn-checked) and IBANs, by pattern;
- fields a policy marks with `redact`.

**Send records to your observability stack** as OpenTelemetry spans (GenAI conventions, `execute_tool`):

```jsonc
"ledger": { "retentionDays": 365, "otlp": { "endpoint": "http://otel-collector:4318", "headers": { "authorization": "Bearer …" } } }
```

**Rejected logins** are recorded as `auth.rejected` (guard), `token.denied` (token exchange) and `api.auth_rejected` (control plane API). There is at most one record per reason every 10 seconds, with a count of the rest. Filter them in the console (**Activity → rejected logins**) or with `GET /api/ledger?type=@rejected`.

## Console

`http://127.0.0.1:7400/console` shows activity, approvals, agents, revocations, the policy editor, and the audit tools (chain verification, exports, report). Sign in with your identity provider ([Identity](identity.md)), or paste an API key.
