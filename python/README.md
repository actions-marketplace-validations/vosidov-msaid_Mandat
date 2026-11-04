# mandat (Python)

**Authorization, delegation and audit for AI agent actions: the Python guard for [Mandat](https://github.com/vosidov-msaid/Mandat).**

Protect an MCP server written with the official Python SDK (`mcp` ≥ 2.0). Every tool call is then:

- **authorised** by a policy on the call's arguments, delegation chain and session taint (`refund ≤ €50 → auto · €50–500 → ask a human · > €500 → deny`);
- **attributed** to the human, the agent and any sub-agents, from a short-lived, single-task Mandat token;
- **audited** in Mandat's hash-chained ledger.

It uses the same policy language, the same decisions and the same control plane as the TypeScript SDK. A shared conformance suite (`spec/conformance/policy.json`) checks that both SDKs decide every case identically.

```bash
pip install "mandat[mcp]"
```

Requires Python ≥ 3.10. The core depends only on `cryptography`; the `mcp` extra adds the MCP SDK integration. The control plane (STS, approvals, revocation, ledger, console) is the `mandat` npm package: `npm i -g mandat && mandat init && mandat serve`.

## Protect an MCPServer

```python
from mcp.server.mcpserver import MCPServer
from mandat import create_guard
from mandat.mcp import auth_settings, protect, token_verifier

guard = await create_guard(
    resource="https://mcp.example.com/mcp",   # token audience: this server
    control_plane="http://127.0.0.1:7400",    # `mandat serve`
    api_key=SERVICE_KEY,                      # API key with the "service" role (.mandat/credentials.json)
)
server = MCPServer("billing", token_verifier=token_verifier(guard), auth=auth_settings(guard))
protect(server, guard)                        # register tools after this line

@server.tool()
async def refund(order_id: str, amount: float, currency: str) -> str:
    """Refund (part of) an order."""
    ...

app = server.streamable_http_app()            # serve with uvicorn
```

- **`token_verifier(guard)`** makes the SDK's bearer middleware accept only valid, unrevoked Mandat task tokens for this server. Anything else gets `401` with a `resource_metadata` challenge. `auth_settings(guard)` publishes the RFC 9728 metadata.
- **`protect(server, guard)`** wraps each tool registered afterwards with policy, approvals, session taint, tool pinning and a ledger record. It keeps the function signature, so the SDK derives the same input schema. Sync tools still run on a worker thread.
- **Denied calls** return `isError: true` with Mandat's decision in `_meta["mandat/decision"]`, the same shape as the TypeScript SDK. Calls that need approval wait up to `approval_wait` seconds for a human, then ask the agent to retry.

A complete server is in [`examples/server.py`](examples/server.py).

## Without MCP

```python
auth = await guard.verify(bearer_token)                  # raises AuthError (-> HTTP 401)
result = await guard.execute(auth, "refund", args, lambda: do_refund(**args))   # raises GuardDenied
```

`compile_policy(doc).evaluate(input)` gives you the decision engine on its own, with no I/O.

## Behaviour

- **Fail-safe:** the guard checks its API key at startup and refuses to run with a rejected key. If the control plane is unreachable, it starts from the last policy snapshot, and `financial` / `destructive` tools fail closed after 15 s without revocation updates.
- **Revocations** are polled every 2 s, so a revoked agent is locked out within seconds.
- **Ledger records** are shipped in the background, batched and delivered at least once, so the request path never waits for them.
- **Rejected tokens** are recorded (`auth.rejected`), at most one record per reason every 10 s.

## Development

```bash
cd python
uv venv && uv pip install -r requirements-dev.txt -e .
python -m unittest discover -s tests -v    # end-to-end tests need Node >= 23.6 (they run the real control plane)
```

If a system proxy is configured (common on Windows), set `NO_PROXY=127.0.0.1,localhost`. The `httpx` client used by the MCP SDK otherwise sends local requests through the proxy.

License: Apache-2.0.
