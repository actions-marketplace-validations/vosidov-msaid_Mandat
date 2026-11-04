"""Acme Support MCP server written with the official Python SDK (`mcp` 2.x), protected by Mandat.

Start `mandat serve` first, then from the same folder (it reads .mandat/credentials.json):

    pip install "mandat[mcp]"
    python examples/server.py

Env: MANDAT_URL, MANDAT_SERVICE_KEY, MCP_PORT (default 7403). The Mandat-specific lines are marked "← Mandat".
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import uvicorn
from mcp.server.mcpserver import MCPServer

from mandat import create_guard
from mandat.mcp import auth_settings, protect, token_verifier

ORDERS = {"A-1001": 45, "A-1002": 180, "A-1003": 1290}


async def main() -> None:
    creds_file = Path(".mandat/credentials.json")
    creds = json.loads(creds_file.read_text()) if creds_file.exists() else {}
    port = int(os.environ.get("MCP_PORT", "7403"))
    resource = f"http://127.0.0.1:{port}/mcp"

    guard = await create_guard(  # ← Mandat
        resource=resource,
        control_plane=os.environ.get("MANDAT_URL", creds.get("url", "http://127.0.0.1:7400")),
        api_key=os.environ.get("MANDAT_SERVICE_KEY", creds.get("keys", {}).get("service", "")),
        source="acme-support-python",
        approval_wait=15,
    )
    server = MCPServer("acme-support-python", token_verifier=token_verifier(guard), auth=auth_settings(guard))  # ← Mandat
    protect(server, guard)  # ← Mandat: policy, approvals and audit on every tool below

    @server.tool()
    async def lookup_order(order_id: str) -> str:
        """Look up an order by id."""
        return json.dumps({"order_id": order_id, "total": ORDERS.get(order_id)})

    @server.tool()
    async def refund(order_id: str, amount: float, currency: str) -> str:
        """Refund (part of) an order to the original payment method."""
        return f"Refunded {amount:g} {currency} on {order_id}."

    @server.tool()
    async def send_email(to: list[str], subject: str, body: str) -> str:
        """Send an e-mail from the support mailbox."""
        return f"Sent '{subject}' to {', '.join(to)}."

    print(f"Acme Support (Python, protected by Mandat) at {resource}")
    await uvicorn.Server(uvicorn.Config(server.streamable_http_app(), host="127.0.0.1", port=port, log_level="warning")).serve()


if __name__ == "__main__":
    asyncio.run(main())
