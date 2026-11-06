"""Mandat for the official Python MCP SDK (`mcp` >= 2.0, MCPServer).

    from mcp.server.mcpserver import MCPServer
    from mandat import create_guard
    from mandat.mcp import auth_settings, protect, token_verifier

    guard = await create_guard(resource="http://127.0.0.1:7403/mcp", control_plane=..., api_key=...)
    server = MCPServer("billing", token_verifier=token_verifier(guard), auth=auth_settings(guard))
    protect(server, guard)                 # before registering tools

    @server.tool()
    async def refund(order_id: str, amount: float, currency: str) -> str: ...

`token_verifier` makes the SDK's bearer middleware reject anything that isn't a valid, unrevoked Mandat task
token for this server (401 + resource_metadata challenge). `protect` runs policy, approvals and audit on
every call of every tool registered afterwards.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import Context, MCPServer
from mcp_types import CallToolResult, TextContent

from .guard import AuthError, Guard, GuardDenied

__all__ = ["protect", "token_verifier", "auth_settings", "denied_result"]


class MandatTokenVerifier:
    """`mcp.server.auth.provider.TokenVerifier` backed by a Mandat Guard."""

    def __init__(self, guard: Guard) -> None:
        self.guard = guard

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            auth = await self.guard.verify(token)
        except AuthError:
            return None
        c = auth.claims
        return AccessToken(
            token=token,
            client_id=auth.agent["id"],
            scopes=[],
            expires_at=c.get("exp"),
            resource=self.guard.resource,
            subject=auth.principal["sub"],
            claims=c,
        )


def token_verifier(guard: Guard) -> MandatTokenVerifier:
    return MandatTokenVerifier(guard)


def auth_settings(guard: Guard) -> AuthSettings:
    """AuthSettings pointing MCP clients at the Mandat control plane (RFC 9728 discovery)."""
    return AuthSettings(issuer_url=guard.issuer, resource_server_url=guard.resource, validate_token_resource=True)


def denied_result(e: GuardDenied) -> CallToolResult:
    """Tool result shown to the model when Mandat blocks a call (same shape as the TypeScript SDK)."""
    text = (f"Mandat: this action needs human approval. {e}" if e.code == "approval_pending" else f"Mandat blocked this action: {e}")
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        is_error=True,
        meta={"mandat/decision": {
            "code": e.code,
            "effect": e.decision.effect if e.decision else "deny",
            "rules": e.decision.matched if e.decision else [],
            "approval_id": e.approval_id,
        }},
    )


def protect(server: MCPServer, guard: Guard) -> MCPServer:
    """Wraps every tool registered on `server` from now on with Mandat. Returns the same server."""
    original_add_tool = server.add_tool
    pinned = False

    async def pin_once() -> None:
        nonlocal pinned
        if pinned:
            return
        pinned = True
        tools = await server.list_tools()
        guard.register_tools([t.model_dump(by_alias=True, exclude_none=True) for t in tools])

    def add_tool(fn: Callable[..., Any], name: str | None = None, *args: Any, **kwargs: Any) -> Any:
        tool_name = name or fn.__name__
        is_async = inspect.iscoroutinefunction(fn)

        @functools.wraps(fn)  # keeps the signature, so the SDK still derives the same input schema
        async def guarded(**call_kwargs: Any) -> Any:
            token = get_access_token()
            if token is None:
                return denied_result(GuardDenied("denied", "unauthenticated call", None))
            try:
                auth = await guard.verify(token.token)
            except AuthError as e:
                return denied_result(GuardDenied("denied", str(e), None))
            await pin_once()
            tool_args = {k: v for k, v in call_kwargs.items() if not isinstance(v, Context)}

            async def run() -> Any:
                if is_async:
                    return await fn(**call_kwargs)
                import anyio  # the SDK runs sync tools on a worker thread; keep that behaviour
                return await anyio.to_thread.run_sync(functools.partial(fn, **call_kwargs))

            try:
                return await guard.execute(auth, tool_name, tool_args, run)
            except GuardDenied as e:
                return denied_result(e)

        return original_add_tool(guarded, name, *args, **kwargs)

    server.add_tool = add_tool  # type: ignore[method-assign]
    return server
