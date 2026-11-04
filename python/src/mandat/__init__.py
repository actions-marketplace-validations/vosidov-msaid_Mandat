"""Mandat: authorization, delegation and audit for AI agent actions (Python guard).

Same policy language, decisions and control plane as the TypeScript SDK. The MCP integration lives in
`mandat.mcp` (requires `pip install mandat[mcp]`).
"""

from .expr import ExprError, compile_expr
from .guard import AuthError, Guard, GuardDenied, VerifiedAuth, create_guard, tool_hash
from .policy import CompiledPolicy, Decision, PolicyError, compile_policy
from .redact import redact
from .remote import ControlPlane, FilePolicy, HttpLedger, MemoryLedger, RemoteApprovals, RemotePolicy, RemoteRevocations, StaticPolicy

__version__ = "0.1.0"

__all__ = [
    "AuthError", "CompiledPolicy", "ControlPlane", "Decision", "ExprError", "FilePolicy", "Guard", "GuardDenied", "HttpLedger",
    "MemoryLedger", "PolicyError", "RemoteApprovals", "RemotePolicy", "RemoteRevocations", "StaticPolicy", "VerifiedAuth",
    "compile_expr", "compile_policy", "create_guard", "redact", "tool_hash",
]
