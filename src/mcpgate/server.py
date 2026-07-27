from __future__ import annotations

from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from .gateway import GatewayError, Invocation
from .runtime import Runtime, create_runtime


class AuditedToolError(ToolError):
    """A refusal the guard pipeline has already written to the audit trail."""


def create_server(runtime: Runtime | None = None) -> FastMCP:
    runtime = runtime or create_runtime()
    settings = runtime.settings
    server = FastMCP(
        "MCPGate",
        instructions=(
            "A governed ticketing server. Every call is authenticated, scoped, "
            "rate-limited, row-filtered, and written to a tamper-evident audit trail."
        ),
        host=settings.host,
        port=settings.port,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        auth_server_provider=runtime.provider,
        auth=AuthSettings(
            issuer_url=settings.issuer_url,
            resource_server_url=settings.resource_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=False,
                valid_scopes=sorted(
                    {scope for c in runtime.policy.clients.values() for scope in c.scopes}
                ),
            ),
            revocation_options=RevocationOptions(enabled=True),
        ),
    )

    async def invoke(tool: str, args: dict[str, Any], ctx: Context) -> Any:
        access = get_access_token()
        if access is None:
            raise AuditedToolError("invalid_token")
        try:
            return await runtime.gateway.invoke(
                Invocation(
                    tool=tool,
                    args=args,
                    token=access.token,
                    session_id=f"mcp-{ctx.request_id}",
                )
            )
        except GatewayError as exc:
            suffix = f" retry_after={exc.retry_after:.3f}" if exc.retry_after else ""
            raise AuditedToolError(f"{exc.code}{suffix}") from exc

    @server.tool()
    async def list_tickets(ctx: Context, status: str | None = None) -> list[dict[str, Any]]:
        """List only tickets visible to the caller's authorized teams."""
        return await invoke("list_tickets", {"status": status}, ctx)

    @server.tool()
    async def get_ticket(ticket_id: int, ctx: Context) -> dict[str, Any]:
        """Get one ticket if its team is in the caller's row scope."""
        return await invoke("get_ticket", {"ticket_id": ticket_id}, ctx)

    @server.tool()
    async def create_ticket(team: str, title: str, body: str, ctx: Context) -> dict[str, Any]:
        """Create a ticket in an authorized team; requires tickets:write."""
        return await invoke("create_ticket", {"team": team, "title": title, "body": body}, ctx)

    @server.tool()
    async def update_ticket_status(ticket_id: int, status: str, ctx: Context) -> dict[str, Any]:
        """Change status on a visible ticket; requires tickets:write."""
        return await invoke("update_ticket_status", {"ticket_id": ticket_id, "status": status}, ctx)

    @server.tool()
    async def audit_recent(ctx: Context, limit: int = 20) -> list[dict[str, Any]]:
        """Read recent structured audit events; requires audit:read."""
        return await invoke("audit_recent", {"limit": limit}, ctx)

    # The SDK validates the tool name and argument schema *before* the guard
    # pipeline runs, so a malformed or unknown-tool call would otherwise be
    # refused with no audit record. Re-register the handler to capture those
    # rejections too, which is what makes "every call is audited" true.
    inner_call_tool = server.call_tool

    async def audited_call_tool(name: str, arguments: dict[str, Any]) -> Any:
        try:
            return await inner_call_tool(name, arguments)
        except Exception as raised:
            # The SDK re-wraps tool exceptions, so the marker may be a cause
            # rather than the raised type. Walk the chain to avoid
            # double-recording a refusal the guard already logged.
            if _already_audited(raised):
                raise
            access = get_access_token()
            runtime.audit.record(
                session_id=f"mcp-{_current_request_id(server)}",
                client_id=access.client_id if access else None,
                tool=name,
                action=(
                    runtime.policy.tools[name].action if name in runtime.policy.tools else "unknown"
                ),
                decision="deny",
                reason="rejected_before_dispatch",
                args=arguments if isinstance(arguments, dict) else {},
                latency_ms=0.0,
            )
            raise

    server._mcp_server.call_tool(validate_input=False)(audited_call_tool)

    # Keep the runtime reachable for in-process validation and operators.
    server._mcpgate_runtime = runtime  # type: ignore[attr-defined]
    return server


def _already_audited(error: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        if isinstance(current, AuditedToolError):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def _current_request_id(server: FastMCP) -> str:
    try:
        return str(server.get_context().request_id)
    except Exception:  # pragma: no cover - outside a request
        return "unknown"
