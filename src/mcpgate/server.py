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
            raise ToolError("invalid_token")
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
            raise ToolError(f"{exc.code}{suffix}") from exc

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

    # Keep the runtime reachable for in-process validation and operators.
    server._mcpgate_runtime = runtime  # type: ignore[attr-defined]
    return server
