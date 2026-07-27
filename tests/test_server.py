from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from mcpgate.runtime import Runtime
from mcpgate.server import create_server


@pytest.mark.asyncio
async def test_official_mcp_server_exposes_governed_tools(runtime: Runtime) -> None:
    server = create_server(runtime)
    tools = await server.list_tools()
    assert {tool.name for tool in tools} == {
        "list_tickets",
        "get_ticket",
        "create_ticket",
        "update_ticket_status",
        "audit_recent",
    }
    app = server.streamable_http_app()
    paths = {route.path for route in app.routes}
    assert "/mcp" in paths
    assert "/authorize" in paths
    assert "/token" in paths
    assert "/.well-known/oauth-protected-resource/mcp" in paths


def test_streamable_http_mcp_call_is_oauth_protected_and_row_filtered(
    runtime: Runtime,
) -> None:
    server = create_server(runtime)
    pair = runtime.provider.issue_for_client("readonly-agent", "readonly-local-secret")
    app = server.streamable_http_app()
    headers = {
        "Authorization": f"Bearer {pair.access_token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Host": "127.0.0.1:8000",
    }
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "integration-test", "version": "1"},
        },
    }
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "list_tickets", "arguments": {}},
    }
    with TestClient(app) as client:
        assert (
            client.post(
                "/mcp",
                headers={k: v for k, v in headers.items() if k != "Authorization"},
                json=initialize,
            ).status_code
            == 401
        )
        initialized = client.post("/mcp", headers=headers, json=initialize)
        assert initialized.status_code == 200
        response = client.post("/mcp", headers=headers, json=call)
        assert response.status_code == 200
        payload = response.json()
        assert payload["result"]["isError"] is False
        tickets = payload["result"]["structuredContent"]["result"]
        assert tickets, "readonly agent should see its own team's tickets"
        assert {ticket["team"] for ticket in tickets} == {"alpha"}
