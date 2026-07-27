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


def test_every_transport_level_call_is_audited_exactly_once(runtime: Runtime) -> None:
    """Regression: the SDK's schema layer used to deny before the guard ran.

    A malformed or unknown-tool call was refused with no audit record at all,
    which made the audit-completeness claim false. Each case below must produce
    exactly one event — no gaps, and no double-recording of guard denials.
    """
    server = create_server(runtime)
    pair = runtime.provider.issue_for_client("operator-agent", "operator-local-secret")
    headers = {
        "Host": "127.0.0.1:8000",
        "Authorization": f"Bearer {pair.access_token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    cases = [
        ("get_ticket", {"ticket_id": "0x1"}, True),  # schema rejection
        ("nonexistent_tool", {}, True),  # unknown tool
        ("get_ticket", {"ticket_id": 3}, True),  # guard denial (row scope)
        ("get_ticket", {"ticket_id": 1}, False),  # allowed
    ]
    with TestClient(server.streamable_http_app(), raise_server_exceptions=False) as client:
        client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "audit-coverage", "version": "1"},
                },
            },
        )
        for tool, arguments, expect_error in cases:
            before = len(runtime.store.audit_events(limit=10_000))
            response = client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments},
                },
            )
            after = len(runtime.store.audit_events(limit=10_000))
            assert response.json()["result"]["isError"] is expect_error, tool
            assert after - before == 1, f"{tool} wrote {after - before} audit rows"
    assert runtime.audit.verify_chain()
