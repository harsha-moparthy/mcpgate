from __future__ import annotations

import pytest

from mcpgate.gateway import GatewayError, Invocation
from mcpgate.runtime import Runtime


@pytest.mark.asyncio
async def test_audit_reconstructs_allow_and_deny_and_redacts_body(
    runtime: Runtime,
) -> None:
    pair = runtime.provider.issue_for_client("operator-agent", "operator-local-secret")
    session = "reconstruction-demo"
    await runtime.gateway.invoke(
        Invocation("list_tickets", {"status": "open"}, pair.access_token, session)
    )
    await runtime.gateway.invoke(
        Invocation(
            "create_ticket",
            {"team": "alpha", "title": "Audit me", "body": "sensitive customer text"},
            pair.access_token,
            session,
        )
    )
    with pytest.raises(GatewayError):
        await runtime.gateway.invoke(
            Invocation("get_ticket", {"ticket_id": 3}, pair.access_token, session)
        )
    reconstructed = runtime.audit.reconstruct(session)
    assert [event["decision"] for event in reconstructed] == ["allow", "allow", "deny"]
    assert reconstructed[1]["args"]["body"] == "[REDACTED]"
    assert runtime.audit.verify_chain()


@pytest.mark.asyncio
async def test_audit_chain_detects_tampering(runtime: Runtime) -> None:
    pair = runtime.provider.issue_for_client("readonly-agent", "readonly-local-secret")
    await runtime.gateway.invoke(
        Invocation("list_tickets", {"status": None}, pair.access_token, "tamper")
    )
    assert runtime.audit.verify_chain()
    runtime.store.connection.execute("UPDATE audit_events SET decision='deny' WHERE sequence=1")
    runtime.store.connection.commit()
    assert not runtime.audit.verify_chain()
