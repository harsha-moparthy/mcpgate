from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from mcp.server.auth.provider import AuthorizationParams, TokenError
from pydantic import AnyUrl

from mcpgate.runtime import Runtime


@pytest.mark.asyncio
async def test_issued_access_token_round_trip(runtime: Runtime) -> None:
    pair = runtime.provider.issue_for_client(
        "readonly-agent", "readonly-local-secret", ["tickets:read"]
    )
    access = await runtime.provider.load_access_token(pair.access_token)
    assert access is not None
    assert access.client_id == "readonly-agent"
    assert access.scopes == ["tickets:read"]
    assert access.claims["teams"] == ["alpha"]


@pytest.mark.asyncio
async def test_revoked_access_token_is_rejected(runtime: Runtime) -> None:
    pair = runtime.provider.issue_for_client("readonly-agent", "readonly-local-secret")
    access = await runtime.provider.load_access_token(pair.access_token)
    assert access is not None
    await runtime.provider.revoke_token(access)
    assert await runtime.provider.load_access_token(pair.access_token) is None


def test_bootstrap_rejects_bad_secret_and_scope_escalation(runtime: Runtime) -> None:
    with pytest.raises(PermissionError, match="invalid_client"):
        runtime.provider.issue_for_client("readonly-agent", "wrong")
    with pytest.raises(PermissionError, match="scope_escalation"):
        runtime.provider.issue_for_client(
            "readonly-agent", "readonly-local-secret", ["tickets:write"]
        )


@pytest.mark.asyncio
async def test_authorization_code_is_single_use(runtime: Runtime) -> None:
    client = await runtime.provider.get_client("operator-agent")
    assert client is not None
    redirect = await runtime.provider.authorize(
        client,
        AuthorizationParams(
            state="state-123",
            scopes=["tickets:read"],
            code_challenge="challenge-from-pkce-s256",
            redirect_uri=AnyUrl("http://127.0.0.1/callback"),
            redirect_uri_provided_explicitly=True,
            resource=runtime.settings.resource_url,
        ),
    )
    query = parse_qs(urlparse(redirect).query)
    code_string = query["code"][0]
    code = await runtime.provider.load_authorization_code(client, code_string)
    assert code is not None
    first = await runtime.provider.exchange_authorization_code(client, code)
    assert await runtime.provider.load_access_token(first.access_token) is not None
    with pytest.raises(TokenError, match="replayed"):
        await runtime.provider.exchange_authorization_code(client, code)


@pytest.mark.asyncio
async def test_refresh_token_rotates_and_cannot_increase_scope(
    runtime: Runtime,
) -> None:
    client = await runtime.provider.get_client("operator-agent")
    assert client is not None
    pair = runtime.provider.issue_for_client(
        "operator-agent", "operator-local-secret", ["tickets:read"]
    )
    refresh = await runtime.provider.load_refresh_token(client, pair.refresh_token)
    assert refresh is not None
    with pytest.raises(TokenError, match="increase"):
        await runtime.provider.exchange_refresh_token(
            client, refresh, ["tickets:read", "tickets:write"]
        )
    # A rejected exchange consumes the old token: fail closed under replay.
    assert await runtime.provider.load_refresh_token(client, pair.refresh_token) is None
