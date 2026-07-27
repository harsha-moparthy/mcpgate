"""End-to-end OAuth 2.1 authorization-code + PKCE flow over real HTTP.

Nothing here bypasses the server: the code, token, and MCP call all go through
the official SDK's endpoints, exactly as an agent client would.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import tempfile
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from starlette.testclient import TestClient

from mcpgate.config import Settings
from mcpgate.runtime import create_runtime
from mcpgate.server import create_server

CLIENT_ID = "operator-agent"
CLIENT_SECRET = "operator-local-secret"
REDIRECT_URI = "http://127.0.0.1/callback"
HOST = "127.0.0.1:8000"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    return verifier, challenge


def main() -> int:
    logging.disable(logging.INFO)
    with tempfile.TemporaryDirectory() as directory:
        runtime = create_runtime(
            replace(Settings(), database_path=Path(directory) / "oauth.sqlite3")
        )
        server = create_server(runtime)
        app = server.streamable_http_app()
        verifier, challenge = pkce()
        ok = True

        with TestClient(app) as client:
            print("=== 1. discovery: protected-resource and authorization-server metadata ===")
            resource = client.get(
                "/.well-known/oauth-protected-resource/mcp", headers={"Host": HOST}
            )
            metadata = client.get("/.well-known/oauth-authorization-server", headers={"Host": HOST})
            print(f"  resource metadata  {resource.status_code}")
            print(
                f"  auth server        {metadata.status_code} "
                f"endpoints={sorted(k for k in metadata.json() if k.endswith('_endpoint'))}"
            )
            ok &= resource.status_code == 200 and metadata.status_code == 200

            print()
            print("=== 2. unauthenticated MCP call is refused ===")
            anonymous = client.post(
                "/mcp",
                headers={
                    "Host": HOST,
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            print(
                f"  status={anonymous.status_code} "
                f"www-authenticate={anonymous.headers.get('www-authenticate', '-')[:60]}"
            )
            ok &= anonymous.status_code == 401

            print()
            print("=== 3. /authorize with PKCE S256 ===")
            authorize = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "scope": "tickets:read tickets:write",
                    "state": "demo-state",
                    "resource": runtime.settings.resource_url,
                },
                headers={"Host": HOST},
                follow_redirects=False,
            )
            location = authorize.headers.get("location", "")
            code = parse_qs(urlparse(location).query).get("code", [""])[0]
            print(f"  status={authorize.status_code} code={code[:12]}...")
            ok &= authorize.status_code in (302, 307) and bool(code)

            print()
            print("=== 4. /token exchange (code + verifier + client secret) ===")
            token_response = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code_verifier": verifier,
                    "resource": runtime.settings.resource_url,
                },
                headers={"Host": HOST},
            )
            payload = token_response.json()
            access_token = payload.get("access_token", "")
            print(
                f"  status={token_response.status_code} scope={payload.get('scope')!r} "
                f"expires_in={payload.get('expires_in')}"
            )
            ok &= token_response.status_code == 200 and bool(access_token)

            print()
            print("=== 5. replaying the same authorization code fails ===")
            replay = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code_verifier": verifier,
                    "resource": runtime.settings.resource_url,
                },
                headers={"Host": HOST},
            )
            print(f"  status={replay.status_code} error={replay.json().get('error')}")
            ok &= replay.status_code == 400

            print()
            print("=== 6. wrong PKCE verifier is rejected ===")
            other_verifier, other_challenge = pkce()
            second = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "code_challenge": other_challenge,
                    "code_challenge_method": "S256",
                    "scope": "tickets:read",
                    "state": "s2",
                    "resource": runtime.settings.resource_url,
                },
                headers={"Host": HOST},
                follow_redirects=False,
            )
            second_code = parse_qs(urlparse(second.headers["location"]).query)["code"][0]
            mismatched = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": second_code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code_verifier": other_verifier + "tampered",
                    "resource": runtime.settings.resource_url,
                },
                headers={"Host": HOST},
            )
            print(f"  status={mismatched.status_code} error={mismatched.json().get('error')}")
            ok &= mismatched.status_code == 400

            print()
            print("=== 7. authenticated MCP tools/call, row-filtered ===")
            headers = {
                "Host": HOST,
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            }
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
                        "clientInfo": {"name": "oauth-demo", "version": "1"},
                    },
                },
            )
            call = client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "list_tickets", "arguments": {}},
                },
            )
            tickets = call.json()["result"]["structuredContent"]["result"]
            teams = sorted({ticket["team"] for ticket in tickets})
            print(f"  status={call.status_code} visible_teams={teams} rows={len(tickets)}")
            ok &= teams == ["alpha", "beta"]

            print()
            print("=== 8. the audit trail covers the authenticated call ===")
            recorded = runtime.store.audit_events(limit=10)
            print(
                f"  events={len(recorded)} last="
                + json.dumps({k: recorded[0][k] for k in ("tool", "decision", "reason")})
            )
            ok &= runtime.audit.verify_chain() and len(recorded) >= 1

        runtime.store.close()
        print()
        print("=== OAUTH FLOW DEMO PASSED ===" if ok else "=== OAUTH FLOW DEMO FAILED ===")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
