from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.provider import AccessToken

from .audit import AuditLog
from .auth import OAuthProvider
from .policy import Policy
from .rate_limit import TokenBucketLimiter
from .store import Store


class GatewayError(Exception):
    def __init__(self, code: str, message: str | None = None, retry_after: float | None = None):
        self.code = code
        self.retry_after = retry_after
        super().__init__(message or code)


@dataclass(frozen=True)
class Invocation:
    tool: str
    args: dict[str, Any]
    token: str
    session_id: str | None = None


class Gateway:
    def __init__(
        self,
        store: Store,
        policy: Policy,
        provider: OAuthProvider,
        limiter: TokenBucketLimiter,
        audit: AuditLog,
    ):
        self.store = store
        self.policy = policy
        self.provider = provider
        self.limiter = limiter
        self.audit = audit

    async def invoke(self, invocation: Invocation) -> Any:
        started = time.perf_counter()
        access = await self.provider.load_access_token(invocation.token)
        client_id = access.client_id if access else None
        session_id = invocation.session_id or self._session_id(access)
        action = self.policy.tools.get(invocation.tool)
        action_name = action.action if action else "unknown"
        try:
            if access is None:
                raise GatewayError("invalid_token")
            allowed, retry_after = self.limiter.allow(access.client_id)
            if not allowed:
                raise GatewayError("rate_limited", retry_after=retry_after)
            try:
                self.policy.require_tool(invocation.tool, set(access.scopes))
            except PermissionError as exc:
                raise GatewayError("forbidden", str(exc)) from exc
            self._validate_inputs(invocation.tool, invocation.args)
            result = self._dispatch(invocation.tool, invocation.args, access)
        except GatewayError as exc:
            self.audit.record(
                session_id=session_id,
                client_id=client_id,
                tool=invocation.tool,
                action=action_name,
                decision="deny",
                reason=exc.code,
                args=invocation.args,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
            raise
        self.audit.record(
            session_id=session_id,
            client_id=client_id,
            tool=invocation.tool,
            action=action_name,
            decision="allow",
            reason="policy_satisfied",
            args=invocation.args,
            latency_ms=(time.perf_counter() - started) * 1000,
        )
        return result

    def direct(self, tool: str, args: dict[str, Any], teams: set[str], client_id: str) -> Any:
        """Direct-system baseline used only by the overhead benchmark."""
        access = AccessToken(
            token="benchmark",
            client_id=client_id,
            scopes=["tickets:read", "tickets:write", "audit:read"],
            claims={"teams": sorted(teams)},
        )
        return self._dispatch(tool, args, access)

    @staticmethod
    def _session_id(access: AccessToken | None) -> str:
        if access and access.claims:
            return str(access.claims.get("jti", uuid.uuid4().hex))
        return f"unauth-{uuid.uuid4().hex}"

    @staticmethod
    def _validate_inputs(tool: str, args: dict[str, Any]) -> None:
        expected = {
            "list_tickets": {"status"},
            "get_ticket": {"ticket_id"},
            "create_ticket": {"team", "title", "body"},
            "update_ticket_status": {"ticket_id", "status"},
            "audit_recent": {"limit"},
        }
        if tool not in expected:
            raise GatewayError("unknown_tool")
        if set(args) - expected[tool]:
            raise GatewayError("unexpected_argument")
        for value in args.values():
            if isinstance(value, str):
                if len(value) > 4_000:
                    raise GatewayError("input_too_long")
                if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", value):
                    raise GatewayError("control_character")
        if tool == "create_ticket" and (
            not str(args.get("title", "")).strip() or not str(args.get("body", "")).strip()
        ):
            raise GatewayError("invalid_input")
        if tool == "update_ticket_status" and args.get("status") not in {
            "open",
            "in_progress",
            "resolved",
            "closed",
            "planned",
        }:
            raise GatewayError("invalid_status")

    def _dispatch(self, tool: str, args: dict[str, Any], access: AccessToken) -> Any:
        claims = access.claims or {}
        teams = set(claims.get("teams", []))
        if tool == "list_tickets":
            return self.store.list_tickets(teams, args.get("status"))
        if tool == "get_ticket":
            ticket = self._visible_ticket(int(args["ticket_id"]), teams)
            return ticket
        if tool == "create_ticket":
            team = str(args["team"])
            if team not in teams:
                raise GatewayError("row_scope_violation")
            return self.store.create_ticket(
                team, str(args["title"]), str(args["body"]), access.client_id
            )
        if tool == "update_ticket_status":
            ticket_id = int(args["ticket_id"])
            self._visible_ticket(ticket_id, teams)
            return self.store.update_status(ticket_id, str(args["status"]))
        if tool == "audit_recent":
            limit = min(max(int(args.get("limit", 20)), 1), 100)
            return self.store.audit_events(limit=limit)
        raise GatewayError("unknown_tool")

    def _visible_ticket(self, ticket_id: int, teams: set[str]) -> dict[str, Any]:
        ticket = self.store.get_ticket(ticket_id)
        if ticket is None:
            raise GatewayError("not_found")
        if ticket["team"] not in teams:
            # Do not reveal whether an out-of-scope row exists.
            raise GatewayError("not_found")
        return ticket
