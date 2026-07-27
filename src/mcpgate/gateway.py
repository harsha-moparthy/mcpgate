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
            clean = self._validate_inputs(invocation.tool, invocation.args)
            result = self._dispatch(invocation.tool, clean, access)
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
        except Exception as exc:
            # An unexpected fault must still be evidence, and must not leak
            # internals to the caller. Fail closed, audited.
            self.audit.record(
                session_id=session_id,
                client_id=client_id,
                tool=invocation.tool,
                action=action_name,
                decision="deny",
                reason="internal_error",
                args=invocation.args,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
            raise GatewayError("internal_error") from exc
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

    # Declared argument types. Validation is positive (an allowlist of shapes),
    # never a str() coercion, so a dict or list can never reach the store.
    ARGUMENT_TYPES: dict[str, dict[str, str]] = {
        "list_tickets": {"status": "optional_text"},
        "get_ticket": {"ticket_id": "integer"},
        "create_ticket": {"team": "text", "title": "text", "body": "text"},
        "update_ticket_status": {"ticket_id": "integer", "status": "text"},
        "audit_recent": {"limit": "optional_integer"},
    }
    VALID_STATUSES = frozenset({"open", "in_progress", "resolved", "closed", "planned"})
    CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

    @classmethod
    def _coerce_integer(cls, value: Any) -> int:
        # bool is a subclass of int; True must not silently mean ticket 1.
        if isinstance(value, bool) or not isinstance(value, int):
            raise GatewayError("invalid_argument_type")
        return value

    @classmethod
    def _coerce_text(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise GatewayError("invalid_argument_type")
        if len(value) > 4_000:
            raise GatewayError("input_too_long")
        if cls.CONTROL_CHARACTERS.search(value):
            raise GatewayError("control_character")
        return value

    @classmethod
    def _validate_inputs(cls, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        """Return a type-checked copy of args, or raise a GatewayError.

        Every value is validated against a declared type. Unvalidated values
        never reach `_dispatch`, so the store cannot be handed a coerced
        `str(dict)` or an oversized nested payload.
        """
        declared = cls.ARGUMENT_TYPES.get(tool)
        if declared is None:
            raise GatewayError("unknown_tool")
        if set(args) - set(declared):
            raise GatewayError("unexpected_argument")

        clean: dict[str, Any] = {}
        for name, kind in declared.items():
            optional = kind.startswith("optional_")
            if name not in args or args[name] is None:
                if not optional:
                    raise GatewayError("missing_argument")
                clean[name] = None
                continue
            base = kind.removeprefix("optional_")
            clean[name] = (
                cls._coerce_integer(args[name])
                if base == "integer"
                else cls._coerce_text(args[name])
            )

        if tool == "create_ticket" and (not clean["title"].strip() or not clean["body"].strip()):
            raise GatewayError("invalid_input")
        if tool == "update_ticket_status" and clean["status"] not in cls.VALID_STATUSES:
            raise GatewayError("invalid_status")
        if tool == "get_ticket" and clean["ticket_id"] < 1:
            raise GatewayError("invalid_argument_type")
        return clean

    def _dispatch(self, tool: str, args: dict[str, Any], access: AccessToken) -> Any:
        claims = access.claims or {}
        teams = set(claims.get("teams", []))
        if tool == "list_tickets":
            return self.store.list_tickets(teams, args["status"])
        if tool == "get_ticket":
            return self._visible_ticket(args["ticket_id"], teams)
        if tool == "create_ticket":
            if args["team"] not in teams:
                raise GatewayError("row_scope_violation")
            return self.store.create_ticket(
                args["team"], args["title"], args["body"], access.client_id
            )
        if tool == "update_ticket_status":
            ticket_id = args["ticket_id"]
            self._visible_ticket(ticket_id, teams)
            return self.store.update_status(ticket_id, args["status"])
        if tool == "audit_recent":
            limit = min(max(args["limit"] or 20, 1), 100)
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
