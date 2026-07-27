from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from .store import Store

REDACTED_FIELDS = {"token", "client_secret", "body"}


def _safe_args(args: dict[str, Any]) -> dict[str, Any]:
    return {
        key: "[REDACTED]" if key.lower() in REDACTED_FIELDS else value
        for key, value in args.items()
    }


class AuditLog:
    """Structured, tamper-evident audit trail chained with HMAC-SHA256."""

    def __init__(self, store: Store, signing_key: str):
        self.store = store
        self.key = signing_key.encode()

    def record(
        self,
        *,
        session_id: str,
        client_id: str | None,
        tool: str,
        action: str,
        decision: str,
        reason: str,
        args: dict[str, Any],
        latency_ms: float,
    ) -> dict[str, Any]:
        safe = _safe_args(args)
        args_json = json.dumps(safe, sort_keys=True, separators=(",", ":"))
        args_digest = hashlib.sha256(
            json.dumps(args, sort_keys=True, default=str).encode()
        ).hexdigest()
        previous_hash = self.store.last_audit_hash()
        occurred_at = time.time()
        canonical = json.dumps(
            {
                "session_id": session_id,
                "occurred_at": occurred_at,
                "client_id": client_id,
                "tool": tool,
                "action": action,
                "decision": decision,
                "reason": reason,
                "args_json": args_json,
                "args_digest": args_digest,
                "latency_ms": round(latency_ms, 6),
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        event_hash = hmac.new(self.key, canonical.encode(), hashlib.sha256).hexdigest()
        return self.store.append_audit(
            {
                "session_id": session_id,
                "occurred_at": occurred_at,
                "client_id": client_id,
                "tool": tool,
                "action": action,
                "decision": decision,
                "reason": reason,
                "args_json": args_json,
                "args_digest": args_digest,
                "latency_ms": round(latency_ms, 6),
                "previous_hash": previous_hash,
                "event_hash": event_hash,
            }
        )

    def verify_chain(self) -> bool:
        events = list(reversed(self.store.audit_events(limit=1_000_000)))
        previous_hash = "0" * 64
        for event in events:
            if event["previous_hash"] != previous_hash:
                return False
            canonical = json.dumps(
                {
                    key: event[key]
                    for key in (
                        "session_id",
                        "occurred_at",
                        "client_id",
                        "tool",
                        "action",
                        "decision",
                        "reason",
                        "args_json",
                        "args_digest",
                        "latency_ms",
                        "previous_hash",
                    )
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            expected = hmac.new(self.key, canonical.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, event["event_hash"]):
                return False
            previous_hash = event["event_hash"]
        return True

    def reconstruct(self, session_id: str) -> list[dict[str, Any]]:
        return [
            {
                "sequence": event["sequence"],
                "tool": event["tool"],
                "action": event["action"],
                "decision": event["decision"],
                "reason": event["reason"],
                "args": json.loads(event["args_json"]),
            }
            for event in self.store.audit_events(session_id=session_id, limit=10_000)
        ]
