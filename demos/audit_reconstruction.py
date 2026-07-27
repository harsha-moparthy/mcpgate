"""Drive a realistic mixed session, then rebuild it from the audit trail alone."""

from __future__ import annotations

import asyncio
import json
import tempfile
from dataclasses import replace
from pathlib import Path

from mcpgate.config import Settings
from mcpgate.gateway import GatewayError, Invocation
from mcpgate.runtime import create_runtime

SESSION = "incident-4417"


async def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        runtime = create_runtime(
            replace(
                Settings(),
                database_path=Path(directory) / "demo.sqlite3",
                rate_capacity=4,
                rate_refill_per_second=0.01,
            )
        )
        operator = runtime.provider.issue_for_client(
            "operator-agent", "operator-local-secret"
        ).access_token
        readonly = runtime.provider.issue_for_client(
            "readonly-agent", "readonly-local-secret"
        ).access_token

        print("=== 1. a mixed session: legitimate work plus three attacks ===")
        attempts: list[tuple[str, str, dict[str, object]]] = [
            (operator, "list_tickets", {"status": "open"}),
            (
                operator,
                "create_ticket",
                {
                    "team": "alpha",
                    "title": "Payment retries spike",
                    "body": "Customer PII and card details go here.",
                },
            ),
            (readonly, "create_ticket", {"team": "alpha", "title": "x", "body": "y"}),
            (operator, "get_ticket", {"ticket_id": 3}),
            ("not-a-real-token", "list_tickets", {"status": None}),
        ]
        for token, tool, args in attempts:
            try:
                await runtime.gateway.invoke(Invocation(tool, args, token, SESSION))
                print(f"  allow  {tool}")
            except GatewayError as exc:
                print(f"  DENY   {tool} -> {exc.code}")

        print()
        print("=== 2. rebuild the session from the audit trail alone ===")
        events = runtime.audit.reconstruct(SESSION)
        for event in events:
            print(
                f"  #{event['sequence']} {event['decision']:5} {event['tool']:22}"
                f" {event['reason']:22} args={json.dumps(event['args'])}"
            )

        print()
        print("=== 3. verify the evidence ===")
        allows = sum(1 for event in events if event["decision"] == "allow")
        denies = sum(1 for event in events if event["decision"] == "deny")
        checks = [
            ("every attempt is on the record", len(events) == len(attempts)),
            ("2 allowed, 3 denied", (allows, denies) == (2, 3)),
            (
                "sensitive body redacted in the log",
                all(event["args"].get("body") in (None, "[REDACTED]") for event in events),
            ),
            ("hash chain intact", runtime.audit.verify_chain()),
            (
                "no forbidden side effect: security ticket untouched",
                runtime.store.get_ticket(3)["status"] == "planned",
            ),
        ]
        ok = True
        for label, passed in checks:
            print(f"  {'PASS ' if passed else 'FAIL '} {label}")
            ok &= passed

        print()
        print("=== 4. tamper with one row and re-verify ===")
        runtime.store.connection.execute(
            "UPDATE audit_events SET decision='allow' WHERE sequence = ("
            "  SELECT MIN(sequence) FROM audit_events WHERE decision='deny'"
            ")"
        )
        runtime.store.connection.commit()
        detected = not runtime.audit.verify_chain()
        print(f"  {'PASS ' if detected else 'FAIL '} tampering detected after edit")
        ok &= detected

        runtime.store.close()
        print()
        print(
            "=== AUDIT RECONSTRUCTION DEMO PASSED ==="
            if ok
            else "=== AUDIT RECONSTRUCTION DEMO FAILED ==="
        )
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
