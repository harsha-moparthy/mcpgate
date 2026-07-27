from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_artifacts (
    digest TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    client_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    expires_at REAL NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    occurred_at REAL NOT NULL,
    client_id TEXT,
    tool TEXT NOT NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    args_json TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ticket_team ON tickets(team);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id, sequence);
"""


class Store:
    def __init__(self, path: Path | str = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self.connection.executescript(SCHEMA)
            self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def seed(self) -> None:
        with self._lock:
            count = self.connection.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
            if count:
                return
            now = time.time()
            rows = [
                (
                    "alpha",
                    "Login timeout",
                    "Customers see a timeout after SSO.",
                    "open",
                    "seed",
                ),
                (
                    "beta",
                    "Export is slow",
                    "CSV export exceeds the latency SLO.",
                    "open",
                    "seed",
                ),
                (
                    "security",
                    "Rotate signing key",
                    "Quarterly key rotation is due.",
                    "planned",
                    "seed",
                ),
            ]
            self.connection.executemany(
                "INSERT INTO tickets(team,title,body,status,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?)",
                [(*row, now, now) for row in rows],
            )
            self.connection.commit()

    def list_tickets(self, teams: set[str], status: str | None = None) -> list[dict[str, Any]]:
        if not teams:
            return []
        placeholders = ",".join("?" for _ in teams)
        sql = f"SELECT * FROM tickets WHERE team IN ({placeholders})"
        values: list[Any] = sorted(teams)
        if status is not None:
            sql += " AND status = ?"
            values.append(status)
        sql += " ORDER BY id"
        with self._lock:
            return [dict(row) for row in self.connection.execute(sql, values)]

    def get_ticket(self, ticket_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM tickets WHERE id = ?", (ticket_id,)
            ).fetchone()
            return dict(row) if row else None

    def create_ticket(self, team: str, title: str, body: str, client_id: str) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            cursor = self.connection.execute(
                "INSERT INTO tickets(team,title,body,status,created_by,created_at,updated_at) "
                "VALUES(?,?,?,'open',?,?,?)",
                (team, title, body, client_id, now, now),
            )
            self.connection.commit()
            return self.get_ticket(cursor.lastrowid)  # type: ignore[return-value]

    def update_status(self, ticket_id: int, status: str) -> dict[str, Any] | None:
        with self._lock:
            cursor = self.connection.execute(
                "UPDATE tickets SET status = ?, updated_at = ? WHERE id = ?",
                (status, time.time(), ticket_id),
            )
            self.connection.commit()
            return self.get_ticket(ticket_id) if cursor.rowcount else None

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def put_artifact(
        self,
        token: str,
        kind: str,
        client_id: str,
        payload: dict[str, Any],
        expires_at: float,
    ) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT OR REPLACE INTO oauth_artifacts"
                "(digest,kind,client_id,payload,expires_at,consumed,revoked) "
                "VALUES(?,?,?,?,?,0,0)",
                (
                    self.digest(token),
                    kind,
                    client_id,
                    json.dumps(payload, sort_keys=True),
                    expires_at,
                ),
            )
            self.connection.commit()

    def get_artifact(
        self, token: str, kind: str, *, consume: bool = False
    ) -> dict[str, Any] | None:
        digest = self.digest(token)
        now = time.time()
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM oauth_artifacts WHERE digest=? AND kind=? AND revoked=0 "
                "AND consumed=0 AND expires_at>?",
                (digest, kind, now),
            ).fetchone()
            if row is None:
                return None
            if consume:
                changed = self.connection.execute(
                    "UPDATE oauth_artifacts SET consumed=1 WHERE digest=? AND consumed=0",
                    (digest,),
                ).rowcount
                self.connection.commit()
                if changed != 1:
                    return None
            payload = json.loads(row["payload"])
            payload.update(client_id=row["client_id"], expires_at=row["expires_at"])
            return payload

    def revoke_artifact(self, token: str) -> None:
        with self._lock:
            self.connection.execute(
                "UPDATE oauth_artifacts SET revoked=1 WHERE digest=?",
                (self.digest(token),),
            )
            self.connection.commit()

    def append_audit(self, values: dict[str, Any]) -> dict[str, Any]:
        columns = ",".join(values)
        placeholders = ",".join("?" for _ in values)
        with self._lock:
            cursor = self.connection.execute(
                f"INSERT INTO audit_events({columns}) VALUES({placeholders})",
                tuple(values.values()),
            )
            self.connection.commit()
            row = self.connection.execute(
                "SELECT * FROM audit_events WHERE sequence=?", (cursor.lastrowid,)
            ).fetchone()
            return dict(row)

    def last_audit_hash(self) -> str:
        with self._lock:
            row = self.connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            return str(row[0]) if row else "0" * 64

    def audit_events(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            if session_id:
                rows = self.connection.execute(
                    "SELECT * FROM audit_events WHERE session_id=? ORDER BY sequence LIMIT ?",
                    (session_id, limit),
                )
            else:
                rows = self.connection.execute(
                    "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?",
                    (limit,),
                )
            return [dict(row) for row in rows]
