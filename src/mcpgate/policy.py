from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ClientPolicy:
    client_id: str
    secret: str
    scopes: frozenset[str]
    teams: frozenset[str]


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    scope: str
    action: str


class Policy:
    def __init__(self, path: Path):
        raw: dict[str, Any] = yaml.safe_load(path.read_text())
        if raw.get("version") != 1:
            raise ValueError("unsupported policy version")
        self.clients = {
            client_id: ClientPolicy(
                client_id=client_id,
                secret=str(spec["secret"]),
                scopes=frozenset(spec["scopes"]),
                teams=frozenset(spec["teams"]),
            )
            for client_id, spec in raw["clients"].items()
        }
        self.tools = {
            name: ToolPolicy(name=name, scope=spec["scope"], action=spec["action"])
            for name, spec in raw["tools"].items()
        }

    def client(self, client_id: str) -> ClientPolicy | None:
        return self.clients.get(client_id)

    def authorize_scopes(self, client_id: str, requested: list[str]) -> list[str]:
        client = self.client(client_id)
        if client is None:
            raise PermissionError("unknown_client")
        requested_set = set(requested)
        if not requested_set <= client.scopes:
            raise PermissionError("scope_escalation")
        return sorted(requested_set)

    def require_tool(self, tool: str, scopes: set[str]) -> ToolPolicy:
        rule = self.tools.get(tool)
        if rule is None:
            raise PermissionError("unknown_tool")
        if rule.scope not in scopes:
            raise PermissionError(f"missing_scope:{rule.scope}")
        return rule
