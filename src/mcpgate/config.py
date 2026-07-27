from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    database_path: Path = Path(os.environ.get("MCPGATE_DB", ROOT / "data" / "mcpgate.sqlite3"))
    policy_path: Path = Path(os.environ.get("MCPGATE_POLICY", ROOT / "policy.yaml"))
    issuer_url: str = os.environ.get("MCPGATE_ISSUER", "http://127.0.0.1:8000")
    resource_url: str = os.environ.get("MCPGATE_RESOURCE", "http://127.0.0.1:8000/mcp")
    jwt_secret: str = os.environ.get(
        "MCPGATE_JWT_SECRET", "local-development-secret-change-before-deploy"
    )
    access_token_ttl: int = int(os.environ.get("MCPGATE_ACCESS_TTL", "300"))
    refresh_token_ttl: int = int(os.environ.get("MCPGATE_REFRESH_TTL", "3600"))
    rate_capacity: int = int(os.environ.get("MCPGATE_RATE_CAPACITY", "20"))
    rate_refill_per_second: float = float(os.environ.get("MCPGATE_RATE_REFILL", "5"))
    host: str = os.environ.get("MCPGATE_HOST", "127.0.0.1")
    port: int = int(os.environ.get("MCPGATE_PORT", "8000"))
