from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from mcpgate.config import Settings
from mcpgate.runtime import Runtime, create_runtime


@pytest.fixture
def runtime(tmp_path: Path) -> Runtime:
    settings = replace(
        Settings(),
        database_path=tmp_path / "test.sqlite3",
        rate_capacity=5,
        rate_refill_per_second=0.01,
    )
    value = create_runtime(settings)
    yield value
    value.store.close()
