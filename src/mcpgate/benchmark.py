from __future__ import annotations

import asyncio
import json
import statistics
import tempfile
import time
from pathlib import Path

from .config import Settings
from .gateway import Invocation
from .runtime import create_runtime


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * p)))
    return ordered[index]


async def run_benchmark(iterations: int = 500) -> dict[str, float | int]:
    with tempfile.TemporaryDirectory() as directory:
        settings = Settings(
            database_path=Path(directory) / "bench.sqlite3",
            rate_capacity=iterations + 10,
            rate_refill_per_second=iterations + 10,
        )
        runtime = create_runtime(settings)
        pair = runtime.provider.issue_for_client(
            "operator-agent", "operator-local-secret", ["tickets:read"]
        )
        direct_ms: list[float] = []
        governed_ms: list[float] = []
        for _ in range(iterations):
            started = time.perf_counter()
            runtime.gateway.direct("list_tickets", {"status": None}, {"alpha", "beta"}, "bench")
            direct_ms.append((time.perf_counter() - started) * 1000)

            started = time.perf_counter()
            await runtime.gateway.invoke(
                Invocation("list_tickets", {"status": None}, pair.access_token, "benchmark")
            )
            governed_ms.append((time.perf_counter() - started) * 1000)
        result: dict[str, float | int] = {
            "iterations": iterations,
            "direct_median_ms": round(statistics.median(direct_ms), 4),
            "direct_p95_ms": round(percentile(direct_ms, 0.95), 4),
            "governed_median_ms": round(statistics.median(governed_ms), 4),
            "governed_p95_ms": round(percentile(governed_ms, 0.95), 4),
            "median_overhead_ms": round(
                statistics.median(governed_ms) - statistics.median(direct_ms), 4
            ),
            "p95_overhead_ms": round(
                percentile(governed_ms, 0.95) - percentile(direct_ms, 0.95), 4
            ),
        }
        runtime.store.close()
        return result


def main(iterations: int = 500) -> None:
    print(json.dumps(asyncio.run(run_benchmark(iterations)), indent=2))
