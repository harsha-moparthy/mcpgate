from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class Bucket:
    tokens: float
    updated_at: float


class TokenBucketLimiter:
    """Thread-safe token bucket keyed by authenticated client identity."""

    def __init__(
        self,
        capacity: int,
        refill_per_second: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        if capacity <= 0 or refill_per_second <= 0:
            raise ValueError("rate limit values must be positive")
        self.capacity = float(capacity)
        self.refill_per_second = refill_per_second
        self.clock = clock
        self._buckets: dict[str, Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, identity: str, cost: float = 1.0) -> tuple[bool, float]:
        now = self.clock()
        with self._lock:
            bucket = self._buckets.setdefault(identity, Bucket(self.capacity, now))
            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_per_second)
            bucket.updated_at = now
            if bucket.tokens < cost:
                retry_after = (cost - bucket.tokens) / self.refill_per_second
                return False, retry_after
            bucket.tokens -= cost
            return True, 0.0
