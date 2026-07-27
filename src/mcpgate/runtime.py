from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditLog
from .auth import OAuthProvider
from .config import Settings
from .gateway import Gateway
from .policy import Policy
from .rate_limit import TokenBucketLimiter
from .store import Store


@dataclass
class Runtime:
    settings: Settings
    store: Store
    policy: Policy
    provider: OAuthProvider
    limiter: TokenBucketLimiter
    audit: AuditLog
    gateway: Gateway


def create_runtime(settings: Settings | None = None) -> Runtime:
    settings = settings or Settings()
    store = Store(settings.database_path)
    store.seed()
    policy = Policy(settings.policy_path)
    provider = OAuthProvider(store, policy, settings)
    limiter = TokenBucketLimiter(settings.rate_capacity, settings.rate_refill_per_second)
    audit = AuditLog(store, settings.jwt_secret)
    gateway = Gateway(store, policy, provider, limiter, audit)
    return Runtime(settings, store, policy, provider, limiter, audit, gateway)
