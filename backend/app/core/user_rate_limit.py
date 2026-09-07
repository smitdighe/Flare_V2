"""Per-user, per-route budgets. CONTRACT §9.5 / PLAN §10.4.

The global limiter in `app/core/middleware.py` is sized for ordinary API
traffic — 120 requests a minute — which is the right number for reading alerts
and the wrong number for a route that spends four metered provider quotas per
call. At the global limit one operator leaning on `/health/deep` would draw 480
provider calls a minute and exhaust the free tier before the demo started.

This is a SECOND budget, applied on top, keyed by user id and route. It is a
token bucket for the same reason the reasoning budget is: a fixed window lets
the whole minute's allowance leave in the first second, which is exactly the
burst a provider counts against you.

`time.monotonic` only, and no sleeping — `check` answers immediately and the
caller raises. The limiter never blocks the event loop (I6).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    tokens: float
    last: float


@dataclass
class UserRateLimiter:
    """One named budget, per user."""

    name: str
    calls_per_minute: float
    burst: int = 1
    _buckets: dict[int, _Bucket] = field(default_factory=dict)

    @property
    def _rate_per_second(self) -> float:
        return self.calls_per_minute / 60.0

    def check(self, user_id: int) -> float | None:
        """Returns None when allowed, or the seconds to wait when refused."""
        now = time.monotonic()
        capacity = float(max(1, self.burst))
        bucket = self._buckets.get(user_id)
        if bucket is None:
            bucket = _Bucket(tokens=capacity, last=now)
            self._buckets[user_id] = bucket

        elapsed = now - bucket.last
        bucket.last = now
        bucket.tokens = min(capacity, bucket.tokens + elapsed * self._rate_per_second)

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            self._evict(now)
            return None

        needed = 1.0 - bucket.tokens
        return max(1.0, needed / self._rate_per_second)

    def _evict(self, now: float) -> None:
        """Bounded memory: forget users whose bucket has fully refilled.

        Without this the dict grows once per distinct user and never shrinks —
        the same leak the global limiter's cutoff sweep exists to prevent.
        """
        if len(self._buckets) <= 1024:
            return
        capacity = float(max(1, self.burst))
        full_after = capacity / self._rate_per_second
        for user_id in [
            uid for uid, b in self._buckets.items() if now - b.last > full_after
        ]:
            del self._buckets[user_id]

    def reset(self) -> None:
        self._buckets.clear()


_limiters: dict[str, UserRateLimiter] = {}


def get_limiter(name: str, calls_per_minute: float, burst: int = 1) -> UserRateLimiter:
    limiter = _limiters.get(name)
    if limiter is None or limiter.calls_per_minute != calls_per_minute:
        limiter = UserRateLimiter(
            name=name, calls_per_minute=calls_per_minute, burst=burst
        )
        _limiters[name] = limiter
    return limiter


def reset_limiters() -> None:
    """Test seam."""
    _limiters.clear()
