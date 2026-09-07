"""Reasoning-call rate budget. PLAN §10.4 / Part B.

The severity floor is POLICY — which alerts deserve an analyst narrative. This
is the CAP — how many the free tier can actually absorb. They are different
questions and conflating them produces a floor chosen to dodge a quota rather
than to express what an analyst needs.

The arithmetic that makes this necessary: at the configured replay rate of 30
alerts/min, a `high` floor admits roughly 20 alerts/min, and Gemini's free tier
is ~15 RPM. Without a cap the demo 429s inside the first minute (T4). With it,
admission is bounded at `reason_calls_per_minute` and every alert turned away
gets a TRACED skip naming the budget — never a silent drop (T12/I5).

A token bucket rather than a fixed window: a fixed window lets 12 calls fire in
the first second of every minute, which is a burst the provider sees as 12 RPS.
The bucket smooths admission to the average rate with a small burst allowance.

`time.monotonic` only. No sleeping, no blocking: `try_acquire` answers
immediately and the caller routes on the answer (I6, T5).
"""

from __future__ import annotations

import time


class RateBudget:
    def __init__(self, calls_per_minute: float, burst: int | None = None) -> None:
        self.calls_per_minute = calls_per_minute
        self._rate_per_second = calls_per_minute / 60.0
        # One burst slot per 5 seconds of rate, minimum 1: enough to absorb the
        # jitter of a replay loop without letting a whole minute's allowance
        # leave in one breath.
        self.capacity = float(burst if burst is not None else max(1, round(calls_per_minute / 5)))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self.admitted = 0
        self.rejected = 0

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self._rate_per_second)

    def try_acquire(self) -> bool:
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            self.admitted += 1
            return True
        self.rejected += 1
        return False

    def stats(self) -> dict[str, float | int]:
        self._refill()
        return {
            "calls_per_minute": self.calls_per_minute,
            "capacity": self.capacity,
            "available": round(self._tokens, 3),
            "admitted": self.admitted,
            "rejected": self.rejected,
        }


_budget: RateBudget | None = None


def get_reason_budget() -> RateBudget:
    global _budget
    if _budget is None:
        from app.config import get_settings

        _budget = RateBudget(get_settings().reason_calls_per_minute)
    return _budget


def reset_reason_budget(calls_per_minute: float | None = None) -> RateBudget:
    """Test seam, and the hook the runtime uses to retune the rate live."""
    global _budget
    if calls_per_minute is None:
        from app.config import get_settings

        calls_per_minute = get_settings().reason_calls_per_minute
    _budget = RateBudget(calls_per_minute)
    return _budget
