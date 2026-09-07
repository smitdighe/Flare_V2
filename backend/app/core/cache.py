"""TTL cache. PLAN §10.2 — a repeated source IP must not spend fresh quota.

Bounded and LRU-evicting, because an unbounded cache keyed on attacker IPs is a
memory leak with a plausible-looking name on it.

ONE RULE THIS ENFORCES AND THE PRIOR CODEBASE DID NOT: a degraded result is
never cached. Caching a partial enrichment pins a transient provider outage for
the whole TTL and makes it look like a stable fact about the IP.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Generic, TypeVar

V = TypeVar("V")


class TTLCache(Generic[V]):
    def __init__(self, ttl_seconds: float, max_entries: int) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: OrderedDict[str, tuple[float, V]] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> V | None:
        entry = self._entries.get(key)
        if entry is None:
            self.misses += 1
            return None
        expires_at, value = entry
        if time.monotonic() >= expires_at:
            del self._entries[key]
            self.misses += 1
            return None
        self._entries.move_to_end(key)
        self.hits += 1
        return value

    def set(self, key: str, value: V) -> None:
        self._entries[key] = (time.monotonic() + self.ttl_seconds, value)
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def clear(self) -> None:
        self._entries.clear()
        self.hits = 0
        self.misses = 0

    def stats(self) -> dict[str, int | float]:
        return {
            "entries": len(self._entries),
            "max_entries": self.max_entries,
            "ttl_seconds": self.ttl_seconds,
            "hits": self.hits,
            "misses": self.misses,
        }
