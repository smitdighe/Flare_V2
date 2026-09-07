"""Aggregate AbuseIPDB + VirusTotal. PLAN Part D / §10.2 / T12.

    score     = max(normalized score across sources that answered)
    malicious = any(source said malicious)

`max` and `any` because these are independent observers of the same address:
one source having seen abuse is evidence, and the other not having seen it is
not counter-evidence. Averaging would let a silent source dilute a real hit.

PARTIAL FAILURE IS A FIRST-CLASS RESULT, NOT A SILENT ONE. If one source errors
and the other answers, the aggregate is usable AND `degraded` — both facts
travel together, both reach the trace, and the pair is NOT written to the cache.
Caching a degraded result would pin a transient outage as a stable fact about
the address for the whole TTL.

Both sources are called CONCURRENTLY. Sequentially they cost the sum of two
timeouts on the enrich stage, and the two calls have nothing to do with each
other.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from app.config import Settings
from app.core.cache import TTLCache
from app.intel.abuseipdb import AbuseIPDBClient
from app.intel.base import IntelResult, is_public_ip
from app.intel.virustotal import VirusTotalClient


@dataclass(frozen=True)
class IntelVerdict:
    ip: str
    checked: bool
    score: int | None
    malicious: bool
    degraded: bool
    cached: bool
    results: list[IntelResult] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def sources_ok(self) -> list[str]:
        return [r.source for r in self.results if r.status == "ok"]

    @property
    def sources_failed(self) -> list[str]:
        return [r.source for r in self.results if r.status in ("error", "rate_limited")]

    def note(self) -> str:
        if not self.checked:
            return "not checked"
        parts = []
        if self.sources_ok:
            parts.append(f"answered: {', '.join(self.sources_ok)}")
        if self.sources_failed:
            parts.append(f"failed: {', '.join(self.sources_failed)}")
        if self.cached:
            parts.append("served from per-IP cache")
        return "; ".join(parts) or "no source answered"


class IntelAggregator:
    def __init__(self, settings: Settings) -> None:
        self._abuseipdb = AbuseIPDBClient(
            settings.abuseipdb_api_key, settings.intel_timeout_seconds
        )
        self._virustotal = VirusTotalClient(
            settings.virustotal_api_key, settings.intel_timeout_seconds
        )
        self._cache: TTLCache[IntelVerdict] = TTLCache(
            ttl_seconds=settings.intel_cache_ttl_seconds,
            max_entries=settings.intel_cache_max_entries,
        )

    @property
    def cache_stats(self) -> dict[str, int | float]:
        return self._cache.stats()

    def clear_cache(self) -> None:
        """Drop every cached verdict. PLAN E8.

        The eval bypasses this cache before scoring: a reputation served from a
        lookup would let an escalation decision rest on a call that did not
        happen during the run, and the run would be reporting a mixture of fresh
        and remembered evidence as one number.
        """
        self._cache.clear()

    async def probe(self, source: str, ip: str) -> IntelResult:
        """One source, one address, CACHE BYPASSED. For /health/deep only.

        A health probe served from cache would report the provider as healthy
        long after it stopped answering, which is the opposite of what the
        endpoint is for.
        """
        if source == "abuseipdb":
            return await self._abuseipdb.check(ip)
        if source == "virustotal":
            return await self._virustotal.check(ip)
        raise KeyError(f"unknown intel source {source!r}")

    async def lookup(self, ip: str) -> IntelVerdict:
        if not is_public_ip(ip):
            # PLAN §10.2 — do not spend a metered unit on RFC1918 space. This is
            # an honest skip with a reason, not a fabricated clean verdict:
            # `checked` is False and `score` is None.
            return IntelVerdict(
                ip=ip,
                checked=False,
                score=None,
                malicious=False,
                degraded=False,
                cached=False,
                results=[
                    IntelResult(
                        source="aggregator",
                        status="skipped",
                        detail=(
                            "address is private, loopback or reserved; no intel "
                            "source has data on it and a lookup would spend "
                            "quota to learn nothing"
                        ),
                    )
                ],
            )

        cached = self._cache.get(ip)
        if cached is not None:
            return IntelVerdict(
                ip=cached.ip,
                checked=cached.checked,
                score=cached.score,
                malicious=cached.malicious,
                degraded=cached.degraded,
                cached=True,
                results=cached.results,
                duration_ms=0.0,
            )

        started = asyncio.get_running_loop().time()
        abuse, virustotal = await asyncio.gather(
            self._abuseipdb.check(ip), self._virustotal.check(ip)
        )
        duration_ms = (asyncio.get_running_loop().time() - started) * 1000

        results = [abuse, virustotal]
        usable = [r for r in results if r.usable]
        scores = [r.score for r in usable if r.score is not None]

        answered = [r for r in results if r.status == "ok"]
        failed = [r for r in results if r.status in ("error", "rate_limited")]

        verdict = IntelVerdict(
            ip=ip,
            checked=bool(answered),
            score=max(scores) if scores else None,
            malicious=any(r.malicious for r in results),
            degraded=bool(failed),
            cached=False,
            results=results,
            duration_ms=duration_ms,
        )

        # T12 / PLAN Part D — a degraded verdict is never cached.
        if not verdict.degraded and verdict.checked:
            self._cache.set(ip, verdict)
        return verdict


_aggregator: IntelAggregator | None = None


def load_aggregator(settings: Settings) -> IntelAggregator:
    global _aggregator
    _aggregator = IntelAggregator(settings)
    return _aggregator


def get_aggregator() -> IntelAggregator:
    global _aggregator
    if _aggregator is None:
        from app.config import get_settings

        _aggregator = IntelAggregator(get_settings())
    return _aggregator


def reset_aggregator() -> None:
    global _aggregator
    _aggregator = None
