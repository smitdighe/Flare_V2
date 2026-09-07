"""VirusTotal IP reputation. PLAN §10.1 (~4/min, ~500/day), T11, I7.

**THE IP ENDPOINT ONLY. NO HASH LOOKUP, EVER.**

The prior codebase computed `md5(signature)` and queried the file-hash endpoint
with it. That digest names no file that has ever existed, so every call was a
guaranteed 404, and the 404 was rendered to the analyst as a threat verdict —
T11. A hash is not derivable from a network flow record, so the honest handling
is to not have one: `vt_hash` stays null on every alert this pipeline produces.

The score is normalized from `last_analysis_stats` so it is comparable with
AbuseIPDB's 0-100 confidence and `max()` across sources is meaningful.
"""

from __future__ import annotations

import time

import httpx

from app.intel.base import IntelResult

BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
SOURCE = "virustotal"


class VirusTotalClient:
    def __init__(self, api_key: str | None, timeout_seconds: float) -> None:
        self._api_key = api_key
        self._timeout = timeout_seconds

    async def check(self, ip: str) -> IntelResult:
        if not self._api_key:
            return IntelResult(
                source=SOURCE, status="skipped", detail="no API key configured"
            )

        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    f"{BASE_URL}/{ip}", headers={"x-apikey": self._api_key}
                )
        except httpx.TimeoutException:
            return IntelResult(
                source=SOURCE,
                status="error",
                detail=f"timeout after {self._timeout}s",
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except httpx.HTTPError as exc:
            return IntelResult(
                source=SOURCE,
                status="error",
                detail=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        duration_ms = (time.perf_counter() - started) * 1000

        if response.status_code == 429:
            return IntelResult(
                source=SOURCE,
                status="rate_limited",
                detail="quota exhausted (4/min, 500/day on the free tier)",
                duration_ms=duration_ms,
            )
        if response.status_code == 404:
            # VirusTotal genuinely has no record for this address. That is a
            # real answer meaning "unknown", NOT a clean bill of health, so it
            # carries no score.
            return IntelResult(
                source=SOURCE,
                status="ok",
                score=None,
                malicious=False,
                detail="no VirusTotal record for this address",
                duration_ms=duration_ms,
            )
        if response.status_code != 200:
            return IntelResult(
                source=SOURCE,
                status="error",
                detail=f"HTTP {response.status_code}: {response.text[:120]}",
                duration_ms=duration_ms,
            )

        try:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(int(v) for v in stats.values())
        except (KeyError, TypeError, ValueError) as exc:
            return IntelResult(
                source=SOURCE,
                status="error",
                detail=f"unexpected response shape: {exc}",
                duration_ms=duration_ms,
            )

        if total <= 0:
            return IntelResult(
                source=SOURCE,
                status="ok",
                score=None,
                detail="no engine results",
                duration_ms=duration_ms,
            )

        # Suspicious counts half. An engine saying "suspicious" is weaker
        # evidence than one saying "malicious", and flattening them would
        # overstate the score on an address a single engine merely flagged.
        score = round(100 * (malicious + 0.5 * suspicious) / total)
        return IntelResult(
            source=SOURCE,
            status="ok",
            score=score,
            malicious=malicious > 0,
            detail=f"{malicious} malicious / {suspicious} suspicious of {total} engines",
            duration_ms=duration_ms,
        )
