"""AbuseIPDB IP reputation. PLAN §10.1 (~1000/day), I7.

`abuseConfidenceScore` is already 0-100, so no rescaling is needed and none is
invented. `malicious` is a threshold on that score rather than a separate field,
because AbuseIPDB does not publish a boolean verdict and manufacturing one from
`totalReports` would be our opinion wearing the provider's name.
"""

from __future__ import annotations

import time

import httpx

from app.intel.base import IntelResult

URL = "https://api.abuseipdb.com/api/v2/check"
SOURCE = "abuseipdb"
MALICIOUS_AT = 25


class AbuseIPDBClient:
    def __init__(self, api_key: str | None, timeout_seconds: float) -> None:
        self._api_key = api_key
        self._timeout = timeout_seconds

    async def check(self, ip: str) -> IntelResult:
        if not self._api_key:
            return IntelResult(
                source=SOURCE,
                status="skipped",
                detail="no API key configured",
            )

        started = time.perf_counter()
        try:
            # T1 — construction inside the try.
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    URL,
                    headers={"Key": self._api_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
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
                detail="daily quota exhausted",
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
            data = response.json()["data"]
            score = int(data["abuseConfidenceScore"])
        except (KeyError, TypeError, ValueError) as exc:
            # A 200 whose body does not carry the field is a failed lookup, the
            # same rule I18 applies to providers.
            return IntelResult(
                source=SOURCE,
                status="error",
                detail=f"unexpected response shape: {exc}",
                duration_ms=duration_ms,
            )

        return IntelResult(
            source=SOURCE,
            status="ok",
            score=score,
            malicious=score >= MALICIOUS_AT,
            detail=(
                f"{data.get('totalReports', 0)} reports from "
                f"{data.get('numDistinctUsers', 0)} distinct users"
            ),
            duration_ms=duration_ms,
        )
