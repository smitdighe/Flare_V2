"""Threat intel: aggregation, caching, degraded results, T11.

PLAN Part D / §10.2 / T11 / I7.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from app.config import Settings
from app.core.cache import TTLCache
from app.intel.abuseipdb import AbuseIPDBClient
from app.intel.aggregator import IntelAggregator
from app.intel.base import is_public_ip
from app.intel.virustotal import VirusTotalClient

PUBLIC = "118.25.6.39"


def settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "jwt_secret": "t" * 40,
        "environment": "test",
        "abuseipdb_api_key": "abuse-key",
        "virustotal_api_key": "vt-key",
        "intel_timeout_seconds": 3.0,
        "intel_escalation_score": 50,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def route(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    """One MockTransport shared by both intel clients, restored after the test."""
    import app.intel.abuseipdb as abuse_mod
    import app.intel.virustotal as vt_mod

    slot: dict[str, object] = {}
    real = httpx.AsyncClient

    class _Client(real):  # type: ignore[misc,valid-type]
        def __init__(self, **kwargs: object) -> None:
            super().__init__(  # type: ignore[arg-type]
                transport=httpx.MockTransport(slot["handler"]), **kwargs
            )

    monkeypatch.setattr(abuse_mod.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(vt_mod.httpx, "AsyncClient", _Client)
    yield slot


def by_host(abuse: httpx.Response, virustotal: httpx.Response):
    def handler(request: httpx.Request) -> httpx.Response:
        return abuse if "abuseipdb" in request.url.host else virustotal

    return handler


def abuse_ok(score: int) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "ipAddress": PUBLIC,
                "abuseConfidenceScore": score,
                "totalReports": 4,
                "numDistinctUsers": 3,
            }
        },
    )


def vt_ok(malicious: int, suspicious: int = 0, harmless: int = 60) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": 30,
                        "timeout": 0,
                    }
                }
            }
        },
    )


# ---------------------------------------------------------------------------
# aggregation
# ---------------------------------------------------------------------------


async def test_score_is_the_max_and_malicious_is_any(route) -> None:
    """One source seeing abuse is evidence; the other's silence is not counter-evidence."""
    route["handler"] = by_host(abuse_ok(12), vt_ok(malicious=6, harmless=54))
    verdict = await IntelAggregator(settings()).lookup(PUBLIC)

    # VT: 6 malicious of 90 engines -> 7; AbuseIPDB: 12. max() picks 12.
    assert verdict.score == 12
    assert verdict.malicious is True
    assert verdict.degraded is False


async def test_a_failing_source_makes_the_verdict_degraded(route) -> None:
    route["handler"] = by_host(abuse_ok(30), httpx.Response(500, text="vt down"))
    verdict = await IntelAggregator(settings()).lookup(PUBLIC)

    assert verdict.degraded is True
    assert verdict.checked is True
    assert verdict.score == 30
    assert verdict.sources_failed == ["virustotal"]


async def test_a_failed_lookup_has_no_score_rather_than_zero(route) -> None:
    """A zero would render 'we could not check' as 'clean'."""
    route["handler"] = by_host(
        httpx.Response(500, text="down"), httpx.Response(500, text="down")
    )
    verdict = await IntelAggregator(settings()).lookup(PUBLIC)

    assert verdict.score is None
    assert verdict.checked is False
    assert verdict.degraded is True


async def test_a_429_is_reported_as_rate_limited_not_as_an_error(route) -> None:
    route["handler"] = by_host(httpx.Response(429), vt_ok(malicious=0))
    verdict = await IntelAggregator(settings()).lookup(PUBLIC)
    statuses = {r.source: r.status for r in verdict.results}
    assert statuses["abuseipdb"] == "rate_limited"


async def test_a_virustotal_404_is_unknown_not_clean(route) -> None:
    route["handler"] = by_host(abuse_ok(0), httpx.Response(404, json={}))
    verdict = await IntelAggregator(settings()).lookup(PUBLIC)
    vt = next(r for r in verdict.results if r.source == "virustotal")

    assert vt.status == "ok"
    assert vt.score is None, "no record is 'we do not know', not a clean bill of health"


async def test_a_200_with_the_wrong_shape_is_a_failure(route) -> None:
    route["handler"] = by_host(httpx.Response(200, json={"nope": 1}), vt_ok(0))
    verdict = await IntelAggregator(settings()).lookup(PUBLIC)
    abuse = next(r for r in verdict.results if r.source == "abuseipdb")
    assert abuse.status == "error"


async def test_a_timeout_is_a_degraded_result_not_a_crash(route) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "abuseipdb" in request.url.host:
            raise httpx.ReadTimeout("slow", request=request)
        return vt_ok(0)

    route["handler"] = handler
    verdict = await IntelAggregator(settings()).lookup(PUBLIC)
    abuse = next(r for r in verdict.results if r.source == "abuseipdb")
    assert abuse.status == "error"
    assert "timeout after 3.0s" in (abuse.detail or "")


# ---------------------------------------------------------------------------
# caching — PLAN §10.2
# ---------------------------------------------------------------------------


async def test_a_repeated_ip_does_not_spend_fresh_quota(route) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return abuse_ok(20) if "abuseipdb" in request.url.host else vt_ok(0)

    route["handler"] = handler
    aggregator = IntelAggregator(settings())

    first = await aggregator.lookup(PUBLIC)
    second = await aggregator.lookup(PUBLIC)

    assert calls == 2, "one call per source, once"
    assert first.cached is False
    assert second.cached is True
    assert second.score == first.score


async def test_a_degraded_verdict_is_never_cached(route) -> None:
    """T12 — caching it pins a transient outage as a fact for the whole TTL."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if "abuseipdb" in request.url.host:
            return abuse_ok(20)
        return httpx.Response(503, text="temporarily unavailable")

    route["handler"] = handler
    aggregator = IntelAggregator(settings())

    await aggregator.lookup(PUBLIC)
    second = await aggregator.lookup(PUBLIC)

    assert calls == 4, "the degraded verdict was re-fetched, not served from cache"
    assert second.cached is False


def test_the_cache_expires_and_evicts() -> None:
    cache: TTLCache[str] = TTLCache(ttl_seconds=-1, max_entries=2)
    cache.set("a", "1")
    assert cache.get("a") is None, "an expired entry is a miss"

    bounded: TTLCache[str] = TTLCache(ttl_seconds=60, max_entries=2)
    for key in ("a", "b", "c"):
        bounded.set(key, key)
    assert bounded.get("a") is None, "the oldest entry is evicted at the bound"
    assert bounded.get("c") == "c"


# ---------------------------------------------------------------------------
# what is not queried, and T11
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["192.168.10.50", "10.0.0.7", "127.0.0.1", "203.0.113.9"])
async def test_unroutable_addresses_are_skipped_with_a_reason(route, ip: str) -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return abuse_ok(0)

    route["handler"] = handler
    verdict = await IntelAggregator(settings()).lookup(ip)

    assert called is False
    assert verdict.checked is False
    assert verdict.score is None, "not a fabricated clean verdict"
    assert "quota" in (verdict.results[0].detail or "")


def test_the_destination_is_checked_when_the_source_is_internal() -> None:
    """The botnet case, and the reason source-only was wrong.

    A C2 beacon runs OUTBOUND from a compromised internal host, so its source is
    RFC1918 and the address worth asking about is the destination. CICIDS2017's
    C2 is 205.174.165.73 and a source-only lookup never asks about it once —
    which silently removes the most interesting intel lookup in the dataset.
    """
    from app.intel.base import external_endpoint

    assert external_endpoint("192.168.10.15", "205.174.165.73") == (
        "205.174.165.73",
        "destination",
    )


def test_the_source_wins_when_both_ends_are_routable() -> None:
    """An inbound attack is the more common shape and the attacker is the source."""
    from app.intel.base import external_endpoint

    assert external_endpoint("118.25.6.39", "8.8.8.8") == ("118.25.6.39", "source")


def test_no_endpoint_when_the_whole_flow_is_internal() -> None:
    from app.intel.base import external_endpoint

    assert external_endpoint("192.168.10.5", "192.168.10.50") is None
    assert external_endpoint("172.16.0.1", "10.0.0.7") is None


def test_is_public_ip_rejects_garbage() -> None:
    assert is_public_ip("not-an-ip") is False
    assert is_public_ip("") is False
    assert is_public_ip("8.8.8.8") is True


def test_virustotal_client_exposes_no_hash_lookup() -> None:
    """PLAN T11 — the old code md5'd the signature and queried the file endpoint.

    The digest named no file that has ever existed, so every call was a
    guaranteed 404 rendered to the analyst as a verdict. There is no method here
    that could do it, and the module never references the file endpoint.
    """
    import ast
    import inspect

    import app.intel.virustotal as vt_mod

    # Docstrings and comments are stripped first: the module DOCUMENTS the trap
    # by name, and matching on prose would fail for saying so.
    tree = ast.parse(inspect.getsource(vt_mod))
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            if node.body and isinstance(node.body[0], ast.Expr):
                first = node.body[0].value
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    node.body.pop(0)
    code = ast.unparse(tree).lower()

    assert "/files/" not in code
    assert "md5" not in code
    assert "hashlib" not in code
    assert not [
        name
        for name in dir(VirusTotalClient)
        if not name.startswith("__") and ("hash" in name.lower() or "file" in name.lower())
    ]


def test_a_missing_key_is_skipped_not_faked() -> None:
    client = AbuseIPDBClient(None, 3.0)
    import asyncio

    result = asyncio.run(client.check(PUBLIC))
    assert result.status == "skipped"
    assert result.score is None
