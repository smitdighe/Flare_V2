"""Failure injection — intel, the database and the queues. PLAN §12.

The theme is the same as the provider file: each failure has to stay
*distinguishable*. An intel source that timed out and an intel source that
answered "clean" must never render the same, because one of them is a fact about
the address and the other is a fact about the network — and a build that
defaults a failed lookup to score 0 renders "we could not check" as "we checked
and it is fine".
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest

from app.config import get_settings
from app.intel.aggregator import IntelAggregator
from app.workers.queue import BoundedQueue, QueueFullError

pytestmark = pytest.mark.failure


# ---------------------------------------------------------------------------
# intel
# ---------------------------------------------------------------------------

ABUSE_OK = {
    "data": {"abuseConfidenceScore": 92, "totalReports": 40, "countryCode": "NL"}
}
VT_OK = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 7,
                "suspicious": 1,
                "harmless": 60,
                "undetected": 12,
            }
        }
    }
}


@pytest.fixture
def intel(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    """Route both intel clients through one MockTransport handler."""
    import app.intel.abuseipdb as abuse_mod
    import app.intel.virustotal as vt_mod

    slot: dict[str, object] = {}
    real = httpx.AsyncClient

    class _Client(real):  # type: ignore[misc,valid-type]
        def __init__(self, **kwargs: object) -> None:
            handler = slot["handler"]
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(abuse_mod.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(vt_mod.httpx, "AsyncClient", _Client)
    yield slot


def aggregator() -> IntelAggregator:
    return IntelAggregator(
        get_settings().model_copy(
            update={
                "abuseipdb_api_key": "fake-abuse-key",
                "virustotal_api_key": "fake-vt-key",
                "intel_timeout_seconds": 5.0,
            }
        )
    )


async def test_intel_partial_failure_keeps_the_source_that_answered(intel) -> None:
    """One source down is a DEGRADED verdict, not a missing one."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "abuseipdb" in str(request.url):
            return httpx.Response(200, json=ABUSE_OK)
        return httpx.Response(500, text="virustotal is having a day")

    intel["handler"] = handler
    verdict = await aggregator().lookup("205.174.165.73")

    assert verdict.checked is True, "one source answered — the lookup happened"
    assert verdict.score == 92, "the answer that arrived is used, not discarded"
    assert verdict.degraded is True, "and the half that failed is declared"
    assert verdict.sources_ok == ["abuseipdb"]
    assert verdict.sources_failed == ["virustotal"]
    assert "failed: virustotal" in verdict.note()


async def test_a_partial_failure_is_never_cached(intel) -> None:
    """T12 — caching a degraded verdict pins a transient outage for the TTL."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "abuseipdb" in str(request.url):
            return httpx.Response(200, json=ABUSE_OK)
        return httpx.Response(503, text="unavailable")

    intel["handler"] = handler
    agg = aggregator()
    first = await agg.lookup("205.174.165.73")
    before = len(calls)
    second = await agg.lookup("205.174.165.73")

    assert first.degraded and second.degraded
    assert second.cached is False
    assert len(calls) > before, "the second lookup went back to the network"


async def test_intel_total_failure_is_unchecked_and_scoreless(intel) -> None:
    """PLAN — a failed lookup has NO score. Defaulting to 0 renders 'we could
    not check' as 'we checked and it is clean', which is the worse of the two
    possible lies."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="both sources are down")

    intel["handler"] = handler
    verdict = await aggregator().lookup("205.174.165.73")

    assert verdict.checked is False
    assert verdict.score is None, "not 0 — there is no score to report"
    assert verdict.malicious is False
    assert verdict.degraded is True
    assert sorted(verdict.sources_failed) == ["abuseipdb", "virustotal"]


async def test_intel_timeout_is_a_failed_source_not_a_hang(intel) -> None:
    """PLAN I7 — every intel call carries a timeout and the timeout is handled."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    intel["handler"] = handler
    verdict = await aggregator().lookup("205.174.165.73")

    assert verdict.checked is False
    assert verdict.score is None
    assert verdict.degraded is True


async def test_a_429_from_intel_is_rate_limited_not_a_clean_verdict(intel) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "abuseipdb" in str(request.url):
            return httpx.Response(429, text="quota exceeded")
        return httpx.Response(200, json=VT_OK)

    intel["handler"] = handler
    verdict = await aggregator().lookup("205.174.165.73")

    statuses = {r.source: r.status for r in verdict.results}
    assert statuses["abuseipdb"] == "rate_limited"
    assert statuses["virustotal"] == "ok"
    assert verdict.degraded is True
    for result in verdict.results:
        if result.status != "ok":
            assert result.score is None


async def test_malformed_intel_json_does_not_crash_the_lookup(intel) -> None:
    """A source that answers 200 with a shape we do not recognise is a failed
    source, exactly like I18 on the LLM side."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>we moved</html>")

    intel["handler"] = handler
    verdict = await aggregator().lookup("205.174.165.73")

    assert verdict.score is None
    assert verdict.checked is False


# ---------------------------------------------------------------------------
# database
# ---------------------------------------------------------------------------


async def test_a_locked_database_is_counted_and_never_a_silent_drop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SQLite raises OperationalError('database is locked') under contention.

    The property under test is that a persistence failure is COUNTED and stays
    visible on `/health/deep`. A feed that swallows a write failure keeps
    streaming alerts to the screen that are not in the database, and the two
    views disagree with nothing anywhere saying so.
    """
    import sqlalchemy.exc

    import app.ingestion.feed as feed_mod
    from app.ingestion.feed import FeedService

    feed = FeedService()
    before = feed.stats()["persist_failures"]

    async def locked(*_args: object, **_kwargs: object) -> object:
        raise sqlalchemy.exc.OperationalError(
            "INSERT INTO alerts ...", {}, Exception("database is locked")
        )

    monkeypatch.setattr(feed_mod, "upsert_alert", locked)

    stored = await feed._persist(_normalized_alert())

    assert stored is None, "the caller is told the write did not happen"
    assert feed.stats()["persist_failures"] == before + 1, (
        "the failure is counted, and /health/deep reads this counter"
    )


async def test_a_locked_database_on_a_read_is_not_a_leaked_stack_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An operational failure must not put SQL or internals in a response body.

    A dedicated client with `raise_app_exceptions=False` is used because the
    shared `client` fixture re-raises server exceptions into the test — which is
    the right default for finding bugs and the wrong one here, where the
    RESPONSE the app produced is the thing under test.
    """
    import sqlalchemy.exc
    from httpx import ASGITransport, AsyncClient

    import app.api.routes.alerts as alerts_mod
    from app.main import create_app
    from tests.conftest import auth_header, login, make_user

    transport = ASGITransport(app=create_app(), raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        await make_user("locked@example.com")
        token = await login(http, "locked@example.com")

        async def boom(*_args: object, **_kwargs: object) -> object:
            raise sqlalchemy.exc.OperationalError(
                "SELECT alerts.id FROM alerts", {}, Exception("database is locked")
            )

        monkeypatch.setattr(alerts_mod, "list_alerts", boom)
        response = await http.get("/api/v1/alerts", headers=auth_header(token))

    assert response.status_code == 500, response.text
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "internal_error"
    # PLAN §9 / T13 — the caller is told an error occurred, never shown the query.
    assert "SELECT alerts.id" not in response.text
    assert "OperationalError" not in response.text
    assert "database is locked" not in response.text


def _normalized_alert():
    """A minimal NormalizedAlert, built the way the ingestion path builds one."""
    from app.ingestion.normalize import NormalizedAlert

    return NormalizedAlert(
        id="ALT-000001",
        timestamp=datetime(2017, 7, 7, 9, 0, tzinfo=UTC),
        source="cicids_replay",
        severity="critical",
        attack_type="botnet",
        src_ip="205.174.165.73",
        dest_ip="192.168.10.15",
        dest_port=8080,
        protocol="TCP",
        signature="Botnet C2 beacon",
    )


# ---------------------------------------------------------------------------
# queues
# ---------------------------------------------------------------------------


def test_a_full_queue_drops_and_counts_rather_than_growing() -> None:
    """PLAN §12 load rule, asserted as a failure case at unit level."""
    queue: BoundedQueue[int] = BoundedQueue("triage", 3)

    for item in range(3):
        queue.put_nowait(item)

    for item in range(3, 10):
        with pytest.raises(QueueFullError):
            queue.put_nowait(item)

    stats = queue.stats()
    assert stats.depth == 3, "bounded — it never grew past maxsize"
    assert stats.accepted == 3
    assert stats.dropped == 7, "every rejection is counted, not swallowed"


def test_a_queue_full_error_names_the_queue_and_its_size() -> None:
    """The 503 an operator sees has to say WHICH queue and how big it is."""
    queue: BoundedQueue[int] = BoundedQueue("enrich", 2)
    queue.put_nowait(1)
    queue.put_nowait(2)

    with pytest.raises(QueueFullError) as caught:
        queue.put_nowait(3)

    assert caught.value.name == "enrich"
    assert caught.value.maxsize == 2
    assert "enrich" in str(caught.value)
    assert "2" in str(caught.value)


def test_a_full_queue_recovers_the_moment_a_slot_is_returned() -> None:
    """Full is a state, not a death. The next release admits the next item."""
    queue: BoundedQueue[int] = BoundedQueue("triage", 1)
    queue.put_nowait(1)
    with pytest.raises(QueueFullError):
        queue.put_nowait(2)

    queue.release()
    queue.put_nowait(3)

    assert queue.stats().accepted == 2
    assert queue.stats().dropped == 1
