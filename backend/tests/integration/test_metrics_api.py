"""Every right-rail and header number, asserted against a KNOWN FIXTURE SET.

PLAN I2 — no hardcoded metric. The way to prove a number is computed rather
than literal is to change the data and watch the number change with it, so
every test here seeds a specific set of alerts and asserts the value that set
implies. A literal would fail immediately; a plausible-looking constant would
fail as soon as the fixture changed.

What each test replaces (CONTRACT §7.4, the densest cluster of fabrications):

    +18.4%                       -> threat_forecast.change_pct
    x 62 scale on the series     -> signal_velocity, sampled per interval
    window 60m                   -> the real span the samples cover
    3 hot                        -> attack_surface.hot
    08 origins // 08 paths       -> attack_surface.origins / .paths
    10.24.0.0/16                 -> attack_surface.dominant_subnet
    loads 0.82/0.64/0.71/0.45    -> pipeline_activity.nodes[].load
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from httpx import AsyncClient

from app.store.models import Alert, MetricSample
from app.store.session import get_sessionmaker
from tests.conftest import auth_header, login, make_user


def _now() -> datetime:
    """Read the clock PER TEST.

    A module-level constant goes stale: the suite runs for minutes, so a
    fixture written "one minute ago" against an import-time constant can
    land several one-minute buckets in the past and the assertions drift
    with it.
    """
    return datetime.now(UTC)


def _trace(*, reason_status: str = "ok", enrich_status: str = "skipped") -> list[dict]:
    return [
        {"node": "classify", "status": "ok", "duration_ms": 1.0},
        {"node": "enrich", "status": enrich_status, "duration_ms": 0.0},
        {"node": "retrieve", "status": "ok", "duration_ms": 4.0},
        {"node": "reason", "status": reason_status, "duration_ms": 900.0},
        {"node": "recommend", "status": "ok", "duration_ms": 0.5},
        {"node": "rules", "status": "ok", "duration_ms": 0.2},
        {"node": "finalize", "status": "ok", "duration_ms": 0.1},
    ]


async def _seed(rows: list[dict[str, Any]]) -> None:
    async with get_sessionmaker()() as session:
        for index, row in enumerate(rows):
            base: dict[str, Any] = {
                "id": f"ALT-{index:06X}",
                "timestamp": _now(),
                "source": "cicids_replay",
                "severity": "low",
                "attack_type": "benign",
                "src_ip": "10.0.0.1",
                "dest_ip": "192.168.10.50",
                "dest_port": 80,
                "protocol": "TCP",
                "signature": "flow",
                "trace": _trace(),
                "tags": [],
                "rule_trace": [],
            }
            base.update(row)
            session.add(Alert(**base))
        await session.commit()


async def _token(client: AsyncClient, email: str, role: str = "analyst") -> str:
    await make_user(email, role=role)
    return await login(client, email)


async def _rail(client: AsyncClient, token: str) -> dict[str, Any]:
    response = await client.get("/api/v1/metrics/rail", headers=auth_header(token))
    assert response.status_code == 200
    return dict(response.json()["data"])


# ---------------------------------------------------------------------------
# /stats — event velocity (CONTRACT §9.4, PLAN D7)
# ---------------------------------------------------------------------------


async def test_the_timeline_is_bucketed_and_contiguous(client: AsyncClient) -> None:
    token = await _token(client, "stats-shape@example.com")
    await _seed([{"timestamp": _now() - timedelta(minutes=m)} for m in range(0, 6)])

    data = (await client.get("/api/v1/stats", headers=auth_header(token))).json()[
        "data"
    ]

    assert data["window_minutes"] == 30
    assert data["bucket_seconds"] == 60
    assert len(data["timeline"]) == 30, "contiguous — an empty minute is a zero"
    times = [bucket["time"] for bucket in data["timeline"]]
    assert len(set(times)) == 30, "unique — these are React keys"
    for value in times:
        assert value[10] == "T", "sliced as time.slice(11,16) for HH:MM"
    assert sum(bucket["count"] for bucket in data["timeline"]) == 6


async def test_alert_velocity_is_the_mean_over_the_whole_window(
    client: AsyncClient,
) -> None:
    """CONTRACT §9.4 — the MEAN over the window, not the most recent bucket.

    60 alerts, three per minute across the last twenty minutes. The most recent
    bucket holds 3; the mean over the full 30-minute window is 2. The two
    answers differ, which is the only way this test can tell them apart.

    The fixture stays clear of the window's far edge on purpose: a bucket
    boundary can tick over between seeding and querying, and a test that fails
    once a minute is worse than no test.
    """
    token = await _token(client, "stats-mean@example.com")
    await _seed(
        [{"timestamp": _now() - timedelta(minutes=i % 20)} for i in range(60)]
    )

    data = (await client.get("/api/v1/stats", headers=auth_header(token))).json()[
        "data"
    ]
    counts = [bucket["count"] for bucket in data["timeline"]]
    assert data["total_in_window"] == 60
    assert max(counts) == 3, "the busiest bucket"
    assert data["alert_velocity"] == 2, "and the mean over the whole window"


async def test_a_sparse_trailing_bucket_does_not_read_as_zero(
    client: AsyncClient,
) -> None:
    """The reason §9.4 chose the mean.

    All 60 alerts arrived 10-19 minutes ago and none in the last minute. The
    latest bucket is 0; the mean over the window is 2/min. A panel labelled "30
    minute window" showing 0 would look broken.
    """
    token = await _token(client, "stats-sparse@example.com")
    await _seed(
        [
            {"timestamp": _now() - timedelta(minutes=10 + (i % 10))}
            for i in range(60)
        ]
    )

    data = (await client.get("/api/v1/stats", headers=auth_header(token))).json()[
        "data"
    ]
    assert data["timeline"][-1]["count"] == 0, "the trailing bucket really is empty"
    assert data["alert_velocity"] == 2, "and the number under the label is not"


# ---------------------------------------------------------------------------
# threat forecast — PLAN D8
# ---------------------------------------------------------------------------


async def test_the_forecast_is_a_real_window_over_window_delta(
    client: AsyncClient,
) -> None:
    """(current / previous - 1) * 100, on a fixture that makes the answer exact.

    10 alerts in the current 30 minutes against 8 in the previous 30 is
    +25.0%. The hardcoded literal it replaces was +18.4%.
    """
    token = await _token(client, "forecast@example.com")
    rows = [{"timestamp": _now() - timedelta(minutes=1 + i)} for i in range(10)]
    rows += [{"timestamp": _now() - timedelta(minutes=31 + i)} for i in range(8)]
    await _seed(rows)

    forecast = (await _rail(client, token))["threat_forecast"]

    assert forecast["current"] == 10
    assert forecast["previous"] == 8
    assert forecast["change_pct"] == 25.0
    assert forecast["change_pct"] != 18.4


async def test_a_zero_previous_window_reports_null_not_a_number(
    client: AsyncClient,
) -> None:
    """There is no honest percentage change from zero.

    Inventing one is how +18.4% got there in the first place.
    """
    token = await _token(client, "forecast-zero@example.com")
    await _seed([{"timestamp": _now() - timedelta(minutes=1)}])

    forecast = (await _rail(client, token))["threat_forecast"]
    assert forecast["change_pct"] is None
    assert forecast["previous"] == 0
    assert "no percentage change" in forecast["note"]


# ---------------------------------------------------------------------------
# signal velocity — sampled, not re-bucketed
# ---------------------------------------------------------------------------


async def test_signal_velocity_reads_the_sampled_series(
    client: AsyncClient,
) -> None:
    token = await _token(client, "velocity@example.com")
    async with get_sessionmaker()() as session:
        for minutes, rate in ((6, 12.0), (4, 30.0), (2, 18.0)):
            session.add(
                MetricSample(
                    observed_at=_now() - timedelta(minutes=minutes),
                    alerts_per_minute=rate,
                    window_seconds=60,
                )
            )
        await session.commit()

    velocity = (await _rail(client, token))["signal_velocity"]

    assert velocity["sample_count"] == 3
    assert velocity["now_per_min"] == 18.0, "the latest observation"
    assert velocity["peak_per_min"] == 30.0, "the highest observation"
    assert velocity["window_minutes"] == 4.0, "the REAL span the samples cover"
    assert velocity["window_minutes"] != 60, "not the hardcoded `window 60m`"
    assert velocity["configured_window_minutes"] == 60
    # Both branches of the payload carry the same keys — see the empty-series
    # test below for the other half.
    assert velocity["note"] is None
    assert [s["alerts_per_minute"] for s in velocity["samples"]] == [12.0, 30.0, 18.0]


async def test_an_empty_series_says_so_rather_than_drawing_a_flat_line(
    client: AsyncClient,
) -> None:
    token = await _token(client, "velocity-empty@example.com")
    velocity = (await _rail(client, token))["signal_velocity"]

    assert velocity["sample_count"] == 0
    assert velocity["samples"] == []
    assert velocity["window_minutes"] == 0.0, "no samples cover no span"
    assert "genuinely empty" in velocity["note"]


# ---------------------------------------------------------------------------
# attack surface
# ---------------------------------------------------------------------------


async def test_origins_paths_hot_and_subnet_are_all_measured(
    client: AsyncClient,
) -> None:
    """Replaces `3 hot`, `08 origins // 08 paths` and `10.24.0.0/16`."""
    token = await _token(client, "surface@example.com")
    await _seed(
        [
            {"src_ip": "1.1.1.1", "dest_ip": "10.24.0.5", "dest_port": 80, "severity": "high"},
            {"src_ip": "1.1.1.1", "dest_ip": "10.24.0.5", "dest_port": 443, "severity": "high"},
            {"src_ip": "2.2.2.2", "dest_ip": "10.24.0.6", "dest_port": 80, "severity": "low"},
            {"src_ip": "3.3.3.3", "dest_ip": "10.99.0.1", "dest_port": 22, "severity": "critical"},
        ]
    )

    surface = (await _rail(client, token))["attack_surface"]

    assert surface["origins"] == 3, "three distinct source IPs"
    assert surface["paths"] == 4, "four distinct src->dest:port triples"
    assert surface["hot"] == 3, "two high plus one critical"
    assert surface["dominant_subnet"] == "10.24.0.0/16", "measured, not invented"
    assert len(surface["nodes"]) == 3
    assert surface["nodes"][0]["src_ip"] == "1.1.1.1", "busiest first"


async def test_hot_changes_with_the_data(client: AsyncClient) -> None:
    """`3 hot` was a literal, so the only proof is that it is not always 3."""
    token = await _token(client, "surface-hot@example.com")
    await _seed([{"src_ip": "9.9.9.9", "severity": "low"}])

    surface = (await _rail(client, token))["attack_surface"]
    assert surface["hot"] == 0
    assert surface["origins"] == 1
    assert surface["paths"] == 1


# ---------------------------------------------------------------------------
# pipeline activity — PLAN D9 / FE-4
# ---------------------------------------------------------------------------


async def test_pipeline_load_is_the_real_share_of_alerts_a_node_worked_on(
    client: AsyncClient,
) -> None:
    """Replaces the loads 0.82 / 0.64 / 0.71 / 0.45.

    Four alerts: `enrich` ran on one of them and was skipped on three, so its
    load is exactly 0.25. `classify` ran on all four, so its load is 1.0.
    """
    token = await _token(client, "pipeline@example.com")
    await _seed(
        [
            {"trace": _trace(enrich_status="ok")},
            {"trace": _trace(enrich_status="skipped")},
            {"trace": _trace(enrich_status="skipped")},
            {"trace": _trace(enrich_status="skipped", reason_status="failed")},
        ]
    )

    activity = (await _rail(client, token))["pipeline_activity"]
    nodes = {node["name"]: node for node in activity["nodes"]}

    assert activity["sampled_alerts"] == 4
    assert nodes["classify"]["load"] == 1.0
    assert nodes["enrich"]["load"] == 0.25
    assert nodes["enrich"]["skipped"] == 3
    assert nodes["reason"]["failed"] == 1
    assert nodes["reason"]["ok"] == 3
    assert nodes["classify"]["state"] == "active"
    assert nodes["classify"]["mean_duration_ms"] == 1.0


async def test_the_node_names_come_from_the_graph_itself(
    client: AsyncClient,
) -> None:
    """PLAN D9 — truthful names, and they cannot drift from the pipeline."""
    from app.agent.state import NodeName

    token = await _token(client, "pipeline-names@example.com")
    activity = (await _rail(client, token))["pipeline_activity"]

    assert [node["name"] for node in activity["nodes"]] == [n.value for n in NodeName]
    invented = {"sentinel-alpha", "cortex-03", "sentinel-beta", "reasoner-01"}
    assert not invented & {node["name"] for node in activity["nodes"]}


async def test_a_node_that_never_ran_is_idle_at_zero(client: AsyncClient) -> None:
    token = await _token(client, "pipeline-idle@example.com")
    activity = (await _rail(client, token))["pipeline_activity"]

    assert activity["sampled_alerts"] == 0
    assert all(node["load"] == 0.0 for node in activity["nodes"])
    assert all(node["state"] == "idle" for node in activity["nodes"])


# ---------------------------------------------------------------------------
# header counters, ticker and search
# ---------------------------------------------------------------------------


async def test_counters_are_computed_over_the_active_filter_set(
    client: AsyncClient,
) -> None:
    """PLAN §3.1 — over the ACTIVE FILTER SET.

    The frozen frontend counts its unfiltered 200-alert buffer, so its
    TOTAL/HIGH/MEDIUM disagree with the table as soon as a filter is on.
    """
    token = await _token(client, "counters@example.com")
    await _seed(
        [
            {"severity": "high", "attack_type": "dos"},
            {"severity": "high", "attack_type": "ddos"},
            {"severity": "medium", "attack_type": "port_scan"},
            {"severity": "low", "attack_type": "benign"},
            {"severity": "unknown", "attack_type": "unknown"},
        ]
    )

    everything = (
        await client.get("/api/v1/metrics/overview", headers=auth_header(token))
    ).json()["data"]
    assert everything["total"] == 5
    assert everything["by_severity"]["high"] == 2
    assert everything["by_severity"]["unknown"] == 1

    filtered = (
        await client.get(
            "/api/v1/metrics/overview?severity=high", headers=auth_header(token)
        )
    ).json()["data"]
    assert filtered["total"] == 2
    assert filtered["by_severity"]["medium"] == 0


async def test_the_ticker_is_the_highest_severity_alert(
    client: AsyncClient,
) -> None:
    token = await _token(client, "ticker@example.com")
    await _seed(
        [
            {"severity": "low", "signature": "quiet"},
            {"severity": "critical", "signature": "loud", "dest_ip": "10.0.0.9"},
            {"severity": "medium", "signature": "middling"},
        ]
    )

    overview = (
        await client.get("/api/v1/metrics/overview", headers=auth_header(token))
    ).json()["data"]

    assert overview["ticker"]["severity"] == "critical"
    assert overview["ticker"]["signature"] == "loud"
    assert overview["ticker"]["dest_ip"] == "10.0.0.9"


async def test_the_ticker_is_null_when_there_is_nothing_to_show(
    client: AsyncClient,
) -> None:
    token = await _token(client, "ticker-empty@example.com")
    overview = (
        await client.get("/api/v1/metrics/overview", headers=auth_header(token))
    ).json()["data"]
    assert overview["ticker"] is None
    assert overview["total"] == 0


async def test_unified_search_covers_all_four_fields(client: AsyncClient) -> None:
    """PLAN §3.1 — source IP, dest IP, alert ID and signature."""
    token = await _token(client, "search@example.com")
    await _seed(
        [
            {"src_ip": "203.0.113.7", "signature": "port sweep"},
            {"dest_ip": "198.51.100.2", "signature": "credential stuffing"},
        ]
    )

    async def _count(term: str) -> int:
        body = (
            await client.get(
                f"/api/v1/metrics/overview?search={term}", headers=auth_header(token)
            )
        ).json()["data"]
        return int(body["total"])

    assert await _count("203.0.113.7") == 1, "source IP"
    assert await _count("198.51.100.2") == 1, "destination IP"
    assert await _count("ALT-000000") == 1, "alert id"
    assert await _count("stuffing") == 1, "signature"
    assert await _count("nothing-matches-this") == 0
