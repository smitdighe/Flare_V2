"""GET /alerts — the FE-6 hydration endpoint.

CONTRACT §2.10 / §8.8: enveloped, newest-first, same Alert schema the
WebSocket pushes so the merge is a concat plus a de-dupe on `id`.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient

from app.ingestion.normalize import parse_cicids_row
from app.store.repositories import upsert_alert
from app.store.session import get_sessionmaker
from tests.conftest import auth_header, login, make_user

SPLITS = Path(__file__).resolve().parents[2] / "data" / "splits"
REPLAY_CSV = SPLITS / "replay.csv"

needs_data = pytest.mark.skipif(
    not REPLAY_CSV.exists(),
    reason="partitions not built — run scripts.fetch_dataset then scripts.build_partitions",
)

# Every key the frozen frontend's render path reads, per CONTRACT §4.
CONTRACT_KEYS = {
    "id",
    "timestamp",
    "source",
    "severity",
    "attack_type",
    "src_ip",
    "dest_ip",
    "dest_port",
    "protocol",
    "signature",
    "mitre_technique",
    "ioc_checked",
    "ioc_reputation",
    "vt_ip",
    "vt_hash",
    "explanation",
    "remediation",
    "classify_latency_ms",
    "enrich_latency_ms",
    "reasoning_latency_ms",
    "trace",
    "confidence",
    "degraded",
    # PLAN §4.1 Phase 4 — written by the `add_tag` rule action. Not rendered by
    # the frozen frontend, but it has a real producer, so it is on the payload.
    "tags",
    # PLAN §4.1 Phase 4 — the per-condition fire trace, surfaced on the alert
    # itself as well as on explain-rules. Same stored column, so the two views
    # cannot disagree.
    "rule_trace",
}


async def _seed_alerts(count: int) -> list[str]:
    """Persist `count` real replay rows, oldest first, one second apart."""
    with REPLAY_CSV.open(encoding="utf-8", newline="") as handle:
        rows = [r for _, r in zip(range(count), csv.DictReader(handle), strict=False)]

    base = datetime.now(UTC) - timedelta(seconds=count)
    ids: list[str] = []
    async with get_sessionmaker()() as session:
        for index, row in enumerate(rows):
            alert = parse_cicids_row(
                row, timestamp=base + timedelta(seconds=index)
            )
            await upsert_alert(session, alert)
            ids.append(alert.id)
        await session.commit()
    return ids


@needs_data
async def test_alerts_requires_authentication(client: AsyncClient) -> None:
    response = await client.get("/api/v1/alerts")
    assert response.status_code == 401


@needs_data
async def test_alerts_is_enveloped(client: AsyncClient) -> None:
    await _seed_alerts(5)
    await make_user("feed@example.com")
    token = await login(client, "feed@example.com")

    response = await client.get("/api/v1/alerts", headers=auth_header(token))

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"ok", "data", "meta"}
    assert body["ok"] is True
    assert body["meta"]["latency_ms"] > 0
    assert set(body["data"]) == {"alerts", "total", "limit", "offset"}
    assert body["data"]["total"] == 5


@needs_data
async def test_alert_payload_matches_the_contract_schema(client: AsyncClient) -> None:
    await _seed_alerts(3)
    await make_user("shape@example.com")
    token = await login(client, "shape@example.com")

    alerts = (
        await client.get("/api/v1/alerts", headers=auth_header(token))
    ).json()["data"]["alerts"]

    assert alerts
    for alert in alerts:
        assert set(alert) == CONTRACT_KEYS
        assert alert["id"].startswith("ALT-")
        assert alert["source"] == "cicids_replay"
        assert alert["severity"] in {"critical", "high", "medium", "low", "unknown"}
        assert isinstance(alert["trace"], list)
        assert isinstance(alert["dest_port"], int)
        # PLAN I4 — the label never travels with a rendered alert.
        assert "ground_truth_class" not in alert
        assert "row_id" not in alert


@needs_data
async def test_alerts_are_newest_first(client: AsyncClient) -> None:
    """CONTRACT §8.8 — matches the WS prepend so the merged buffer is ordered."""
    await _seed_alerts(10)
    await make_user("order@example.com")
    token = await login(client, "order@example.com")

    alerts = (
        await client.get("/api/v1/alerts", headers=auth_header(token))
    ).json()["data"]["alerts"]

    stamps = [a["timestamp"] for a in alerts]
    assert stamps == sorted(stamps, reverse=True), "newest first"


@needs_data
async def test_alerts_pagination(client: AsyncClient) -> None:
    await _seed_alerts(12)
    await make_user("page@example.com")
    token = await login(client, "page@example.com")

    first = (
        await client.get(
            "/api/v1/alerts?limit=5&offset=0", headers=auth_header(token)
        )
    ).json()["data"]
    second = (
        await client.get(
            "/api/v1/alerts?limit=5&offset=5", headers=auth_header(token)
        )
    ).json()["data"]

    assert first["total"] == 12 and second["total"] == 12
    assert len(first["alerts"]) == 5
    assert len(second["alerts"]) == 5
    assert {a["id"] for a in first["alerts"]}.isdisjoint(
        {a["id"] for a in second["alerts"]}
    )


@needs_data
async def test_alerts_severity_filter_and_post_filter_total(
    client: AsyncClient,
) -> None:
    await _seed_alerts(30)
    await make_user("filter@example.com")
    token = await login(client, "filter@example.com")

    everything = (
        await client.get("/api/v1/alerts", headers=auth_header(token))
    ).json()["data"]
    high = (
        await client.get(
            "/api/v1/alerts?severity=high", headers=auth_header(token)
        )
    ).json()["data"]

    assert all(a["severity"] == "high" for a in high["alerts"])
    assert high["total"] <= everything["total"]

    # PLAN §12 — this was `total == len or total > len`, which is `total >= len`
    # and could only have failed if the page were LONGER than the set it pages.
    # The property worth pinning is that `total` counts the whole FILTERED set
    # while `alerts` is one capped page of it, and that the filter is applied on
    # the server rather than to the page.
    assert len(high["alerts"]) <= high["total"], (
        "a page can never contain more rows than the set it pages"
    )
    assert high["total"] == sum(
        1 for a in everything["alerts"] if a["severity"] == "high"
    ), (
        "the filtered total is the count of high-severity rows in the whole "
        "set — a server that filtered only the PAGE would report the "
        "unfiltered total here"
    )
    assert len(high["alerts"]) == high["total"], (
        "the seeded set is smaller than one page, so the page IS the set"
    )


@needs_data
async def test_alerts_search_matches_source_ip(client: AsyncClient) -> None:
    await _seed_alerts(10)
    await make_user("search@example.com")
    token = await login(client, "search@example.com")

    everything = (
        await client.get("/api/v1/alerts", headers=auth_header(token))
    ).json()["data"]["alerts"]
    needle = everything[0]["src_ip"]

    found = (
        await client.get(
            f"/api/v1/alerts?search={needle}", headers=auth_header(token)
        )
    ).json()["data"]["alerts"]

    assert found
    assert all(needle in (a["src_ip"] + a["dest_ip"]) for a in found)


@needs_data
async def test_limit_is_capped(client: AsyncClient) -> None:
    await make_user("cap@example.com")
    token = await login(client, "cap@example.com")
    response = await client.get("/api/v1/alerts?limit=5000", headers=auth_header(token))
    assert response.status_code == 422, "a hard limit cap is enforced"


@needs_data
async def test_persistence_is_idempotent_on_id(client: AsyncClient) -> None:
    """Replay loops over the same partition; a second pass must not duplicate."""
    ids = await _seed_alerts(6)
    await _seed_alerts(6)

    await make_user("dupe@example.com")
    token = await login(client, "dupe@example.com")
    data = (
        await client.get("/api/v1/alerts", headers=auth_header(token))
    ).json()["data"]

    assert data["total"] == len(set(ids))
