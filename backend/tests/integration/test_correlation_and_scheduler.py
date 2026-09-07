"""Threat clusters and the scheduler that computes them.

PLAN §3.1 / §4.1 / T14.

`GET /alerts/clusters` READS the correlation job's stored output; it does not
recompute. That is what makes the job load-bearing rather than decorative — a
job that aggregated and discarded would be visible here as an empty screen
instead of being invisible. Both halves are asserted: the job writes rows, and
the endpoint serves them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from httpx import AsyncClient
from sqlalchemy import func, select

from app.store.models import Alert, AlertCluster, JobRun, MetricSample
from app.store.session import get_sessionmaker
from app.workers.scheduler import JOBS, run_job
from tests.conftest import auth_header, login, make_user


def _now() -> datetime:
    """Read the clock PER TEST.

    A module-level constant goes stale: the suite runs for minutes, so a
    fixture written "one minute ago" against an import-time constant can
    land several one-minute buckets in the past and the assertions drift
    with it.
    """
    return datetime.now(UTC)


async def _seed(rows: list[dict[str, Any]]) -> None:
    async with get_sessionmaker()() as session:
        for index, row in enumerate(rows):
            base: dict[str, Any] = {
                "id": f"ALT-{index:06X}",
                "timestamp": _now() - timedelta(minutes=1),
                "source": "cicids_replay",
                "severity": "medium",
                "attack_type": "port_scan",
                "src_ip": "10.0.0.1",
                "dest_ip": "192.168.10.50",
                "dest_port": 80,
                "protocol": "TCP",
                "signature": "flow",
                "trace": [],
                "tags": [],
                "rule_trace": [],
            }
            base.update(row)
            session.add(Alert(**base))
        await session.commit()


async def _token(client: AsyncClient, email: str, role: str = "analyst") -> str:
    await make_user(email, role=role)
    return await login(client, email)


async def _clusters(
    client: AsyncClient, token: str, query: str = ""
) -> dict[str, Any]:
    response = await client.get(
        f"/api/v1/alerts/clusters{query}", headers=auth_header(token)
    )
    assert response.status_code == 200
    return dict(response.json()["data"])


# ---------------------------------------------------------------------------
# correlation
# ---------------------------------------------------------------------------


async def test_the_threshold_is_real_and_a_single_alert_is_not_a_cluster(
    client: AsyncClient,
) -> None:
    """CONTRACT §5.7 — the frozen frontend calls every source IP a cluster.

    Four alerts from one IP and one from another, at the default floor of 3:
    exactly one cluster.
    """
    token = await _token(client, "cluster-threshold@example.com")
    await _seed(
        [{"src_ip": "203.0.113.9"} for _ in range(4)]
        + [{"src_ip": "198.51.100.4"}]
    )
    await run_job("correlation.refresh", trigger="manual")

    data = await _clusters(client, token)

    assert data["min_alerts"] == 3
    assert len(data["clusters"]) == 1
    assert data["clusters"][0]["src_ip"] == "203.0.113.9"
    assert data["clusters"][0]["alert_count"] == 4


async def test_min_alerts_is_honoured_from_the_query(client: AsyncClient) -> None:
    token = await _token(client, "cluster-minalerts@example.com")
    await _seed(
        [{"src_ip": "203.0.113.9"} for _ in range(4)]
        + [{"src_ip": "198.51.100.4"} for _ in range(2)]
    )
    await run_job("correlation.refresh", trigger="manual")

    assert len((await _clusters(client, token, "?min_alerts=1"))["clusters"]) == 2
    assert len((await _clusters(client, token, "?min_alerts=4"))["clusters"]) == 1
    assert len((await _clusters(client, token, "?min_alerts=5"))["clusters"]) == 0


async def test_a_cluster_carries_its_dominant_type_and_worst_severity(
    client: AsyncClient,
) -> None:
    token = await _token(client, "cluster-shape@example.com")
    await _seed(
        [
            {"src_ip": "203.0.113.9", "attack_type": "port_scan", "severity": "medium"},
            {"src_ip": "203.0.113.9", "attack_type": "port_scan", "severity": "low"},
            {"src_ip": "203.0.113.9", "attack_type": "ddos", "severity": "critical"},
        ]
    )
    await run_job("correlation.refresh", trigger="manual")

    cluster = (await _clusters(client, token))["clusters"][0]

    assert cluster["alert_count"] == 3
    assert cluster["dominant_attack_type"] == "port_scan", "2 of 3"
    assert sorted(cluster["attack_types"]) == ["ddos", "port_scan"]
    assert cluster["max_severity"] == "critical", "the worst one seen"
    assert cluster["first_seen"][10] == "T"


async def test_the_endpoint_serves_stored_rows_not_a_live_reduce(
    client: AsyncClient,
) -> None:
    """PLAN §3.1 — "served from the DB".

    Seeding alerts and NOT running the job leaves the screen empty. That is the
    honest consequence of the endpoint reading stored output, and it is what
    makes a job that stopped running visible rather than invisible.
    """
    token = await _token(client, "cluster-stored@example.com")
    await _seed([{"src_ip": "203.0.113.9"} for _ in range(5)])

    before = await _clusters(client, token)
    assert before["clusters"] == []
    assert before["computed_at"] is None

    await run_job("correlation.refresh", trigger="manual")

    after = await _clusters(client, token)
    assert len(after["clusters"]) == 1
    assert after["computed_at"] is not None


async def test_a_refresh_replaces_rather_than_accumulates(
    client: AsyncClient,
) -> None:
    """An IP that has dropped out of the window is no longer a cluster."""
    token = await _token(client, "cluster-replace@example.com")
    await _seed([{"src_ip": "203.0.113.9"} for _ in range(4)])
    await run_job("correlation.refresh", trigger="manual")
    assert len((await _clusters(client, token))["clusters"]) == 1

    async with get_sessionmaker()() as session:
        from sqlalchemy import delete

        await session.execute(delete(Alert))
        await session.commit()

    await run_job("correlation.refresh", trigger="manual")
    assert (await _clusters(client, token))["clusters"] == []


# ---------------------------------------------------------------------------
# the scheduler — PLAN T14
# ---------------------------------------------------------------------------


async def test_every_job_persists_what_it_computes(client: AsyncClient) -> None:
    """A job that aggregates and discards is the defect this asserts against."""
    await _seed([{"src_ip": "203.0.113.9"} for _ in range(3)])

    for name in JOBS:
        record = await run_job(name, trigger="manual")
        assert record.status == "ok", record.error
        assert record.result is not None, f"{name} recorded nothing it computed"
        assert record.duration_ms >= 0

    async with get_sessionmaker()() as session:
        clusters = (
            await session.execute(select(func.count()).select_from(AlertCluster))
        ).scalar_one()
        samples = (
            await session.execute(select(func.count()).select_from(MetricSample))
        ).scalar_one()
    assert clusters == 1, "correlation.refresh wrote rows"
    assert samples == 1, "metrics.sample wrote a row"


async def test_a_job_run_leaves_a_receipt(client: AsyncClient) -> None:
    admin = await _token(client, "job-receipt@example.com", role="admin")
    await run_job("metrics.sample", trigger="schedule")

    body = (
        await client.get("/api/v1/admin/jobs", headers=auth_header(admin))
    ).json()["data"]

    assert sorted(body["known_jobs"]) == sorted(JOBS)
    assert body["jobs"][0]["job"] == "metrics.sample"
    assert body["jobs"][0]["status"] == "ok"
    assert body["jobs"][0]["trigger"] == "schedule"
    assert "alerts_per_minute" in body["jobs"][0]["result"]


async def test_a_job_run_is_audited(client: AsyncClient) -> None:
    """PLAN §4.1 — every state-changing operation, INCLUDING job triggers."""
    admin = await _token(client, "job-audit@example.com", role="admin")
    await run_job("metrics.sample", trigger="schedule")

    logs = (
        await client.get("/api/v1/audit/logs?action=job.run", headers=auth_header(admin))
    ).json()["data"]
    assert logs["total"] >= 1
    assert logs["logs"][0]["resource_id"] == "metrics.sample"


async def test_a_manual_trigger_carries_the_operator_s_id(
    client: AsyncClient,
) -> None:
    """A scheduled run has no actor; a manual one does. That is the difference
    between "the timer fired" and "somebody asked for this"."""
    admin = await _token(client, "job-manual@example.com", role="admin")
    response = await client.post(
        "/api/v1/admin/jobs/metrics.sample/run", headers=auth_header(admin)
    )
    assert response.status_code == 200
    assert response.json()["data"]["trigger"] == "manual"

    logs = (
        await client.get(
            "/api/v1/audit/logs?action=job.run", headers=auth_header(admin)
        )
    ).json()["data"]["logs"]
    assert logs[0]["actor_id"] is not None


async def test_only_an_admin_can_trigger_a_job(client: AsyncClient) -> None:
    token = await _token(client, "job-viewer@example.com", role="viewer")
    response = await client.post(
        "/api/v1/admin/jobs/metrics.sample/run", headers=auth_header(token)
    )
    assert response.status_code == 403


async def test_an_unknown_job_is_a_404(client: AsyncClient) -> None:
    admin = await _token(client, "job-404@example.com", role="admin")
    response = await client.post(
        "/api/v1/admin/jobs/does.not.exist/run", headers=auth_header(admin)
    )
    assert response.status_code == 404
    assert "Known jobs" in response.json()["detail"]


async def test_a_failing_job_records_the_exception_and_does_not_propagate(
    client: AsyncClient, monkeypatch
) -> None:
    """A scheduler that dies on one bad run takes a screen down with it."""

    async def _boom(session: Any, settings: Any) -> dict[str, Any]:
        raise RuntimeError("the correlation query exploded")

    monkeypatch.setitem(JOBS, "correlation.refresh", _boom)
    record = await run_job("correlation.refresh", trigger="manual")

    assert record.status == "failed"
    assert "the correlation query exploded" in (record.error or "")
    assert record.result is None

    async with get_sessionmaker()() as session:
        stored = (
            await session.execute(
                select(JobRun).where(JobRun.status == "failed")
            )
        ).scalars().all()
    assert len(stored) == 1
