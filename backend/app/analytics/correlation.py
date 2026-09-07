"""Source-IP correlation. PLAN §3.1 / CONTRACT §5.7.

**SERVED FROM THE DATABASE, WITH A REAL THRESHOLD.** The frozen frontend
reduces its 200-alert buffer client-side and calls every source IP with one
alert a "cluster" (WorkspacePanel.jsx:498) — so the screen shows whatever
happens to be in the buffer, a single alert counts as a correlation, and
anything older than the buffer is invisible. This computes over the whole
alerts table inside a window, applies a real `min_alerts` floor, and stores the
result.

**THE JOB IS LOAD-BEARING.** `GET /alerts/clusters` reads `alert_clusters`; it
does not recompute. That is deliberate — a scheduled job whose output nothing
reads is the "aggregate and discard" defect (PLAN T14), and wiring the endpoint
to the table is what makes the job's absence visible instead of invisible. The
job also runs once at startup so the screen is never empty for want of a timer.

**THE AGGREGATION IS SQL, NOT PYTHON.** One GROUP BY over
(src_ip, attack_type, severity) returns at most `distinct IPs x 6 x 5` rows on
this dataset, and the fold that turns those into clusters runs over group rows
rather than over alerts. Pulling every alert into the process to reduce it here
would be the same client-side reduce one layer down.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ingestion.labels import severity_rank
from app.store.models import Alert, AlertCluster, as_utc


async def compute_clusters(
    session: AsyncSession, *, window_minutes: int, min_alerts: int
) -> list[dict[str, Any]]:
    """Group the window's alerts by source IP. Returns the ones over the floor."""
    since = datetime.now(UTC) - timedelta(minutes=window_minutes)

    rows = (
        await session.execute(
            select(
                Alert.src_ip,
                Alert.attack_type,
                Alert.severity,
                func.count().label("n"),
                func.min(Alert.timestamp).label("first_seen"),
                func.max(Alert.timestamp).label("last_seen"),
            )
            .where(Alert.timestamp >= since)
            .group_by(Alert.src_ip, Alert.attack_type, Alert.severity)
        )
    ).all()

    grouped: dict[str, dict[str, Any]] = {}
    for src_ip, attack_type, severity, count, first_seen, last_seen in rows:
        bucket = grouped.setdefault(
            src_ip,
            {
                "src_ip": src_ip,
                "alert_count": 0,
                "by_type": {},
                "max_severity": "unknown",
                "first_seen": first_seen,
                "last_seen": last_seen,
            },
        )
        bucket["alert_count"] += int(count)
        bucket["by_type"][attack_type] = bucket["by_type"].get(attack_type, 0) + int(
            count
        )
        if severity_rank(severity) > severity_rank(bucket["max_severity"]):
            bucket["max_severity"] = severity
        if first_seen < bucket["first_seen"]:
            bucket["first_seen"] = first_seen
        if last_seen > bucket["last_seen"]:
            bucket["last_seen"] = last_seen

    clusters: list[dict[str, Any]] = []
    for bucket in grouped.values():
        if bucket["alert_count"] < min_alerts:
            continue
        by_type: dict[str, int] = bucket["by_type"]
        # Ties break on the alphabetically first type so the answer is stable
        # across runs — a "dominant type" that flips between equal counts on
        # every refresh reads as the data changing when it has not.
        dominant = max(sorted(by_type), key=lambda key: (by_type[key], key))
        clusters.append(
            {
                "src_ip": bucket["src_ip"],
                "alert_count": bucket["alert_count"],
                "dominant_attack_type": dominant,
                "attack_types": sorted(by_type),
                "max_severity": bucket["max_severity"],
                "first_seen": bucket["first_seen"],
                "last_seen": bucket["last_seen"],
                "window_minutes": window_minutes,
            }
        )

    clusters.sort(key=lambda c: (-c["alert_count"], c["src_ip"]))
    return clusters


async def refresh_clusters(
    session: AsyncSession, *, window_minutes: int, min_alerts: int
) -> dict[str, Any]:
    """Recompute and REPLACE the stored aggregate.

    A full replace rather than an upsert: a source IP that has dropped out of
    the window is no longer a cluster, and leaving its row behind would show a
    correlation the data no longer supports.

    THE JOB STORES EVERY GROUP; THE THRESHOLD IS APPLIED ON READ. Baking the
    floor into the stored rows would make `min_alerts` on the endpoint able only
    to RAISE it — a caller asking for `min_alerts=1` would get the job's floor
    back and no indication that its request had been quietly overruled. The
    configured floor is still the endpoint's default, so the screen shows real
    clusters; it is just not the only answer the stored data can give.
    """
    clusters = await compute_clusters(
        session, window_minutes=window_minutes, min_alerts=1
    )
    await session.execute(delete(AlertCluster))
    now = datetime.now(UTC)
    for cluster in clusters:
        session.add(
            AlertCluster(
                src_ip=cluster["src_ip"],
                alert_count=cluster["alert_count"],
                dominant_attack_type=cluster["dominant_attack_type"],
                attack_types=cluster["attack_types"],
                max_severity=cluster["max_severity"],
                first_seen=cluster["first_seen"],
                last_seen=cluster["last_seen"],
                window_minutes=window_minutes,
                computed_at=now,
            )
        )
    return {
        "stored": len(clusters),
        "above_threshold": sum(
            1 for c in clusters if c["alert_count"] >= min_alerts
        ),
        "window_minutes": window_minutes,
        "min_alerts": min_alerts,
        "alerts_linked": sum(c["alert_count"] for c in clusters),
    }


def cluster_to_dict(row: AlertCluster) -> dict[str, Any]:
    return {
        "src_ip": row.src_ip,
        "alert_count": row.alert_count,
        "dominant_attack_type": row.dominant_attack_type,
        "attack_types": row.attack_types or [],
        "max_severity": row.max_severity,
        "first_seen": as_utc(row.first_seen).isoformat(),
        "last_seen": as_utc(row.last_seen).isoformat(),
        "window_minutes": row.window_minutes,
        "computed_at": as_utc(row.computed_at).isoformat(),
    }


async def list_clusters(
    session: AsyncSession, *, min_alerts: int, limit: int
) -> tuple[list[dict[str, Any]], datetime | None]:
    """Read the stored clusters. Returns (clusters, computed_at)."""
    rows = list(
        (
            await session.execute(
                select(AlertCluster)
                .where(AlertCluster.alert_count >= min_alerts)
                .order_by(AlertCluster.alert_count.desc(), AlertCluster.src_ip)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    computed_at = as_utc(rows[0].computed_at) if rows else None
    return [cluster_to_dict(row) for row in rows], computed_at
