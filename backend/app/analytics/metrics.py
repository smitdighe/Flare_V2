"""Every number the right rail, the header and the velocity screen render.

PLAN I2 — **ZERO LITERALS.** Each function here replaces a value the frozen
frontend currently invents, and each one is named next to what it replaces:

| what the UI shows today                | what this computes                     |
|----------------------------------------|----------------------------------------|
| `+18.4%` threat forecast               | `threat_forecast` — real window delta   |
| `x 62` scale on the velocity series    | `signal_velocity` — sampled alerts/min  |
| `window 60m`                           | the real window the samples cover       |
| `3 hot`                                | `attack_surface.hot`                    |
| `08 origins // 08 paths`               | distinct source IPs and distinct paths  |
| `10.24.0.0/16`                         | the dominant destination /16, measured  |
| loads `0.82 / 0.64 / 0.71 / 0.45`      | `pipeline_activity` — real node share   |

**THE VELOCITY SERIES IS SAMPLED, NOT RE-BUCKETED.** `signal_velocity` reads
`metric_samples`, which the scheduler writes once per interval. That is what
PLAN §3.1 means by "real samples": each point is a rate that was OBSERVED at an
instant. Re-bucketing stored alert timestamps would give counts per bucket,
which is a different quantity, and would make the panel's history depend on
nothing having been deleted. When no sample exists yet the function says so —
`sample_count: 0` and a computed fallback — instead of drawing a line from
nothing.

**A RATIO WITH A ZERO DENOMINATOR IS NULL, NOT A NUMBER.** `threat_forecast`
returns `change_pct: null` when the previous window was empty, with the counts
and a reason alongside. There is no honest percentage change from zero, and
inventing one is how `+18.4%` got there in the first place.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Integer, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.state import NodeName
from app.ingestion.labels import SEVERITY_ORDER, severity_rank
from app.store.models import Alert, MetricSample, as_utc

ALL_SEVERITIES: tuple[str, ...] = (*SEVERITY_ORDER, "unknown")


def _epoch_bucket(bucket_seconds: int) -> Any:
    """Bucket index for a stored timestamp.

    SQLite-specific by design (PLAN D1 — SQLite is the database). Stored
    timestamps are naive UTC, which is exactly what `strftime('%s', …)` reads,
    so the arithmetic is exact rather than approximate. A later Postgres swap
    replaces this one expression, which is why it is isolated in a function.
    """
    return func.cast(func.strftime("%s", Alert.timestamp), Integer) / bucket_seconds


# ---------------------------------------------------------------------------
# /stats — the event-velocity screen
# ---------------------------------------------------------------------------


async def timeline(
    session: AsyncSession, *, window_minutes: int, bucket_seconds: int
) -> dict[str, Any]:
    """CONTRACT §9.4 / PLAN D7 — bucketed histogram plus the mean rate.

    Buckets are CONTIGUOUS: an interval with no alerts is emitted as zero
    rather than omitted. A gap would compress the x-axis and make a quiet
    period look like a busy one, and the frontend renders whatever array it is
    given without reading the timestamps for spacing.

    `alert_velocity` is the MEAN over the FULL window, rounded to an integer —
    not the most recent bucket. A sparse trailing bucket reads 0 and looks
    broken under a panel labelled "30 minute window" (CONTRACT §9.4). With
    one-minute buckets the mean is literally alerts per minute, so the number
    matches the label with no rescaling.
    """
    now = datetime.now(UTC)
    bucket_count = max(1, (window_minutes * 60) // bucket_seconds)
    now_index = int(now.timestamp()) // bucket_seconds
    first_index = now_index - bucket_count + 1
    since = datetime.fromtimestamp(first_index * bucket_seconds, tz=UTC)

    bucket = _epoch_bucket(bucket_seconds).label("bucket")
    rows = (
        await session.execute(
            select(bucket, func.count())
            .where(Alert.timestamp >= since)
            .group_by(bucket)
        )
    ).all()
    counts = {int(index): int(count) for index, count in rows}

    buckets: list[dict[str, Any]] = []
    for offset in range(bucket_count):
        index = first_index + offset
        buckets.append(
            {
                "time": datetime.fromtimestamp(
                    index * bucket_seconds, tz=UTC
                ).isoformat(),
                "count": counts.get(index, 0),
            }
        )

    total = sum(b["count"] for b in buckets)
    per_bucket_mean = total / bucket_count
    # Buckets are `bucket_seconds` long; the panel is labelled per MINUTE.
    velocity = round(per_bucket_mean * (60 / bucket_seconds))

    return {
        "timeline": buckets,
        "alert_velocity": int(velocity),
        "window_minutes": window_minutes,
        "bucket_seconds": bucket_seconds,
        "total_in_window": total,
    }


# ---------------------------------------------------------------------------
# right rail
# ---------------------------------------------------------------------------


async def observe_rate(
    session: AsyncSession, *, window_seconds: int
) -> float:
    """Alerts per minute over the trailing window, right now.

    This is the measurement the scheduler stores as one sample. It is a rate at
    an instant, which is why it is taken repeatedly rather than derived once.
    """
    since = datetime.now(UTC) - timedelta(seconds=window_seconds)
    count = (
        await session.execute(
            select(func.count()).select_from(Alert).where(Alert.timestamp >= since)
        )
    ).scalar_one()
    return round(int(count) * 60.0 / window_seconds, 3)


async def signal_velocity(
    session: AsyncSession, *, window_minutes: int, sample_interval_seconds: int
) -> dict[str, Any]:
    """The sampled series the right rail plots. PLAN §3.1."""
    since = datetime.now(UTC) - timedelta(minutes=window_minutes)
    rows = list(
        (
            await session.execute(
                select(MetricSample)
                .where(MetricSample.observed_at >= since)
                .order_by(MetricSample.observed_at)
            )
        )
        .scalars()
        .all()
    )

    if not rows:
        # No sample has been taken yet. Report the live rate and say the series
        # is empty, rather than drawing a flat line that looks like data.
        live = await observe_rate(session, window_seconds=sample_interval_seconds)
        return {
            "samples": [],
            "sample_count": 0,
            "now_per_min": live,
            "peak_per_min": live,
            "window_minutes": 0.0,
            "configured_window_minutes": window_minutes,
            "sample_interval_seconds": sample_interval_seconds,
            "note": (
                "no sample has been recorded yet; `now_per_min` is a live "
                "measurement and the series is genuinely empty"
            ),
        }

    values = [row.alerts_per_minute for row in rows]
    span_seconds = (
        as_utc(rows[-1].observed_at) - as_utc(rows[0].observed_at)
    ).total_seconds()
    return {
        "samples": [
            {
                "at": as_utc(row.observed_at).isoformat(),
                "alerts_per_minute": row.alerts_per_minute,
            }
            for row in rows
        ],
        "sample_count": len(rows),
        "now_per_min": values[-1],
        "peak_per_min": max(values),
        # The REAL span the samples cover, which is what the "window" tile
        # should say. It is smaller than `window_minutes` until the series has
        # filled, and claiming the configured window before then would be a
        # literal wearing a measurement's clothes.
        "window_minutes": round(span_seconds / 60, 2),
        "configured_window_minutes": window_minutes,
        "sample_interval_seconds": sample_interval_seconds,
        # Both branches emit the SAME KEYS. A key that vanishes when the data
        # is present is a key a consumer cannot rely on, and reading it would
        # be undefined exactly when the panel finally has something to draw.
        "note": None,
    }


async def threat_forecast(
    session: AsyncSession, *, window_minutes: int
) -> dict[str, Any]:
    """PLAN D8 — `(current / previous - 1) * 100`, over two adjacent windows."""
    now = datetime.now(UTC)
    current_start = now - timedelta(minutes=window_minutes)
    previous_start = now - timedelta(minutes=window_minutes * 2)

    async def _count(lo: datetime, hi: datetime) -> int:
        return int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(Alert)
                    .where(Alert.timestamp >= lo, Alert.timestamp < hi)
                )
            ).scalar_one()
        )

    current = await _count(current_start, now)
    previous = await _count(previous_start, current_start)

    if previous == 0:
        return {
            "change_pct": None,
            "current": current,
            "previous": previous,
            "window_minutes": window_minutes,
            "note": (
                "the previous window held no alerts, so there is no percentage "
                "change to report — a ratio against zero has no value and "
                "inventing one is what a hardcoded +18.4% is"
            ),
        }

    return {
        "change_pct": round((current / previous - 1) * 100, 1),
        "current": current,
        "previous": previous,
        "window_minutes": window_minutes,
    }


def _subnet16(ip: str) -> str | None:
    parts = ip.split(".")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return None
    return f"{parts[0]}.{parts[1]}.0.0/16"


async def attack_surface(
    session: AsyncSession, *, window_minutes: int, node_limit: int
) -> dict[str, Any]:
    """Real origins, real paths, real hot count, real dominant subnet."""
    since = datetime.now(UTC) - timedelta(minutes=window_minutes)

    origins = int(
        (
            await session.execute(
                select(func.count(func.distinct(Alert.src_ip))).where(
                    Alert.timestamp >= since
                )
            )
        ).scalar_one()
    )
    paths = int(
        (
            await session.execute(
                select(func.count()).select_from(
                    select(Alert.src_ip, Alert.dest_ip, Alert.dest_port)
                    .where(Alert.timestamp >= since)
                    .distinct()
                    .subquery()
                )
            )
        ).scalar_one()
    )
    hot = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Alert)
                .where(
                    Alert.timestamp >= since,
                    Alert.severity.in_(("critical", "high")),
                )
            )
        ).scalar_one()
    )

    node_rows = (
        await session.execute(
            select(
                Alert.src_ip,
                Alert.attack_type,
                Alert.severity,
                func.count().label("n"),
            )
            .where(Alert.timestamp >= since)
            .group_by(Alert.src_ip, Alert.attack_type, Alert.severity)
            .order_by(func.count().desc())
            .limit(node_limit * 4)
        )
    ).all()

    best: dict[str, dict[str, Any]] = {}
    for src_ip, attack_type, severity, count in node_rows:
        entry = best.get(src_ip)
        if entry is None or int(count) > entry["alert_count"]:
            best[src_ip] = {
                "src_ip": src_ip,
                "attack_type": attack_type,
                "severity": severity,
                "alert_count": int(count),
            }
        elif severity_rank(severity) > severity_rank(entry["severity"]):
            entry["severity"] = severity
    nodes = sorted(
        best.values(), key=lambda n: (-n["alert_count"], n["src_ip"])
    )[:node_limit]

    subnet_rows = (
        await session.execute(
            select(Alert.dest_ip, func.count())
            .where(Alert.timestamp >= since)
            .group_by(Alert.dest_ip)
        )
    ).all()
    subnets: Counter[str] = Counter()
    for dest_ip, count in subnet_rows:
        block = _subnet16(dest_ip)
        if block:
            subnets[block] += int(count)
    dominant = subnets.most_common(1)[0][0] if subnets else None

    return {
        "origins": origins,
        "paths": paths,
        "hot": hot,
        "dominant_subnet": dominant,
        "nodes": nodes,
        "window_minutes": window_minutes,
    }


async def pipeline_activity(
    session: AsyncSession, *, sample_size: int
) -> dict[str, Any]:
    """Per-node state and utilization, from the graph's OWN node names.

    PLAN D9 / FE-4. The names come from `NodeName`, so they cannot drift from
    the graph, and there are seven of them because the pipeline has seven
    nodes — the frozen panel renders four, and the extra three are available
    rather than hidden.

    `load` is the share of the sampled alerts on which the node DID WORK: it
    ran and was not skipped. That is a real utilization for a per-alert
    pipeline — a node the router skips on 90% of alerts is genuinely idle 90%
    of the time — and it is the quantity the bar is drawn from.
    """
    rows = list(
        (
            await session.execute(
                select(Alert.trace)
                .order_by(Alert.timestamp.desc(), Alert.id.desc())
                .limit(sample_size)
            )
        )
        .scalars()
        .all()
    )

    ran: Counter[str] = Counter()
    ok: Counter[str] = Counter()
    failed: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    duration: dict[str, float] = {}

    for trace in rows:
        for entry in trace or []:
            node = str(entry.get("node", ""))
            status = str(entry.get("status", ""))
            if status == "skipped":
                skipped[node] += 1
                continue
            ran[node] += 1
            if status == "failed":
                failed[node] += 1
            else:
                ok[node] += 1
            duration[node] = duration.get(node, 0.0) + float(
                entry.get("duration_ms") or 0.0
            )

    sampled = len(rows)
    nodes = []
    for node in NodeName:
        name = node.value
        did_work = ran[name]
        nodes.append(
            {
                "name": name,
                "state": "active" if did_work else "idle",
                "load": round(did_work / sampled, 4) if sampled else 0.0,
                "ran": did_work,
                "ok": ok[name],
                "failed": failed[name],
                "skipped": skipped[name],
                "mean_duration_ms": (
                    round(duration.get(name, 0.0) / did_work, 3) if did_work else 0.0
                ),
            }
        )

    return {"nodes": nodes, "sampled_alerts": sampled}


# ---------------------------------------------------------------------------
# header counters and ticker
# ---------------------------------------------------------------------------


def _filters(
    severity: str | None, attack_type: str | None, search: str | None
) -> list[Any]:
    from sqlalchemy import or_

    filters: list[Any] = []
    if severity:
        filters.append(Alert.severity == severity)
    if attack_type:
        filters.append(Alert.attack_type == attack_type)
    if search:
        needle = f"%{search.strip()}%"
        filters.append(
            or_(
                Alert.src_ip.like(needle),
                Alert.dest_ip.like(needle),
                Alert.id.like(needle.upper()),
                Alert.signature.like(needle),
            )
        )
    return filters


async def overview(
    session: AsyncSession,
    *,
    severity: str | None = None,
    attack_type: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """Header counters and the top-bar ticker, OVER THE ACTIVE FILTER SET.

    PLAN §3.1 asks for counters over the active filter set; the frozen
    frontend counts its unfiltered 200-alert buffer instead, so the numbers
    disagree with the table the moment a filter is on. The same filter
    predicates as `list_alerts` are used here so the two can never diverge.

    The ticker is the highest-severity alert, most recent first within that
    severity — which is what "current highest-severity alert" means when
    several share the top severity.
    """
    filters = _filters(severity, attack_type, search)

    counts_stmt = select(Alert.severity, func.count()).group_by(Alert.severity)
    for condition in filters:
        counts_stmt = counts_stmt.where(condition)
    rows = (await session.execute(counts_stmt)).all()
    by_severity = {name: 0 for name in ALL_SEVERITIES}
    for name, count in rows:
        by_severity[str(name)] = int(count)

    ticker_stmt = select(Alert)
    for condition in filters:
        ticker_stmt = ticker_stmt.where(condition)
    candidates = list(
        (
            await session.execute(
                ticker_stmt.order_by(Alert.timestamp.desc(), Alert.id.desc()).limit(200)
            )
        )
        .scalars()
        .all()
    )
    ticker = None
    if candidates:
        top = max(candidates, key=lambda a: severity_rank(a.severity))
        ticker = {
            "id": top.id,
            "severity": top.severity,
            "signature": top.signature,
            "dest_ip": top.dest_ip,
            "src_ip": top.src_ip,
            "timestamp": as_utc(top.timestamp).isoformat(),
        }

    return {
        "total": sum(by_severity.values()),
        "by_severity": by_severity,
        "ticker": ticker,
        "filters": {
            "severity": severity,
            "attack_type": attack_type,
            "search": search,
        },
    }
