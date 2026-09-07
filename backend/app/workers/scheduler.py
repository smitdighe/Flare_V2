"""APScheduler jobs. PLAN §4.1 / T14 — every job PERSISTS what it computes.

Two jobs, and both are load-bearing rather than decorative:

**`metrics.sample`** takes one observation of the live alert rate and stores it
in `metric_samples`. The right rail's signal-velocity panel plots that series
(PLAN §3.1, "real samples"). The series cannot be reconstructed afterwards from
alert timestamps — re-bucketing stored rows gives counts per bucket, which is a
different quantity from a rate observed at an instant — so this job is the only
thing that can produce the panel's data.

**`correlation.refresh`** recomputes the source-IP clusters and REPLACES
`alert_clusters`. `GET /alerts/clusters` reads that table and does not
recompute, so a job that aggregated and threw the result away would be visible
as an empty Threat Clusters screen rather than being invisible. It also runs
once at startup, so the screen is never empty merely because a timer has not
fired yet.

**EVERY RUN LEAVES A RECEIPT.** `job_runs` records which job, when, how long,
what it wrote, and the exception text if it raised. A run that produced nothing
says so. That table is what `/health/deep` reports job health from, and what
makes "the scheduler is running" a checkable claim instead of an assertion.

**EVERY RUN IS ALSO AUDITED** (PLAN §4.1 — "every state-changing operation,
including job triggers"). Scheduled runs are audited as the actor-less
`job.run`; a manual trigger carries the operator's id. The audit log is
newest-first, so a human action stays at the top of page one even while a
per-minute job writes underneath it.

**AN EXCEPTION NEVER KILLS THE SCHEDULER.** Each job body is wrapped, the
failure is recorded in `job_runs` with its message, and the next tick still
fires. A scheduler that dies on one bad run takes the Threat Clusters screen
down with it and gives no signal about why.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.store.models import JobRun, MetricSample
from app.store.repositories import write_audit
from app.store.session import get_sessionmaker

logger = logging.getLogger("flare.scheduler")

JobBody = Callable[[AsyncSession, Settings], Awaitable[dict[str, Any]]]


# ---------------------------------------------------------------------------
# the jobs
# ---------------------------------------------------------------------------


async def sample_metrics(session: AsyncSession, settings: Settings) -> dict[str, Any]:
    """One observation of the live rate, stored. PLAN §3.1."""
    from app.analytics.metrics import observe_rate
    from app.ingestion.feed import get_feed

    window = settings.metrics_sample_interval_seconds
    rate = await observe_rate(session, window_seconds=window)
    stats = get_feed().stats()

    session.add(
        MetricSample(
            alerts_per_minute=rate,
            window_seconds=window,
            queue_depth=int(stats["queue"]["depth"]),
            subscribers=int(stats["subscribers"]),
        )
    )
    return {
        "alerts_per_minute": rate,
        "window_seconds": window,
        "queue_depth": int(stats["queue"]["depth"]),
        "subscribers": int(stats["subscribers"]),
    }


async def refresh_correlation(
    session: AsyncSession, settings: Settings
) -> dict[str, Any]:
    """Recompute and replace the stored cluster set."""
    from app.analytics.correlation import refresh_clusters

    return await refresh_clusters(
        session,
        window_minutes=settings.correlation_window_minutes,
        min_alerts=settings.correlation_min_alerts,
    )


async def flush_notifications(
    session: AsyncSession, settings: Settings
) -> dict[str, Any]:
    """Send the rollups whose debounce window has expired. PLAN §8.3.

    The dispatcher sends the FIRST alert in a window immediately and holds the
    rest. Without this job a held rollup would wait for the next triggering
    alert, which during a quiet period is exactly the thing that does not
    arrive — so the analyst would learn about a burst only when the next burst
    started. The dispatcher owns its own session for the sends; this job takes
    the receipt.
    """
    from app.notifications.dispatcher import get_dispatcher

    return await get_dispatcher().flush()


JOBS: dict[str, JobBody] = {
    "metrics.sample": sample_metrics,
    "correlation.refresh": refresh_correlation,
    "notifications.flush": flush_notifications,
}


# ---------------------------------------------------------------------------
# the runner
# ---------------------------------------------------------------------------


async def run_job(
    name: str, *, trigger: str = "schedule", actor_id: int | None = None
) -> JobRun:
    """Run one job in its own session, and record the receipt either way."""
    body = JOBS.get(name)
    if body is None:
        raise KeyError(f"unknown job {name!r}; known jobs: {sorted(JOBS)}")

    settings = get_settings()
    started = time.perf_counter()
    result: dict[str, Any] | None = None
    error: str | None = None

    async with get_sessionmaker()() as session:
        try:
            result = await body(session, settings)
            status = "ok"
        except Exception as exc:
            await session.rollback()
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"
            logger.exception("scheduled job failed", extra={"request_id": "-"})

        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        record = JobRun(
            job=name,
            status=status,
            trigger=trigger,
            duration_ms=duration_ms,
            result=result,
            error=error,
        )
        session.add(record)

        await write_audit(
            session,
            action="job.run",
            resource_type="job",
            actor_id=actor_id,
            resource_id=name,
            details={
                "status": status,
                "trigger": trigger,
                "duration_ms": duration_ms,
                "result": result,
                "error": error,
            },
        )
        await session.commit()
        return record


_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler | None:
    return _scheduler


async def start_scheduler(settings: Settings | None = None) -> AsyncIOScheduler | None:
    """Start the jobs, and run the correlation refresh once immediately.

    The immediate run is what stops the Threat Clusters screen being empty for
    the first two minutes of a demo — an empty screen at that moment is
    indistinguishable from a broken one.
    """
    global _scheduler
    settings = settings or get_settings()
    if not settings.scheduler_enabled:
        logger.info("scheduler disabled by config", extra={"request_id": "-"})
        return None
    if _scheduler is not None and _scheduler.running:
        return _scheduler

    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        run_job,
        "interval",
        seconds=settings.metrics_sample_interval_seconds,
        args=["metrics.sample"],
        id="metrics.sample",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.add_job(
        run_job,
        "interval",
        seconds=settings.correlation_refresh_seconds,
        args=["correlation.refresh"],
        id="correlation.refresh",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    if settings.notifications_enabled:
        scheduler.add_job(
            run_job,
            "interval",
            seconds=settings.notification_flush_seconds,
            args=["notifications.flush"],
            id="notifications.flush",
            max_instances=1,
            coalesce=True,
            replace_existing=True,
        )
    scheduler.start()
    _scheduler = scheduler

    await run_job("correlation.refresh", trigger="startup")
    logger.info(
        "scheduler started",
        extra={
            "request_id": "-",
            "metrics_sample_seconds": settings.metrics_sample_interval_seconds,
            "correlation_refresh_seconds": settings.correlation_refresh_seconds,
        },
    )
    return scheduler


async def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
    _scheduler = None
