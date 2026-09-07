"""Event velocity, the right rail and the header counters. PLAN I2 / D7 / D8 / D9.

Three endpoints, all enveloped — none of them is on the pinned exception list
(CONTRACT §1.3.1), because no frozen consumer constrains their shape. `/stats`
is in the frozen inventory (CONTRACT §2.2 #8) and is envelope-tolerant on the
client (`json.data || json`); the two `/metrics/*` routes are new, and are the
producers PLAN §3.1 requires for right-rail values the frontend currently
invents (CONTRACT §7.4).

**WHY THESE ARE NEW PATHS.** CONTRACT §6.1 lists four right-rail requirements
as "no backing call exists" at High severity — threat forecast, signal
velocity, attack surface and pipeline activity. There is nothing to repoint;
the panels take props and compute literals. The backend half is here and is
real; consuming it needs a frontend change beyond FE-5's "delete the literal",
which is reported rather than made (the frontend is frozen).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from app.analytics import metrics as analytics
from app.api.deps import CurrentUser, SessionDep
from app.api.envelope import enveloped_response
from app.config import get_settings

router = APIRouter(tags=["metrics"])


@router.get("/stats")
async def stats(request: Request, user: CurrentUser, session: SessionDep) -> Any:
    """CONTRACT §2.2 #8 — timeline buckets plus `alert_velocity`.

    Only the LAST 20 buckets render (WorkspacePanel.jsx:195) and `time` is
    sliced as `time.slice(11,16)` for HH:MM, so it must be ISO-8601 with `T` at
    index 10 and every value must be unique — contiguous bucket starts satisfy
    both.
    """
    settings = get_settings()
    payload = await analytics.timeline(
        session,
        window_minutes=settings.stats_window_minutes,
        bucket_seconds=settings.stats_bucket_seconds,
    )
    return enveloped_response(payload, request)


@router.get("/metrics/rail")
async def rail(request: Request, user: CurrentUser, session: SessionDep) -> Any:
    """All four right-rail panels in one round trip.

    One endpoint rather than four because the panels render together in a
    single column and four requests on every dashboard mount is three more
    chances for one of them to be the slow one.
    """
    settings = get_settings()
    return enveloped_response(
        {
            "signal_velocity": await analytics.signal_velocity(
                session,
                window_minutes=settings.metrics_sample_window_minutes,
                sample_interval_seconds=settings.metrics_sample_interval_seconds,
            ),
            "threat_forecast": await analytics.threat_forecast(
                session, window_minutes=settings.forecast_window_minutes
            ),
            "attack_surface": await analytics.attack_surface(
                session,
                window_minutes=settings.metrics_sample_window_minutes,
                node_limit=8,
            ),
            "pipeline_activity": await analytics.pipeline_activity(
                session, sample_size=settings.pipeline_activity_sample_size
            ),
        },
        request,
    )


@router.get("/metrics/overview")
async def overview(
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    severity: str | None = None,
    attack_type: str | None = None,
    search: str | None = None,
) -> Any:
    """Header counters and the top-bar ticker, over the ACTIVE FILTER SET.

    The frozen frontend counts its unfiltered 200-alert buffer
    (DashboardView.jsx:65), so its TOTAL/HIGH/MEDIUM disagree with the table as
    soon as a filter is applied. These counts use the same predicates as
    `GET /alerts`, so the two cannot diverge.
    """
    payload = await analytics.overview(
        session, severity=severity, attack_type=attack_type, search=search
    )
    return enveloped_response(payload, request)
