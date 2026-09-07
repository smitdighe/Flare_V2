from typing import Annotated, Any

from fastapi import APIRouter, Query, Request

from app.analytics.correlation import list_clusters
from app.api.deps import CurrentUser, SessionDep
from app.api.envelope import enveloped_response
from app.config import get_settings
from app.ingestion.catalog import attack_types, excluded_classes
from app.store.repositories import alert_to_dict, list_alerts

router = APIRouter(tags=["alerts"])


@router.get("/alerts/attack-types")
async def get_attack_types(request: Request, user: CurrentUser) -> Any:
    """The vector-filter options — SANCTIONED CHANGE FE-11.

    Declared BEFORE `/alerts` is irrelevant here (the paths do not collide),
    but the data source is the point: `app/ingestion/catalog.py` reads the
    committed partition manifest, so this can only ever offer classes the data
    contains. A hardcoded list on this side would be the same bug as the one in
    FilterStrip.jsx, one layer down.
    """
    return enveloped_response(
        {"attack_types": attack_types(), "excluded": excluded_classes()},
        request,
    )


@router.get("/alerts/clusters")
async def get_clusters(
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    min_alerts: Annotated[int | None, Query(ge=1, le=1000)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Any:
    """Threat clusters — PLAN §3.1, served FROM THE DATABASE.

    The frozen frontend reduces its 200-alert buffer client-side and calls
    every source IP with one alert a cluster (WorkspacePanel.jsx:498). This
    reads the correlation job's stored output, so the threshold is real, the
    window is real, and an IP that has not been seen for the whole window is
    not a cluster any more.

    `computed_at` is on the payload because a stored aggregate has an age, and
    a screen that cannot say how old its numbers are is a screen that can show
    stale ones without anyone noticing.
    """
    settings = get_settings()
    threshold = min_alerts or settings.correlation_min_alerts
    clusters, computed_at = await list_clusters(
        session, min_alerts=threshold, limit=limit
    )
    return enveloped_response(
        {
            "clusters": clusters,
            "min_alerts": threshold,
            "window_minutes": settings.correlation_window_minutes,
            "computed_at": computed_at.isoformat() if computed_at else None,
        },
        request,
    )


@router.get("/alerts")
async def get_alerts(
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: str | None = None,
    attack_type: str | None = None,
    search: str | None = None,
) -> Any:
    """Persisted alert list — SANCTIONED CHANGE FE-6.

    ENVELOPED: no frozen consumer constrains it, so it takes the D17 default
    and FE-6 reads json.data.alerts.

    NEWEST FIRST, matching the WebSocket prepend (DashboardPage.jsx:35), so the
    hydrated and live halves of the buffer are ordered consistently and the
    merge is a concat plus a de-dupe on `id`.

    The default limit is 200 — the client caps its own buffer there, so a
    larger page would be truncated on arrival.
    """
    rows, total = await list_alerts(
        session,
        limit=limit,
        offset=offset,
        severity=severity,
        attack_type=attack_type,
        search=search,
    )
    return enveloped_response(
        {
            "alerts": [alert_to_dict(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        },
        request,
    )
