from typing import Any

from fastapi import APIRouter, Request
from sqlalchemy import text

from app.api.deps import CurrentUser, SessionDep
from app.api.envelope import enveloped_response
from app.core.health_state import get_health_cache

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(request: Request, user: CurrentUser, session: SessionDep) -> Any:
    """Cheap health — local state only, NEVER a provider call.

    PLAN §9: authenticated. An anonymous health endpoint in the prior codebase
    burned four metered quotas per anonymous hit.

    PLAN T4/§10: this is the endpoint on the frontend's 30-second timer
    (WorkspacePanel.jsx:39). It reads the local cache and the DB handle only.
    /health/deep is the real four-provider probe and arrives in Phase 3.
    """
    services = get_health_cache().snapshot()

    # The DB is local, so checking it costs nothing and is genuinely measured.
    from time import perf_counter

    started = perf_counter()
    try:
        await session.execute(text("SELECT 1"))
        db_status, db_message = "ok", "sqlite (wal)"
    except Exception as exc:
        db_status, db_message = "error", type(exc).__name__
    db_latency = round((perf_counter() - started) * 1000, 3)

    services.append(
        {
            "name": "database",
            "status": db_status,
            "latency_ms": db_latency,
            "message": db_message,
            "checked_at": None,
        }
    )

    return enveloped_response({"services": services}, request)
