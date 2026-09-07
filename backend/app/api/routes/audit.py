"""Audit trail. CONTRACT §2.3 / §9.7 / PLAN §4.1.

**`/audit/logs` MUST RETURN 403 FOR A NON-ADMIN.** The frozen frontend branches
on exactly 403 to fall back to `/audit/logs/me` (WorkspacePanel.jsx:243).
Returning 200-with-filtered-rows instead would mean a non-admin never sees the
"my logs" view at all — the screen would silently show them the wrong thing and
look like it worked.

**`total` IS THE POST-FILTER COUNT** (CONTRACT §9.7). Pagination is
`Math.ceil(total / 25)`, so a pre-filter count produces a page count that does
not match the pages.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request

from app.api.deps import CurrentUser, SessionDep, require_role
from app.api.envelope import enveloped_response
from app.store.models import AuditLog, as_utc
from app.store.repositories import list_audit

router = APIRouter(prefix="/audit", tags=["audit"])


def audit_to_dict(row: AuditLog) -> dict[str, Any]:
    """`created_at` is rendered as `created_at.replace('T',' ').slice(0,19)`,
    so it must be ISO-8601 (WorkspacePanel.jsx:311). `details` is rendered with
    JSON.stringify and a falsy value hides the expander."""
    return {
        "id": row.id,
        "actor_id": row.actor_id,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "details": row.details,
        "created_at": as_utc(row.created_at).isoformat(),
    }


@router.get("/logs", dependencies=[Depends(require_role("admin"))])
async def all_logs(
    request: Request,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    action: str | None = None,
    resource_type: str | None = None,
) -> Any:
    rows, total = await list_audit(
        session,
        limit=limit,
        offset=offset,
        action=action,
        resource_type=resource_type,
    )
    return enveloped_response(
        {
            "logs": [audit_to_dict(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        },
        request,
    )


@router.get("/logs/me")
async def my_logs(
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    action: str | None = None,
    resource_type: str | None = None,
) -> Any:
    """Identical shape and identical query parameters, scoped to the caller."""
    rows, total = await list_audit(
        session,
        limit=limit,
        offset=offset,
        action=action,
        resource_type=resource_type,
        actor_id=user.id,
    )
    return enveloped_response(
        {
            "logs": [audit_to_dict(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        },
        request,
    )
