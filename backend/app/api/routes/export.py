"""Alert export. CONTRACT §2.5 / PLAN §9.

**BINARY, NEVER ENVELOPED** — the frontend calls `res.blob()` and triggers a
download named `flare_alerts.{format}` (WorkspacePanel.jsx:618-623). This is
pinned exception 11/11.

**THE SAME FILTER SEMANTICS AS THE ON-SCREEN LIST.** The filters come from the
live dashboard state, so the export must go through the same `list_alerts`
query the table does. A second filter implementation is how an export quietly
stops matching what the user is looking at.

`limit` is always the literal `500` from the frozen UI (WorkspacePanel.jsx:610)
and is capped server-side regardless.

A failed export is SILENT to the user — the frontend swallows the error to
`console.error` (WorkspacePanel.jsx:626) — so a failure here must be loud
server-side, which is what the audit row and the exception handler provide.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query, Request
from fastapi.responses import Response

from app.api.deps import CurrentUser, SessionDep
from app.config import get_settings
from app.export.writers import write_csv, write_pdf
from app.store.repositories import list_alerts, write_audit

router = APIRouter(tags=["export"])

MEDIA_TYPES = {"csv": "text/csv; charset=utf-8", "pdf": "application/pdf"}


@router.get("/export/alerts/{format}")
async def export_alerts(
    format: Annotated[str, Path(pattern="^(csv|pdf)$")],
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    severity: str | None = None,
    attack_type: str | None = None,
    search: str | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
) -> Response:
    settings = get_settings()
    capped = min(limit, settings.export_max_rows)

    rows, total = await list_alerts(
        session,
        limit=capped,
        offset=0,
        severity=severity,
        attack_type=attack_type,
        search=search,
    )

    filters = {
        "severity": severity,
        "attack_type": attack_type,
        "search": search,
        "limit": capped,
    }
    if format == "csv":
        payload = write_csv(rows)
    else:
        payload = write_pdf(rows, filters=filters)

    # PLAN §4.1 — an export is a state-changing operation for audit purposes:
    # data left the system. What left, and under which filters, is the part
    # worth recording.
    await write_audit(
        session,
        action="export.alerts",
        resource_type="alert",
        actor_id=user.id,
        resource_id=None,
        details={
            "format": format,
            "rows": len(rows),
            "matched": total,
            "filters": {k: v for k, v in filters.items() if v not in (None, "")},
            "bytes": len(payload),
        },
    )
    await session.commit()

    return Response(
        content=payload,
        media_type=MEDIA_TYPES[format],
        headers={
            "Content-Disposition": f'attachment; filename="flare_alerts.{format}"',
            "X-Flare-Export-Rows": str(len(rows)),
        },
    )
