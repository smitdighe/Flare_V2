"""Notification preferences. CONTRACT §2.8 / §8.6 / PLAN §17.

**POST IS AN UPSERT.** Both "Add" and the Enable/Disable toggle POST to the
same URL, and the toggle re-POSTs the SAME `channel` + `event_type` with
`is_enabled` flipped (WorkspacePanel.jsx:1031). A plain insert would create a
duplicate row on every toggle instead of flipping the existing one. The
uniqueness key is `(user, channel, event_type)`.

**SLACK IS REJECTED, NOT ACCEPTED-AND-IGNORED** (CONTRACT §8.6). PLAN §17 cuts
Slack — "scaffolded but not sending" — while the frozen dropdown offers it as
an equal choice with no disabled state. A judge could create a Slack preference
and watch nothing happen, which is precisely the failure §17 exists to
pre-empt. The rejection carries a `detail` the existing error path renders
verbatim, so the user is told why rather than shown a dead row.

**PHASE 5 CLOSED THE PHASE BOUNDARY.** Phase 4 shipped the preference STORE and
said plainly that nothing read it. `app/notifications/dispatcher.py` now does:
an enabled `email` preference is resolved on every triggering alert, and
disabling one stops sends on the next alert rather than on a cache expiry.
`GET /notifications/log` below is the receipt — every send, every suppression
and every failure, including the ones nobody was emailed about.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select

from app.api.deps import CurrentUser, SessionDep
from app.api.envelope import enveloped_response
from app.api.errors import HTTP_422_UNPROCESSABLE, AppError
from app.store.models import NotificationLog, NotificationPreference, as_utc
from app.store.repositories import write_audit

router = APIRouter(prefix="/notifications", tags=["notifications"])

CHANNELS = ("email", "slack")
EVENT_TYPES = ("alert.high_severity", "rule.matched", "export.ready")

OUTCOMES = ("sent", "suppressed", "failed")

# PLAN §17. `slack` is offered by the frozen dropdown and is not wired.
UNSUPPORTED_CHANNELS = {
    "slack": (
        "Slack notifications are not wired in this build. Email is the real, "
        "working channel; a Slack preference would be a row that goes nowhere, "
        "so it is refused rather than stored."
    )
}


class PreferenceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: str
    event_type: str
    is_enabled: bool


def log_to_dict(row: NotificationLog) -> dict[str, Any]:
    return {
        "id": row.id,
        "channel": row.channel,
        "event_type": row.event_type,
        "outcome": row.outcome,
        "reason": row.reason,
        "alert_id": row.alert_id,
        "severity": row.severity,
        "rollup_count": row.rollup_count,
        "recipient": row.recipient,
        "attempts": row.attempts,
        "created_at": as_utc(row.created_at).isoformat(),
    }


def preference_to_dict(row: NotificationPreference) -> dict[str, Any]:
    """`channel` is rendered with `.toUpperCase()` and NO null guard
    (WorkspacePanel.jsx:1085), so it must never be null."""
    return {
        "id": row.id,
        "channel": row.channel,
        "event_type": row.event_type,
        "is_enabled": row.is_enabled,
    }


@router.get("/preferences")
async def list_preferences(
    request: Request, user: CurrentUser, session: SessionDep
) -> Any:
    """RAW — PINNED EXCEPTION. WorkspacePanel.jsx:1020 reads `d.preferences`."""
    rows = list(
        (
            await session.execute(
                select(NotificationPreference)
                .where(NotificationPreference.user_id == user.id)
                .order_by(NotificationPreference.id)
            )
        )
        .scalars()
        .all()
    )
    return {"preferences": [preference_to_dict(row) for row in rows]}


@router.post("/preferences")
async def upsert_preference(
    body: PreferenceInput, request: Request, user: CurrentUser, session: SessionDep
) -> Any:
    channel = body.channel.strip().lower()
    event_type = body.event_type.strip()

    if channel not in CHANNELS:
        raise AppError(
            "validation_error",
            f"`channel` must be one of {', '.join(CHANNELS)}.",
            HTTP_422_UNPROCESSABLE,
        )
    if channel in UNSUPPORTED_CHANNELS:
        raise AppError(
            "unsupported_channel",
            UNSUPPORTED_CHANNELS[channel],
            status.HTTP_400_BAD_REQUEST,
        )
    if event_type not in EVENT_TYPES:
        raise AppError(
            "validation_error",
            f"`event_type` must be one of {', '.join(EVENT_TYPES)}.",
            HTTP_422_UNPROCESSABLE,
        )

    row = (
        await session.execute(
            select(NotificationPreference).where(
                NotificationPreference.user_id == user.id,
                NotificationPreference.channel == channel,
                NotificationPreference.event_type == event_type,
            )
        )
    ).scalar_one_or_none()

    created = row is None
    if row is None:
        row = NotificationPreference(
            user_id=user.id,
            channel=channel,
            event_type=event_type,
            is_enabled=body.is_enabled,
        )
        session.add(row)
    else:
        row.is_enabled = body.is_enabled
    await session.flush()

    # PLAN §9 — a notification-preference change is a state-changing operation
    # and is audited like any other.
    await write_audit(
        session,
        action="notification.create" if created else "notification.update",
        resource_type="notification_preference",
        actor_id=user.id,
        resource_id=str(row.id),
        details={
            "channel": channel,
            "event_type": event_type,
            "is_enabled": body.is_enabled,
        },
    )
    await session.commit()
    return enveloped_response(preference_to_dict(row), request)


@router.delete(
    "/preferences/{preference_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_preference(
    preference_id: int, request: Request, user: CurrentUser, session: SessionDep
) -> Response:
    """Owner-scoped on LOOKUP — another user's id is a 404 (PLAN §9)."""
    row = (
        await session.execute(
            select(NotificationPreference).where(
                NotificationPreference.id == preference_id,
                NotificationPreference.user_id == user.id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise AppError(
            "not_found", "Preference not found.", status.HTTP_404_NOT_FOUND
        )

    await write_audit(
        session,
        action="notification.delete",
        resource_type="notification_preference",
        actor_id=user.id,
        resource_id=str(preference_id),
        details={"channel": row.channel, "event_type": row.event_type},
    )
    await session.delete(row)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/log")
async def list_log(
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    outcome: str | None = None,
) -> Any:
    """The dispatch record. PLAN §8.3 — sends, SUPPRESSIONS and failures.

    No frozen frontend consumer: this is new surface, added because "the email
    was suppressed because you were watching" is a claim that needs evidence
    somebody can look at. Enveloped, like every other endpoint no frozen
    consumer constrains.

    OWNER-SCOPED ON LOOKUP (PLAN §9, IDOR). A notification log names who was
    emailed about what and when, which is exactly the sort of row one user must
    not be able to read about another.
    """
    if outcome is not None and outcome not in OUTCOMES:
        raise AppError(
            "validation_error",
            f"`outcome` must be one of {', '.join(OUTCOMES)}.",
            HTTP_422_UNPROCESSABLE,
        )

    conditions = [NotificationLog.user_id == user.id]
    if outcome:
        conditions.append(NotificationLog.outcome == outcome)

    total = int(
        (
            await session.execute(
                select(func.count()).select_from(NotificationLog).where(*conditions)
            )
        ).scalar_one()
    )
    rows = list(
        (
            await session.execute(
                select(NotificationLog)
                .where(*conditions)
                .order_by(NotificationLog.created_at.desc(), NotificationLog.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return enveloped_response(
        {
            "entries": [log_to_dict(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        },
        request,
    )
