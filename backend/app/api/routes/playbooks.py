"""Playbooks CRUD and the execution state machine. CONTRACT §2.7.

**THREE PINNED ENVELOPE EXCEPTIONS LIVE HERE** (CONTRACT §1.3.1):
`GET /playbooks` (the frontend reads `d.playbooks`), `POST /{id}/execute` (it
reads `data.execution_id`) and `GET /executions/{id}` (the whole body becomes
component state). Everything else on this router takes the D17 envelope.

**SCOPE.** Playbooks are LISTED deployment-wide — the contract says "list
playbooks", the drawer's action picker needs the full set, and auto-triggering
is deployment-wide too, so an owner-scoped list would show an analyst a shorter
list than the one actually running. Mutation is owner-scoped: PUT and DELETE
against someone else's playbook are a 404, and executions are owner-scoped on
lookup (PLAN §9, IDOR). 404 rather than 403 on purpose — a 403 confirms the id
exists, which is the half of the answer an enumeration attack wants.

**`alert_id` ON EXECUTE IS OPTIONAL** (CONTRACT §9.9). With no alert selected
the frontend posts `…/execute?` with an empty query string
(WorkspacePanel.jsx:856-858); rejecting that breaks the Execute button on the
Playbooks screen.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.api.deps import CurrentUser, SessionDep
from app.api.envelope import enveloped_response
from app.api.errors import HTTP_422_UNPROCESSABLE, AppError
from app.ingestion.labels import SEVERITY_ORDER
from app.playbooks.engine import (
    ApprovalDenied,
    StepConflict,
    cancel_for_playbook,
    complete_step,
    execution_to_dict,
    playbook_to_dict,
    start_execution,
    validate_steps,
)
from app.store.models import Alert, Playbook, PlaybookExecution
from app.store.repositories import write_audit

router = APIRouter(tags=["playbooks"])


class PlaybookInput(BaseModel):
    """WorkspacePanel.jsx:781 and :832 — used by both POST and PUT."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    # FREE TEXT, not an enum — the form field is a plain input
    # (WorkspacePanel.jsx:908) and "" is legal, meaning "any type".
    alert_type: str | None = Field(default=None, max_length=64)
    # "" means "any severity" (WorkspacePanel.jsx:910).
    severity_threshold: str | None = Field(default=None, max_length=10)
    steps: list[dict[str, Any]] = Field(default_factory=list)


class StepBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    notes: str = Field(default="", max_length=2000)


async def _execution_counts(session: SessionDep, ids: list[int]) -> dict[int, int]:
    """PLAN I2 — a real count, not a stored number that can drift."""
    if not ids:
        return {}
    rows = await session.execute(
        select(PlaybookExecution.playbook_id, func.count())
        .where(PlaybookExecution.playbook_id.in_(ids))
        .group_by(PlaybookExecution.playbook_id)
    )
    return {int(pid): int(count) for pid, count in rows.all() if pid is not None}


def _clean_input(body: PlaybookInput) -> dict[str, Any]:
    threshold = (body.severity_threshold or "").strip().lower()
    if threshold and threshold not in SEVERITY_ORDER:
        raise AppError(
            "validation_error",
            f"`severity_threshold` must be empty or one of "
            f"{', '.join(SEVERITY_ORDER)}. `unknown` is not a threshold — it "
            "means classification failed, and it satisfies none (PLAN D27).",
            HTTP_422_UNPROCESSABLE,
        )
    try:
        steps = validate_steps(body.steps)
    except ValueError as exc:
        raise AppError(
            "validation_error", str(exc), HTTP_422_UNPROCESSABLE
        ) from exc

    alert_type = (body.alert_type or "").strip()
    return {
        "name": body.name,
        "description": body.description or None,
        "alert_type": alert_type or None,
        "severity_threshold": threshold or None,
        "steps": steps,
    }


async def _owned(session: SessionDep, playbook_id: int, user_id: int) -> Playbook:
    row = (
        await session.execute(
            select(Playbook).where(
                Playbook.id == playbook_id, Playbook.owner_id == user_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise AppError("not_found", "Playbook not found.", status.HTTP_404_NOT_FOUND)
    return row


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


@router.get("/playbooks")
async def list_playbooks(
    request: Request, user: CurrentUser, session: SessionDep
) -> Any:
    """RAW — PINNED EXCEPTION. WorkspacePanel.jsx:791 reads `d.playbooks`."""
    rows = list(
        (await session.execute(select(Playbook).order_by(Playbook.id)))
        .scalars()
        .all()
    )
    counts = await _execution_counts(session, [row.id for row in rows])
    return {
        "playbooks": [
            playbook_to_dict(row, counts.get(row.id, 0)) for row in rows
        ]
    }


@router.post("/playbooks", status_code=status.HTTP_201_CREATED)
async def create_playbook(
    body: PlaybookInput, request: Request, user: CurrentUser, session: SessionDep
) -> Any:
    fields = _clean_input(body)
    row = Playbook(owner_id=user.id, is_enabled=True, **fields)
    session.add(row)
    await session.flush()

    await write_audit(
        session,
        action="playbook.create",
        resource_type="playbook",
        actor_id=user.id,
        resource_id=str(row.id),
        details={
            "name": row.name,
            "alert_type": row.alert_type,
            "severity_threshold": row.severity_threshold,
            "step_count": len(row.steps or []),
        },
    )
    await session.commit()
    return enveloped_response(
        playbook_to_dict(row, 0), request, status_code=status.HTTP_201_CREATED
    )


@router.put("/playbooks/{playbook_id}")
async def replace_playbook(
    playbook_id: int,
    body: PlaybookInput,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> Any:
    """Full replacement — the form always sends every field."""
    row = await _owned(session, playbook_id, user.id)
    fields = _clean_input(body)
    for key, value in fields.items():
        setattr(row, key, value)

    await write_audit(
        session,
        action="playbook.update",
        resource_type="playbook",
        actor_id=user.id,
        resource_id=str(row.id),
        details={"name": row.name, "step_count": len(row.steps or [])},
    )
    await session.commit()

    counts = await _execution_counts(session, [row.id])
    return enveloped_response(playbook_to_dict(row, counts.get(row.id, 0)), request)


@router.delete("/playbooks/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_playbook(
    playbook_id: int, request: Request, user: CurrentUser, session: SessionDep
) -> Response:
    """Deleting a playbook CANCELS its in-flight runs (CONTRACT §9.6).

    Leaving them `in_progress` would show a run that can never finish, and
    marking them `completed` would claim work that did not happen.
    """
    row = await _owned(session, playbook_id, user.id)
    cancelled = await cancel_for_playbook(
        session,
        playbook_id,
        reason=(
            f"playbook {playbook_id} ({row.name!r}) was deleted while this run "
            "was in flight"
        ),
    )

    await write_audit(
        session,
        action="playbook.delete",
        resource_type="playbook",
        actor_id=user.id,
        resource_id=str(playbook_id),
        details={"name": row.name, "cancelled_executions": cancelled},
    )
    await session.delete(row)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------


@router.post("/playbooks/{playbook_id}/execute", status_code=status.HTTP_201_CREATED)
async def execute_playbook(
    playbook_id: int,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
    alert_id: Annotated[str | None, Query()] = None,
) -> Any:
    """RAW — PINNED EXCEPTION. The frontend reads `data.execution_id`.

    The run does not merely get a row: `start_execution` advances it through
    every leading `auto` step before returning, so a playbook made entirely of
    automatic steps comes back already `completed` (PLAN T14).
    """
    playbook = (
        await session.execute(select(Playbook).where(Playbook.id == playbook_id))
    ).scalar_one_or_none()
    if playbook is None:
        raise AppError("not_found", "Playbook not found.", status.HTTP_404_NOT_FOUND)

    linked = (alert_id or "").strip() or None
    if linked is not None:
        alert = await session.get(Alert, linked)
        if alert is None:
            raise AppError(
                "not_found",
                f"Alert {linked} not found.",
                status.HTTP_404_NOT_FOUND,
            )

    execution = await start_execution(
        session,
        playbook,
        owner_id=user.id,
        alert_id=linked,
        triggered_by="manual",
    )
    await write_audit(
        session,
        action="playbook.execute",
        resource_type="playbook",
        actor_id=user.id,
        resource_id=str(playbook_id),
        details={
            "execution_id": execution.id,
            "alert_id": linked,
            "status": execution.status,
        },
    )
    await session.commit()
    return {"execution_id": execution.id}


async def _execution_for(
    session: SessionDep, execution_id: int, user: Any
) -> PlaybookExecution:
    """Owner-scoped on LOOKUP (PLAN §9). An admin may also act, for oversight."""
    row = await session.get(PlaybookExecution, execution_id)
    if row is None or (row.owner_id != user.id and user.role != "admin"):
        raise AppError(
            "not_found", "Execution not found.", status.HTTP_404_NOT_FOUND
        )
    return row


@router.get("/playbooks/executions/{execution_id}")
async def get_execution(
    execution_id: int, request: Request, user: CurrentUser, session: SessionDep
) -> Any:
    """RAW — PINNED EXCEPTION. The whole body becomes the component's state.

    Polled every 3 s while the status is non-terminal. FE-10 stops the poller
    on `completed`, `failed` OR `cancelled`; the frozen poller stops only on
    `completed` and would otherwise poll a failed run forever.
    """
    row = await _execution_for(session, execution_id, user)
    return execution_to_dict(row)


@router.post("/playbooks/executions/{execution_id}/steps/{step_index}")
async def complete_execution_step(
    execution_id: int,
    step_index: Annotated[int, Path(ge=0)],
    body: StepBody,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> Any:
    """Complete one human step. ENVELOPED — not on the pinned list.

    The frozen UI reads only `res.ok` here and then re-GETs the execution, so
    nothing constrains the body and it takes the D17 default (CONTRACT §9.8).

    An `auto` step is a 409: it is run by the system and is not waiting for
    anyone. An `approval` step reached by a viewer is a 403. Both are the
    branch PLAN §4.1 asks for, made observable from the API.
    """
    row = await _execution_for(session, execution_id, user)

    try:
        await complete_step(
            session,
            row,
            step_index,
            notes=body.notes,
            actor_id=user.id,
            actor_role=user.role,
        )
    except ApprovalDenied as exc:
        raise AppError("forbidden", str(exc), status.HTTP_403_FORBIDDEN) from exc
    except StepConflict as exc:
        raise AppError("conflict", str(exc), status.HTTP_409_CONFLICT) from exc

    await write_audit(
        session,
        action="playbook.step_complete",
        resource_type="playbook",
        actor_id=user.id,
        resource_id=str(row.playbook_id) if row.playbook_id else None,
        details={
            "execution_id": row.id,
            "step_index": step_index,
            "status": row.status,
            "has_notes": bool(body.notes.strip()),
        },
    )
    await session.commit()
    return enveloped_response(execution_to_dict(row), request)
