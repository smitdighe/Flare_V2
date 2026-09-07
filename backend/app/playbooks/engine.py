"""Playbook execution — a state machine that actually runs. PLAN §4.1 / T14.

**THE THREE STEP TYPES ARE BRANCHED ON FOR REAL.** PLAN §4.1 is explicit that
`auto` and `approval` must be branched on or the `type` field removed, with no
bookkeeping that pretends. They are:

| type       | who advances it                | what happens                       |
|------------|--------------------------------|------------------------------------|
| `manual`   | the owner (or an admin)        | marked complete, notes recorded    |
| `approval` | an ANALYST or ADMIN only       | approver recorded on the step      |
| `auto`     | THE ENGINE — no human at all   | snapshots the alert, then advances |

A viewer completing a `manual` step on their own execution is fine; a viewer
completing an `approval` step is a 403, because an approval that anybody can
grant is not an approval. A human posting to an `auto` step is a 409, because
that step is not waiting for anyone — the difference is observable from the
API, which is what makes the branch real rather than decorative.

**WHAT AN `auto` STEP ACTUALLY DOES.** The frozen step shape is
`{type, title, description}` — free text, no machine-readable action — so an
auto step cannot be handed an arbitrary command to run without inventing a
vocabulary nothing emits. What it does instead is real work with a real
artifact: it reads the linked alert and records a SNAPSHOT of its triaged state
(severity, attack type, MITRE technique, IOC reputation, how many rules fired)
into the step notes, attributed to `system`, then advances. That is data which
did not exist before the step ran, stored where an analyst can read it, and it
is why the step can FAIL: if the execution names an alert that cannot be read
at the moment the step runs, there is nothing to snapshot and the run stops as
`failed` rather than claiming a step it did not do.

**ALL THREE TERMINAL STATUSES ARE REAL** (CONTRACT §9.6):

  completed  every step done
  failed     an `auto` step could not do its work — recorded with the reason
  cancelled  the playbook was deleted while the run was in flight

None of them is collapsed into another. FE-10 stops the 3-second poller on any
of the three; the frozen poller stops only on `completed`, which is why that
change is sanctioned.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ingestion.labels import meets_threshold
from app.store.models import Alert, Playbook, PlaybookExecution, as_utc, utcnow

logger = logging.getLogger("flare.playbooks")

STEP_TYPES: frozenset[str] = frozenset({"manual", "auto", "approval"})
APPROVAL_ROLES: frozenset[str] = frozenset({"analyst", "admin"})

TERMINAL_STATUSES: frozenset[str] = frozenset({"completed", "failed", "cancelled"})


class StepConflict(RuntimeError):
    """The step is not the current step, or is not waiting for a human. 409."""


class ApprovalDenied(RuntimeError):
    """An approval step reached by someone who cannot approve. 403."""


# ---------------------------------------------------------------------------
# serialization
# ---------------------------------------------------------------------------


def execution_to_dict(row: PlaybookExecution) -> dict[str, Any]:
    """CONTRACT Execution — the WHOLE body becomes the component's state.

    `completed_steps` is an array of ZERO-BASED INDICES because the UI calls
    `.includes(i)` on it (WorkspacePanel.jsx:944), and `current_step` is an
    integer index compared with `===` (WorkspacePanel.jsx:945). Neither is an
    id and neither is a title.
    """
    return {
        "id": row.id,
        "status": row.status,
        "alert_id": row.alert_id,
        "playbook_id": row.playbook_id,
        "steps": row.steps or [],
        "completed_steps": row.completed_steps or [],
        "current_step": row.current_step,
        "step_notes": row.step_notes or [],
        "terminal_reason": row.terminal_reason,
        "triggered_by": row.triggered_by,
        "created_at": as_utc(row.created_at).isoformat(),
        "updated_at": as_utc(row.updated_at).isoformat(),
    }


def playbook_to_dict(row: Playbook, execution_count: int) -> dict[str, Any]:
    """CONTRACT Playbook. `execution_count` is a REAL count (PLAN I2)."""
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "alert_type": row.alert_type,
        "severity_threshold": row.severity_threshold,
        "steps": row.steps or [],
        "execution_count": execution_count,
        "is_enabled": row.is_enabled,
        "created_at": as_utc(row.created_at).isoformat(),
    }


# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------


def matches_alert(playbook: Playbook, *, attack_type: str, severity: str) -> bool:
    """Does this alert satisfy the playbook's scope? PLAN D27.

    An empty `alert_type` means any type and an empty `severity_threshold`
    means any severity. `unknown` severity satisfies NOTHING: it means
    classification failed, and treating a pipeline failure as "at least high"
    would fire real response actions on our own bugs. `meets_threshold` fails
    closed for exactly this reason.
    """
    if not playbook.is_enabled:
        return False
    wanted = (playbook.alert_type or "").strip()
    if wanted and wanted.lower() != attack_type.lower():
        return False
    return meets_threshold(severity, playbook.severity_threshold)


# ---------------------------------------------------------------------------
# the state machine
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _note(
    execution: PlaybookExecution,
    index: int,
    *,
    text: str,
    by: str,
    kind: str,
    data: dict[str, Any] | None = None,
) -> None:
    entry: dict[str, Any] = {
        "step_index": index,
        "note": text,
        "by": by,
        "kind": kind,
        "at": _now().isoformat(),
    }
    if data:
        entry["data"] = data
    execution.step_notes = [*(execution.step_notes or []), entry]


def _finish(execution: PlaybookExecution, status: str, reason: str | None) -> None:
    execution.status = status
    execution.terminal_reason = reason
    execution.updated_at = utcnow()


async def _snapshot_alert(
    session: AsyncSession, execution: PlaybookExecution, index: int
) -> None:
    """The real work an `auto` step does. Raises if the alert cannot be read."""
    if not execution.alert_id:
        _note(
            execution,
            index,
            text=(
                "completed automatically. This execution is not linked to an "
                "alert, so there was no alert state to record."
            ),
            by="system",
            kind="auto",
        )
        return

    alert = await session.get(Alert, execution.alert_id)
    if alert is None:
        raise LookupError(
            f"alert {execution.alert_id} could not be read when this step ran, "
            "so there was nothing to act on"
        )

    fired = sum(1 for entry in (alert.rule_trace or []) if entry.get("fired"))
    data = {
        "alert_id": alert.id,
        "severity": alert.severity,
        "attack_type": alert.attack_type,
        "mitre_technique": alert.mitre_technique,
        "ioc_reputation": alert.ioc_reputation,
        "rules_fired": fired,
        "tags": list(alert.tags or []),
    }
    _note(
        execution,
        index,
        text=(
            f"completed automatically; recorded {alert.id} as "
            f"{alert.severity}/{alert.attack_type} with {fired} rule(s) fired"
        ),
        by="system",
        kind="auto",
        data=data,
    )


async def advance(session: AsyncSession, execution: PlaybookExecution) -> None:
    """Run every leading `auto` step, then stop at the first human gate.

    Called on start and after every human step completion, so a run made
    entirely of `auto` steps finishes without anyone touching it — which is the
    observable difference between `auto` and `manual`.
    """
    if execution.status in TERMINAL_STATUSES:
        return

    steps = execution.steps or []
    while True:
        index = execution.current_step
        if index >= len(steps):
            _finish(
                execution,
                "completed",
                f"all {len(steps)} step(s) completed",
            )
            return

        step = steps[index]
        if str(step.get("type", "manual")) != "auto":
            execution.status = "in_progress"
            execution.updated_at = utcnow()
            return

        try:
            await _snapshot_alert(session, execution, index)
        except LookupError as exc:
            _note(
                execution,
                index,
                text=f"failed: {exc}",
                by="system",
                kind="auto_failed",
            )
            _finish(
                execution,
                "failed",
                f"step {index} ({step.get('title') or 'untitled'}) could not run: {exc}",
            )
            return

        execution.completed_steps = [*(execution.completed_steps or []), index]
        execution.current_step = index + 1
        execution.updated_at = utcnow()


async def start_execution(
    session: AsyncSession,
    playbook: Playbook,
    *,
    owner_id: int | None,
    alert_id: str | None,
    triggered_by: str = "manual",
) -> PlaybookExecution:
    """Create the run and immediately advance it. PLAN T14.

    `steps` is SNAPSHOTTED here. Editing the playbook mid-run must not rewrite
    the history of a run already in progress, and deleting it must not erase
    the record that it ran.
    """
    execution = PlaybookExecution(
        playbook_id=playbook.id,
        owner_id=owner_id,
        alert_id=alert_id,
        status="pending",
        steps=list(playbook.steps or []),
        completed_steps=[],
        current_step=0,
        step_notes=[],
        triggered_by=triggered_by,
    )
    session.add(execution)
    await session.flush()
    await advance(session, execution)
    return execution


async def complete_step(
    session: AsyncSession,
    execution: PlaybookExecution,
    index: int,
    *,
    notes: str,
    actor_id: int | None,
    actor_role: str,
) -> PlaybookExecution:
    """Complete ONE human step, then let the engine run whatever follows."""
    if execution.status in TERMINAL_STATUSES:
        raise StepConflict(
            f"This execution is already {execution.status} and cannot be changed."
        )

    steps = execution.steps or []
    if index < 0 or index >= len(steps):
        raise StepConflict(f"Step {index} does not exist on this execution.")
    if index in (execution.completed_steps or []):
        raise StepConflict(f"Step {index} is already completed.")
    if index != execution.current_step:
        raise StepConflict(
            f"Step {index} is not the current step (the run is on step "
            f"{execution.current_step})."
        )

    step = steps[index]
    step_type = str(step.get("type", "manual"))

    if step_type == "auto":
        raise StepConflict(
            f"Step {index} is an automatic step. It is run by the system and is "
            "not waiting for anyone."
        )
    if step_type == "approval" and actor_role not in APPROVAL_ROLES:
        raise ApprovalDenied(
            "This step needs an approval, and your role cannot approve. An "
            "approval anyone can grant is not an approval."
        )

    text = notes.strip() if notes and notes.strip() else "completed"
    _note(
        execution,
        index,
        text=text,
        by=f"user:{actor_id}" if actor_id is not None else "unknown",
        kind="approved" if step_type == "approval" else "manual",
    )
    execution.completed_steps = [*(execution.completed_steps or []), index]
    execution.current_step = index + 1
    execution.updated_at = utcnow()

    await advance(session, execution)
    return execution


async def cancel_for_playbook(
    session: AsyncSession, playbook_id: int, *, reason: str
) -> list[int]:
    """CONTRACT §9.6 — `cancelled` is a real outcome with a real producer.

    Deleting a playbook that has runs in flight cancels them. Leaving them
    `in_progress` would show the analyst a run that can never finish, and
    marking them `completed` would claim work that did not happen.
    """
    rows = list(
        (
            await session.execute(
                select(PlaybookExecution).where(
                    PlaybookExecution.playbook_id == playbook_id,
                    PlaybookExecution.status.notin_(sorted(TERMINAL_STATUSES)),
                )
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        _finish(row, "cancelled", reason)
    return [row.id for row in rows]


async def autotrigger(
    session: AsyncSession, *, alert_id: str, attack_type: str, severity: str
) -> list[PlaybookExecution]:
    """Start every enabled playbook whose scope this alert satisfies.

    This is what makes `alert_type` and `severity_threshold` load-bearing
    rather than decorative, and what makes `execution_count` a real number.

    There is a partial unique index on (playbook_id, alert_id) for auto runs,
    so a replay loop revisiting the same alert id does not start a second run.
    The check here is the cheap path; the index is the guarantee.
    """
    playbooks = list(
        (
            await session.execute(
                select(Playbook).where(Playbook.is_enabled.is_(True))
            )
        )
        .scalars()
        .all()
    )
    if not playbooks:
        return []

    started: list[PlaybookExecution] = []
    for playbook in playbooks:
        if not matches_alert(playbook, attack_type=attack_type, severity=severity):
            continue
        existing = (
            await session.execute(
                select(PlaybookExecution.id).where(
                    PlaybookExecution.playbook_id == playbook.id,
                    PlaybookExecution.alert_id == alert_id,
                    PlaybookExecution.triggered_by == "auto",
                )
            )
        ).first()
        if existing is not None:
            continue
        started.append(
            await start_execution(
                session,
                playbook,
                owner_id=playbook.owner_id,
                alert_id=alert_id,
                triggered_by="auto",
            )
        )
    return started


def validate_steps(raw: Any) -> list[dict[str, Any]]:
    """Steps with an empty title are stripped client-side, so [] is legal."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("`steps` must be a list.")
    if len(raw) > 50:
        raise ValueError("A playbook may carry at most 50 steps.")

    cleaned: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"Step {index + 1} is not an object.")
        step_type = str(item.get("type", "manual"))
        if step_type not in STEP_TYPES:
            raise ValueError(
                f"Step {index + 1}: {step_type!r} is not a step type. "
                f"Available: {', '.join(sorted(STEP_TYPES))}."
            )
        title = str(item.get("title") or item.get("label") or "").strip()
        if not title:
            raise ValueError(f"Step {index + 1} needs a title.")
        description = item.get("description")
        cleaned.append(
            {
                "type": step_type,
                # `title` is canonical; the render path falls back to `label`,
                # which is a legacy alias (WorkspacePanel.jsx:951, :992).
                "title": title[:300],
                "description": (str(description)[:1000] if description else None),
            }
        )
    return cleaned
