"""Rules CRUD and the drawer's per-condition fire trace. CONTRACT §2.6.

**TWO OF THESE FOUR ARE PINNED ENVELOPE EXCEPTIONS** (CONTRACT §1.3.1).
`GET /rules` returns a RAW `{rules: [...]}` because the frozen frontend reads
`d.rules` off the top level (WorkspacePanel.jsx:670), and
`GET /rules/alerts/{id}/explain-rules` returns a RAW body because the whole
body becomes the drawer's state (AlertDetailDrawer.jsx:38). Enveloping either
makes the read key undefined and the screen renders its empty state forever,
with no error anywhere.

**IDOR — OWNER-SCOPED ON LOOKUP, NOT JUST ON LIST** (PLAN §9). The delete path
filters by owner in the WHERE clause, so another user's rule id is a 404 rather
than a row that is fetched and then rejected. 404 rather than 403 on purpose:
403 confirms the id exists, which is the half of the answer an enumeration
attack wants.

**THE ACTION IS NOT EDITABLE IN THE FROZEN UI.** It is hardcoded to
`{type:"set_severity", value:"high"}` (WorkspacePanel.jsx:663), so `add_tag` and
`set_attack_type` cannot be created through this frontend even though both are
wired live. That is a limit of the frozen form, not of the API — an API client
can create either, and the rules node applies all three.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Path, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.api.deps import CurrentUser, SessionDep
from app.api.envelope import enveloped_response
from app.api.errors import HTTP_422_UNPROCESSABLE, AppError
from app.rules.store import (
    RuleValidationError,
    refresh_rule_engine,
    rule_to_dict,
    validate_actions,
    validate_buildable,
    validate_conditions,
)
from app.store.models import Alert
from app.store.models import Rule as RuleRow
from app.store.repositories import write_audit

router = APIRouter(tags=["rules"])

ALERT_ID_PATTERN = r"^ALT-[0-9A-F]{6}$"


class RuleCreate(BaseModel):
    """Exact body from WorkspacePanel.jsx:663 and :683.

    `conditions` and `actions` are validated by hand rather than by a nested
    model: the error text is rendered VERBATIM to the user through the
    frontend's `detail` path, and Pydantic's location-and-message shape reads
    like a stack trace in a form field.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    conditions: dict[str, Any]
    actions: list[dict[str, Any]]


@router.get("/rules")
async def list_rules(request: Request, user: CurrentUser, session: SessionDep) -> Any:
    """RAW — PINNED EXCEPTION. WorkspacePanel.jsx:670 reads `d.rules`."""
    rows = (
        (
            await session.execute(
                select(RuleRow)
                .where(RuleRow.owner_id == user.id)
                .order_by(RuleRow.id)
            )
        )
        .scalars()
        .all()
    )
    return {"rules": [rule_to_dict(row) for row in rows]}


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RuleCreate, request: Request, user: CurrentUser, session: SessionDep
) -> Any:
    """CONTRACT §9.8 — returns the created resource, ENVELOPED.

    Validation happens BEFORE the row is written and includes actually building
    the engine rule, so a pathological `contains` pattern is rejected here
    (PLAN §9, ReDoS) rather than sitting in the database waiting for the alert
    that stalls the feed.
    """
    try:
        conditions = validate_conditions(body.conditions)
        actions = validate_actions(body.actions)
        validate_buildable(body.name, conditions, actions)
    except RuleValidationError as exc:
        raise AppError(
            "validation_error", str(exc), HTTP_422_UNPROCESSABLE
        ) from exc

    row = RuleRow(
        owner_id=user.id,
        name=body.name,
        description=body.description or None,
        conditions=conditions,
        actions=actions,
        is_enabled=True,
        match_count=0,
    )
    session.add(row)
    await session.flush()

    await write_audit(
        session,
        action="rule.create",
        resource_type="rule",
        actor_id=user.id,
        resource_id=str(row.id),
        details={
            "name": row.name,
            "conditions": conditions,
            "actions": actions,
        },
    )
    await session.commit()

    # The rules node reads the in-memory engine, so a rule that is not loaded
    # here would exist in the database and change nothing about any alert.
    await refresh_rule_engine(session)

    return enveloped_response(
        rule_to_dict(row), request, status_code=status.HTTP_201_CREATED
    )


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int, request: Request, user: CurrentUser, session: SessionDep
) -> Response:
    """Owner-scoped. Another user's id is a 404, not a 403 (see module docstring)."""
    row = (
        await session.execute(
            select(RuleRow).where(RuleRow.id == rule_id, RuleRow.owner_id == user.id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise AppError("not_found", "Rule not found.", status.HTTP_404_NOT_FOUND)

    await write_audit(
        session,
        action="rule.delete",
        resource_type="rule",
        actor_id=user.id,
        resource_id=str(rule_id),
        details={"name": row.name, "match_count": row.match_count},
    )
    await session.delete(row)
    await session.commit()
    await refresh_rule_engine(session)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/rules/alerts/{alert_id}/explain-rules")
async def explain_rules(
    alert_id: Annotated[str, Path(pattern=ALERT_ID_PATTERN)],
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> Any:
    """RAW — PINNED EXCEPTION. The whole body becomes the drawer's state.

    Served from the trace recorded AT TRIAGE TIME, not recomputed against
    today's rule set. Recomputing would answer "what would the current rules
    say about this alert", which is a different question from "why does this
    alert look the way it does" — and the drawer is asking the second one. An
    alert triaged before any rule existed honestly returns an empty array, and
    the UI renders "No rules evaluated."

    DESPITE THE NAME, this contains EVERY rule evaluated, fired or not: the UI
    renders non-firing rules with a "no match" chip and the full per-condition
    breakdown, which is the strongest beat in the drawer.
    """
    alert = await session.get(Alert, alert_id)
    if alert is None:
        raise AppError("not_found", "Alert not found.", status.HTTP_404_NOT_FOUND)
    return {"matched_rules": alert.rule_trace or []}
