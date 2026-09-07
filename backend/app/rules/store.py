"""Rule persistence and the DB→engine mapping. PLAN D33 / §9 / CONTRACT §2.6.

The engine in `app/rules/engine.py` knows nothing about the database and the
database knows nothing about evaluation. This module is the only join between
them, and it does three jobs:

**TRANSLATE.** The frozen UI speaks `equals` / `not_equals` / `greater_than` /
`contains`; the engine speaks `eq` / `ne` / `gt` / `contains`. The UI also sends
every value as a STRING, even for `dest_port` and `greater_than`
(WorkspacePanel.jsx:739), so `dest_port equals 443` arrives as `"443"` and
would compare false against the integer 443 forever. Coercion happens here,
once, rather than in the engine where it would have to guess.

**VALIDATE AT WRITE TIME.** A pathological regex, an unknown severity, an
invented attack type — all rejected when the rule is created, with a message
the frozen frontend renders verbatim through its `detail` path
(WorkspacePanel.jsx:685). Rejecting at evaluation time instead would mean the
operator finds out when the feed misbehaves.

**KEEP THE ENGINE HOT.** The rules node runs inside the graph, once per alert.
It must not touch the database there — that is an extra async round trip on the
hot path and a second failure mode for the stream. Instead the engine singleton
is REBUILT from the database at startup and after every write, and the node
reads the in-memory set.

**SCOPE — STATED, NOT FUDGED.** Rules are AUTHORED per user and ENFORCED
deployment-wide. The API scopes every read, update and delete to the owner
(PLAN §9, IDOR), but the pipeline evaluates every enabled rule from every
owner, because this is a single-tenant SOC by design (PLAN §17 cuts
multi-tenancy explicitly) and a rule is a statement about the network, not
about a user. The consequence is visible rather than hidden: every fire is
attributed by rule id and name in the drawer's trace, and the audit log records
who created it.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.ingestion.labels import CANONICAL_CLASSES, SEVERITY_ORDER
from app.rules.engine import (
    Action,
    Condition,
    Rule,
    RuleEngine,
    RuleTrace,
    set_rule_engine,
)
from app.rules.safety import PatternTooComplex
from app.store.models import Rule as RuleRow
from app.store.models import as_utc

# CONTRACT RuleCondition.operator — the four the UI offers, mapped onto the
# engine's vocabulary. Anything else is rejected by name rather than silently
# treated as equality.
OPERATOR_MAP: dict[str, str] = {
    "equals": "eq",
    "not_equals": "ne",
    "greater_than": "gt",
    "contains": "contains",
}

# The UI offers four fields (WorkspacePanel.jsx:727-730). The backend accepts a
# superset, for the same reason it accepts all three actions while the UI can
# only create one: PLAN §4.1 specifies the capability, and the frozen form is a
# limit on this frontend, not on the rule engine. Every field here is one the
# rules node genuinely puts on the alert view, so none of them can be a
# condition that is silently always false.
ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "severity",
        "attack_type",
        "src_ip",
        "dest_ip",
        "dest_port",
        "protocol",
        "signature",
        "mitre_technique",
        "ioc_reputation",
        "confidence",
        "source",
    }
)

NUMERIC_FIELDS: frozenset[str] = frozenset({"dest_port", "ioc_reputation", "confidence"})

ACTION_TYPES: frozenset[str] = frozenset({"set_severity", "add_tag", "set_attack_type"})

MAX_CONDITIONS = 16
MAX_ACTIONS = 8


class RuleValidationError(ValueError):
    """A rule body that cannot be turned into a rule. Surfaces as a 422."""


# ---------------------------------------------------------------------------
# validation — write time
# ---------------------------------------------------------------------------


def _coerce(field: str, value: Any) -> Any:
    """String from the form -> the type the alert actually carries.

    `dest_port equals "443"` has to compare true against the integer 443. The
    engine's ordered comparisons already float-cast, but equality does not and
    must not: coercing everywhere would make `severity equals 0` mean something.
    """
    if field not in NUMERIC_FIELDS or not isinstance(value, str):
        return value
    text = value.strip()
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return value


def validate_conditions(payload: Any) -> dict[str, Any]:
    """CONTRACT RuleConditionGroup — {logic, conditions[]}, note the nesting."""
    if not isinstance(payload, dict):
        raise RuleValidationError(
            "`conditions` must be an object of the form "
            '{"logic": "AND", "conditions": [...]}.'
        )
    logic = str(payload.get("logic", "AND")).upper()
    if logic not in ("AND", "OR"):
        raise RuleValidationError("`conditions.logic` must be either AND or OR.")

    raw = payload.get("conditions")
    if not isinstance(raw, list) or not raw:
        raise RuleValidationError("A rule needs at least one condition.")
    if len(raw) > MAX_CONDITIONS:
        raise RuleValidationError(
            f"A rule may carry at most {MAX_CONDITIONS} conditions."
        )

    cleaned: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise RuleValidationError(f"Condition {index + 1} is not an object.")
        field = str(item.get("field", ""))
        operator = str(item.get("operator", ""))
        if field not in ALLOWED_FIELDS:
            raise RuleValidationError(
                f"Condition {index + 1}: {field!r} is not a field an alert has. "
                f"Available: {', '.join(sorted(ALLOWED_FIELDS))}."
            )
        if operator not in OPERATOR_MAP:
            raise RuleValidationError(
                f"Condition {index + 1}: {operator!r} is not a supported "
                f"operator. Available: {', '.join(sorted(OPERATOR_MAP))}."
            )
        if "value" not in item:
            raise RuleValidationError(f"Condition {index + 1} has no value.")
        cleaned.append(
            {"field": field, "operator": operator, "value": item["value"]}
        )

    return {"logic": logic, "conditions": cleaned}


def validate_actions(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload:
        raise RuleValidationError("A rule needs at least one action.")
    if len(payload) > MAX_ACTIONS:
        raise RuleValidationError(f"A rule may carry at most {MAX_ACTIONS} actions.")

    cleaned: list[dict[str, Any]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise RuleValidationError(f"Action {index + 1} is not an object.")
        action_type = str(item.get("type", ""))
        value = item.get("value")
        if action_type not in ACTION_TYPES:
            raise RuleValidationError(
                f"Action {index + 1}: {action_type!r} is not a supported action. "
                f"Available: {', '.join(sorted(ACTION_TYPES))}."
            )
        if action_type == "set_severity" and value not in SEVERITY_ORDER:
            raise RuleValidationError(
                f"Action {index + 1}: set_severity must be one of "
                f"{', '.join(SEVERITY_ORDER)}. `unknown` means the pipeline "
                "failed and is not a severity a rule may assign."
            )
        if action_type == "set_attack_type" and value not in CANONICAL_CLASSES:
            raise RuleValidationError(
                f"Action {index + 1}: set_attack_type must be one of "
                f"{', '.join(CANONICAL_CLASSES)}."
            )
        if action_type == "add_tag" and not str(value or "").strip():
            raise RuleValidationError(f"Action {index + 1}: add_tag needs a tag.")
        cleaned.append({"type": action_type, "value": value})
    return cleaned


def to_engine_rule(row: RuleRow) -> Rule:
    """One stored row -> one engine rule. Raises on anything unbuildable."""
    group = row.conditions if isinstance(row.conditions, dict) else {}
    logic = str(group.get("logic", "AND")).upper()
    raw_conditions = group.get("conditions") or []

    conditions = tuple(
        Condition(
            field=str(item["field"]),
            operator=OPERATOR_MAP[str(item["operator"])],  # type: ignore[arg-type]
            value=_coerce(str(item["field"]), item.get("value")),
        )
        for item in raw_conditions
    )
    actions = tuple(
        Action(str(item["type"]), item.get("value")) for item in (row.actions or [])
    )
    return Rule(
        id=str(row.id),
        name=row.name,
        conditions=conditions,
        actions=actions,
        enabled=row.is_enabled,
        logic="OR" if logic == "OR" else "AND",
    )


def validate_buildable(
    name: str, conditions: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """Build the rule once, before storing it. PLAN §9.

    This is where a ReDoS-shaped `contains` pattern is rejected: `Condition`
    compiles it under the static bounds and raises. Doing it here means the
    failure is a 422 on the create call carrying the reason, rather than a rule
    sitting in the database waiting to stall the feed.
    """
    row = RuleRow(id=0, name=name, conditions=conditions, actions=actions, is_enabled=True)
    try:
        to_engine_rule(row)
    except PatternTooComplex as exc:
        raise RuleValidationError(str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise RuleValidationError(str(exc)) from exc


# ---------------------------------------------------------------------------
# loading — read time
# ---------------------------------------------------------------------------


async def load_rules(session: AsyncSession) -> list[Rule]:
    """Every ENABLED rule, oldest first, skipping any that no longer build.

    Order is creation order, which is the operator's precedence: the last
    firing rule wins, so a rule written later deliberately overrides an earlier
    one. A row that cannot be built is skipped with a log line rather than
    taking the whole engine down — one malformed rule must not disable rule
    evaluation for every other rule.
    """
    import logging

    rows = list(
        (
            await session.execute(
                select(RuleRow)
                .where(RuleRow.is_enabled.is_(True))
                .order_by(RuleRow.id)
            )
        )
        .scalars()
        .all()
    )

    rules: list[Rule] = []
    for row in rows:
        try:
            rules.append(to_engine_rule(row))
        except Exception as exc:
            logging.getLogger("flare.rules").error(
                "rule %s could not be built and is not being evaluated: %s",
                row.id,
                exc,
                extra={"request_id": "-"},
            )
    return rules


async def refresh_rule_engine(session: AsyncSession) -> RuleEngine:
    """Rebuild the in-memory engine from the database and install it."""
    engine = RuleEngine(await load_rules(session))
    set_rule_engine(engine)
    return engine


async def bump_match_counts(session: AsyncSession, rule_ids: list[str]) -> None:
    """PLAN I2 — `match_count` is a real count of alerts this rule fired on.

    Called in the same transaction that persists the alert, so the counter and
    the alerts that produced it cannot disagree.
    """
    numeric = [int(rid) for rid in rule_ids if rid.isdigit()]
    if not numeric:
        return
    await session.execute(
        update(RuleRow)
        .where(RuleRow.id.in_(numeric))
        .values(match_count=RuleRow.match_count + 1)
    )


# ---------------------------------------------------------------------------
# serialization
# ---------------------------------------------------------------------------


def rule_to_dict(row: RuleRow) -> dict[str, Any]:
    """CONTRACT Rule — id, name, description, match_count, is_enabled."""
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "match_count": row.match_count,
        "is_enabled": row.is_enabled,
        "conditions": row.conditions,
        "actions": row.actions,
        "created_at": as_utc(row.created_at).isoformat(),
    }


def _rule_id(value: str) -> int | str:
    """The drawer uses `rule_id` as a React key and types it integer."""
    return int(value) if value.isdigit() else value


def trace_to_payload(traces: list[RuleTrace]) -> list[dict[str, Any]]:
    """CONTRACT §2.6 #16 — EVERY rule evaluated, fired or not.

    The key is named `matched_rules` and the UI renders the non-firing ones
    with a "no match" chip, so filtering to fired rules here would delete the
    drawer's best beat.
    """
    payload: list[dict[str, Any]] = []
    for trace in traces:
        conditions: list[dict[str, Any]] = []
        for condition in trace.conditions:
            entry: dict[str, Any] = {
                "field": condition.field,
                "operator": condition.operator,
                "expected": condition.expected,
                "actual": condition.actual,
                "result": condition.result,
            }
            if condition.note:
                entry["note"] = condition.note
            conditions.append(entry)
        payload.append(
            {
                "rule_id": _rule_id(trace.rule_id),
                "rule_name": trace.rule_name,
                "fired": trace.fired,
                "conditions": conditions,
                "actions_applied": trace.applied,
            }
        )
    return payload
