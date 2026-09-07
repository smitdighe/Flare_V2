"""Detection rules and their precedence. PLAN Part D / §4.1 / CONTRACT §3.

**PRECEDENCE: RULES BEAT EVERYTHING.**

    trained model  <  intel escalation  <  RULES

The rules node runs LAST in the graph and its actions overwrite both the
model's verdict and any upgrade intel applied. That ordering is a policy
decision with a reason: a rule is an operator's explicit, written instruction
about their own network. The model generalises from a 2017 test-bed capture and
intel generalises from what the internet has seen; neither knows that
10.0.0.7 is the payments database. When an operator has written the rule down,
the operator wins.

Every override is recorded — the rule id, the rule name, the from-value and the
to-value — so a severity on screen is always traceable to whatever produced it.
A rule that silently changed a verdict would be indistinguishable from a model
that produced it, which is the failure mode this whole design is arranged
against.

**PHASE 4 — THE ACTIONS ARE LIVE.** `set_severity`, `add_tag` and
`set_attack_type` all mutate the alert for real (PLAN §4.1, T14): the severity
lands on the payload, the tag lands in `alerts.tags`, the attack type lands on
the vector column and the filter. In the prior codebase the whole rules module
was unreachable dead code, which is why "wired live" is stated as a property
here and asserted by a test rather than assumed.

Storage lives in `app/rules/store.py` (PLAN D33 — the engine shipped in Phase 3,
persistence in Phase 4). This module still knows nothing about the database:
it takes `Rule` objects and evaluates them, which is what lets the same engine
be exercised by a unit test with no session at all.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

from app.ingestion.labels import CANONICAL_CLASSES, SEVERITY_ORDER, severity_rank
from app.rules.safety import MatchOutcome, PatternTooComplex, compile_pattern, safe_search

Operator = Literal[
    "eq", "ne", "gt", "gte", "lt", "lte", "in", "contains", "cidr"
]

# The three PLAN §4.1 names, and no others. `tag` is accepted as an alias for
# `add_tag` because Phase 3's vocabulary used the short form; it normalises at
# construction so there is exactly ONE set of action names inside the engine.
# Phase 3's `suppress` is gone: nothing suppressed anything, and an action that
# records itself and changes nothing is the bookkeeping-that-pretends this
# phase exists to remove.
ActionType = Literal["set_severity", "add_tag", "set_attack_type"]

_ACTION_ALIASES: dict[str, str] = {"tag": "add_tag"}

RuleAction = ActionType  # back-compatible name used by Phase 3 call sites

Logic = Literal["AND", "OR"]


@dataclass(frozen=True)
class RegexBounds:
    """PLAN §9 — the three numbers that bound a user-supplied pattern."""

    max_length: int
    max_quantifiers: int
    match_timeout_seconds: float
    max_subject_length: int


@lru_cache(maxsize=1)
def default_bounds() -> RegexBounds:
    """Bounds from config, read once.

    A lazy read rather than an import-time one: `app.config` builds Settings
    from the environment, and the engine must stay importable by a unit test
    that never touches settings.
    """
    from app.config import get_settings

    settings = get_settings()
    return RegexBounds(
        max_length=settings.rule_regex_max_length,
        max_quantifiers=settings.rule_regex_max_quantifiers,
        match_timeout_seconds=settings.rule_regex_match_timeout_seconds,
        max_subject_length=settings.rule_regex_max_subject_length,
    )


@dataclass(frozen=True)
class Condition:
    field: str
    operator: Operator
    value: Any
    bounds: RegexBounds | None = None

    def __post_init__(self) -> None:
        # `contains` is the only operator that compiles user input. Compiling
        # HERE means a pathological pattern is rejected while the rule is being
        # created, not on the first alert that happens to hit it.
        if self.operator == "contains":
            bounds = self.bounds or default_bounds()
            object.__setattr__(
                self,
                "_pattern",
                compile_pattern(
                    str(self.value),
                    max_length=bounds.max_length,
                    max_quantifiers=bounds.max_quantifiers,
                ),
            )
            object.__setattr__(self, "_bounds", bounds)

    def evaluate(self, alert: dict[str, Any]) -> tuple[bool, Any, str | None]:
        """Returns (result, actual, note). `actual` is what the drawer renders."""
        actual = alert.get(self.field)
        if self.operator == "contains":
            outcome = self._contains(actual)
            return outcome.matched, actual, outcome.note
        try:
            return self._apply(actual), actual, None
        except (TypeError, ValueError):
            # A comparison that cannot be made is FALSE, not an exception that
            # kills the stage. The condition is reported with its actual value
            # so the mismatch is visible in the rule trace.
            return False, actual, None

    def _contains(self, actual: Any) -> MatchOutcome:
        pattern = getattr(self, "_pattern", None)
        bounds = getattr(self, "_bounds", None) or default_bounds()
        if pattern is None:  # pragma: no cover - __post_init__ always sets it
            return MatchOutcome(matched=False, note="pattern was not compiled")
        return safe_search(
            pattern,
            "" if actual is None else str(actual),
            timeout_seconds=bounds.match_timeout_seconds,
            max_subject_length=bounds.max_subject_length,
        )

    def _apply(self, actual: Any) -> bool:
        match self.operator:
            case "eq":
                return bool(actual == self.value)
            case "ne":
                return bool(actual != self.value)
            case "gt":
                return float(actual) > float(self.value)
            case "gte":
                return float(actual) >= float(self.value)
            case "lt":
                return float(actual) < float(self.value)
            case "lte":
                return float(actual) <= float(self.value)
            case "in":
                return actual in self.value
            case "cidr":
                return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(
                    str(self.value), strict=False
                )
        return False


@dataclass(frozen=True)
class Action:
    """One live action. PLAN §4.1 — all three of these mutate the alert."""

    type: str
    value: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "type", _ACTION_ALIASES.get(self.type, self.type))
        if self.type == "set_severity" and self.value not in SEVERITY_ORDER:
            raise ValueError(
                f"set_severity value {self.value!r} is not one of {SEVERITY_ORDER}. "
                "`unknown` is a failure state, not a severity a rule may assign "
                "(PLAN D27)."
            )
        if self.type == "set_attack_type" and self.value not in CANONICAL_CLASSES:
            raise ValueError(
                f"set_attack_type value {self.value!r} is not one of "
                f"{CANONICAL_CLASSES}. A rule may not invent a class the vector "
                "filter and the eval have never heard of."
            )
        if self.type == "add_tag" and not (self.value or "").strip():
            raise ValueError("add_tag needs a non-empty tag value.")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    conditions: tuple[Condition, ...]
    # Phase 3's single-action form. Kept because it reads well for a
    # one-action rule and because the Phase 3 precedence tests are written in
    # it; it normalises into `actions` so the engine has ONE representation.
    action: str | None = None
    severity: str | None = None
    actions: tuple[Action, ...] = ()
    enabled: bool = True
    logic: Logic = "AND"

    def __post_init__(self) -> None:
        if not self.actions and self.action:
            object.__setattr__(self, "actions", (Action(self.action, self.severity),))
        for action in self.actions:
            if action.type == "set_severity" and action.value not in SEVERITY_ORDER:
                raise ValueError(
                    f"rule {self.id!r} sets severity to {action.value!r}, which is "
                    f"not one of {SEVERITY_ORDER}."
                )


@dataclass
class ConditionTrace:
    field: str
    operator: str
    expected: Any
    actual: Any
    result: bool
    note: str | None = None


@dataclass
class RuleTrace:
    """The per-condition fire trace the drawer renders. CONTRACT §2.6 #16."""

    rule_id: str
    rule_name: str
    fired: bool
    conditions: list[ConditionTrace] = field(default_factory=list)
    action: str | None = None
    from_severity: str | None = None
    to_severity: str | None = None
    applied: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class RuleResult:
    """Everything the rules stage changed, and why.

    One object rather than a tuple of three because the caller has to apply all
    of it together — a severity written without its trace is exactly the
    unattributable override this module exists to prevent.
    """

    severity: str
    attack_type: str
    tags: list[str]
    traces: list[RuleTrace]

    @property
    def fired(self) -> list[RuleTrace]:
        return [t for t in self.traces if t.fired]


class RuleEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = list(rules or [])

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    def evaluate(self, alert: dict[str, Any]) -> list[RuleTrace]:
        """Every enabled rule, in order, with a full per-condition trace.

        ALL rules are evaluated even after one fires — the drawer shows why each
        rule did or did not match, and short-circuiting would leave the analyst
        looking at an empty list for the rules that were never reached.
        """
        traces: list[RuleTrace] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            conditions: list[ConditionTrace] = []
            for condition in rule.conditions:
                result, actual, note = condition.evaluate(alert)
                conditions.append(
                    ConditionTrace(
                        field=condition.field,
                        operator=condition.operator,
                        expected=condition.value,
                        actual=actual,
                        result=result,
                        note=note,
                    )
                )
            fired = _fired(conditions, rule.logic)
            traces.append(
                RuleTrace(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    fired=fired,
                    conditions=conditions,
                    action=rule.actions[0].type if fired and rule.actions else None,
                )
            )
        return traces

    def run(self, alert: dict[str, Any]) -> RuleResult:
        """Evaluate, then apply every action of every firing rule, in order.

        The LAST firing rule wins for a given field, so rule order is the
        operator's precedence and it is deterministic. `add_tag` accumulates
        instead of overwriting, because tags are a set and two rules tagging an
        alert are both right.
        """
        traces = self.evaluate(alert)
        severity = str(alert.get("severity", "unknown"))
        attack_type = str(alert.get("attack_type", "unknown"))
        raw_tags = alert.get("tags")
        tags: list[str] = list(raw_tags) if isinstance(raw_tags, list) else []

        by_id = {rule.id: rule for rule in self._rules}
        for trace in traces:
            if not trace.fired:
                continue
            rule = by_id[trace.rule_id]
            for action in rule.actions:
                if action.type == "set_severity" and action.value:
                    trace.from_severity = severity
                    trace.to_severity = action.value
                    trace.applied.append(
                        {"type": action.type, "from": severity, "to": action.value}
                    )
                    severity = action.value
                elif action.type == "set_attack_type" and action.value:
                    trace.applied.append(
                        {
                            "type": action.type,
                            "from": attack_type,
                            "to": action.value,
                        }
                    )
                    attack_type = action.value
                elif action.type == "add_tag" and action.value:
                    tag = action.value.strip()
                    if tag not in tags:
                        tags.append(tag)
                    trace.applied.append({"type": action.type, "to": tag})

        return RuleResult(
            severity=severity, attack_type=attack_type, tags=tags, traces=traces
        )

    def apply(self, alert: dict[str, Any]) -> tuple[str, list[RuleTrace]]:
        """Back-compatible view of `run` — (severity_after_rules, traces).

        A thin delegation, not a second evaluation path: there is one place
        where a condition is decided and one place where an action is applied.
        """
        result = self.run(alert)
        return result.severity, result.traces


def _fired(conditions: list[ConditionTrace], logic: Logic) -> bool:
    """A rule with no conditions never fires, under either logic.

    An empty AND is vacuously true and an empty OR is vacuously false; both
    answers are wrong here for the same reason — a rule with nothing to match
    on is a half-written rule, and half-written rules do not get to change
    verdicts.
    """
    if not conditions:
        return False
    if logic == "OR":
        return any(c.result for c in conditions)
    return all(c.result for c in conditions)


def default_rule_set() -> list[Rule]:
    """EMPTY. PLAN I9 — no seeded fake data, in any environment.

    Phase 4 loads the real set from the database at startup and after every
    write (`app/rules/store.py`). This function is what the engine falls back to
    before that load has happened, and it deliberately returns nothing: a
    shipped example rule would be fake data in every environment, and a demo
    rule that fired would make the precedence look proven when it was staged.
    """
    return []


_engine: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine(default_rule_set())
    return _engine


def set_rule_engine(engine: RuleEngine) -> None:
    """The seam Phase 4's store writes through, and tests assert precedence on."""
    global _engine
    _engine = engine


def reset_rule_engine() -> None:
    global _engine
    _engine = None


def severity_is_upgrade(before: str, after: str) -> bool:
    return severity_rank(after) > severity_rank(before)


__all__ = [
    "Action",
    "Condition",
    "ConditionTrace",
    "PatternTooComplex",
    "RegexBounds",
    "Rule",
    "RuleEngine",
    "RuleResult",
    "RuleTrace",
    "default_bounds",
    "default_rule_set",
    "get_rule_engine",
    "reset_rule_engine",
    "set_rule_engine",
    "severity_is_upgrade",
]
