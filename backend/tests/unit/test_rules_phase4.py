"""Phase 4 rule engine: live actions, AND/OR, and the ReDoS bounds.

PLAN §4.1 requires `set_severity`, `add_tag` and `set_attack_type` to be wired
live and to actually mutate the alert (T14). PLAN §9 requires user-supplied
regex to be compiled with a complexity bound and matched with a timeout.
"""

from __future__ import annotations

import time

import pytest

from app.rules.engine import (
    Action,
    Condition,
    RegexBounds,
    Rule,
    RuleEngine,
)
from app.rules.safety import PatternTooComplex, compile_pattern, safe_search
from app.rules.store import (
    OPERATOR_MAP,
    RuleValidationError,
    to_engine_rule,
    trace_to_payload,
    validate_actions,
    validate_conditions,
)
from app.store.models import Rule as RuleRow

BOUNDS = RegexBounds(
    max_length=200,
    max_quantifiers=8,
    match_timeout_seconds=0.05,
    max_subject_length=1024,
)


def alert(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "severity": "medium",
        "attack_type": "port_scan",
        "src_ip": "118.25.6.39",
        "dest_ip": "10.0.0.7",
        "dest_port": 443,
        "signature": "Flow to TCP/443 — nominal exchange",
        "ioc_reputation": 12,
        "tags": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# the three actions actually change the alert
# ---------------------------------------------------------------------------


def test_set_severity_changes_the_severity() -> None:
    rule = Rule(
        id="1",
        name="raise port scans",
        conditions=(Condition("attack_type", "eq", "port_scan"),),
        actions=(Action("set_severity", "critical"),),
    )
    result = RuleEngine([rule]).run(alert())
    assert result.severity == "critical"
    assert result.traces[0].from_severity == "medium"
    assert result.traces[0].to_severity == "critical"


def test_add_tag_appends_and_does_not_duplicate() -> None:
    rules = [
        Rule(
            id="1",
            name="tag",
            conditions=(Condition("dest_port", "eq", 443),),
            actions=(Action("add_tag", "tls"),),
        ),
        Rule(
            id="2",
            name="tag again",
            conditions=(Condition("dest_port", "eq", 443),),
            actions=(Action("add_tag", "tls"),),
        ),
    ]
    result = RuleEngine(rules).run(alert(tags=["existing"]))
    assert result.tags == ["existing", "tls"]


def test_set_attack_type_changes_the_vector() -> None:
    rule = Rule(
        id="1",
        name="reclassify",
        conditions=(Condition("src_ip", "eq", "118.25.6.39"),),
        actions=(Action("set_attack_type", "botnet"),),
    )
    result = RuleEngine([rule]).run(alert())
    assert result.attack_type == "botnet"
    assert result.severity == "medium", "an attack-type action leaves severity alone"


def test_one_rule_can_carry_several_actions() -> None:
    rule = Rule(
        id="1",
        name="everything",
        conditions=(Condition("attack_type", "eq", "port_scan"),),
        actions=(
            Action("set_severity", "high"),
            Action("add_tag", "recon"),
            Action("set_attack_type", "botnet"),
        ),
    )
    result = RuleEngine([rule]).run(alert())
    assert (result.severity, result.attack_type, result.tags) == (
        "high",
        "botnet",
        ["recon"],
    )


def test_an_action_may_not_invent_a_severity_or_a_class() -> None:
    """PLAN D27 / I14 — `unknown` is a failure state, not an assignable value."""
    with pytest.raises(ValueError, match="unknown"):
        Action("set_severity", "unknown")
    with pytest.raises(ValueError, match="not one of"):
        Action("set_attack_type", "ransomware")


def test_apply_still_returns_severity_and_traces() -> None:
    """Phase 3's signature keeps working; `run` and `apply` share one path."""
    rule = Rule(
        id="1",
        name="raise",
        conditions=(Condition("attack_type", "eq", "port_scan"),),
        action="set_severity",
        severity="critical",
    )
    engine = RuleEngine([rule])
    severity, traces = engine.apply(alert())
    assert severity == "critical"
    assert traces[0].fired is True


# ---------------------------------------------------------------------------
# AND / OR
# ---------------------------------------------------------------------------


def test_or_logic_fires_on_one_matching_condition() -> None:
    rule = Rule(
        id="1",
        name="either",
        conditions=(
            Condition("attack_type", "eq", "ddos"),
            Condition("dest_port", "eq", 443),
        ),
        actions=(Action("set_severity", "high"),),
        logic="OR",
    )
    assert RuleEngine([rule]).run(alert()).severity == "high"


def test_and_logic_needs_every_condition() -> None:
    rule = Rule(
        id="1",
        name="both",
        conditions=(
            Condition("attack_type", "eq", "ddos"),
            Condition("dest_port", "eq", 443),
        ),
        actions=(Action("set_severity", "high"),),
        logic="AND",
    )
    assert RuleEngine([rule]).run(alert()).severity == "medium"


# ---------------------------------------------------------------------------
# ReDoS — PLAN §9
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        "(a+)+$",
        "(a|a)*$",
        "(?:a|aa)+$",
        "(x+x+)+y",
        "((ab)*)*c",
    ],
)
def test_the_complexity_bound_rejects_a_nested_quantifier(pattern: str) -> None:
    """The classic exponential shapes are refused AT RULE-CREATION TIME.

    Rejecting here rather than at match time is the point: the operator finds
    out while writing the rule, not when the feed stalls in front of an
    audience.
    """
    with pytest.raises(PatternTooComplex, match="nests one repetition"):
        compile_pattern(pattern, max_length=200, max_quantifiers=8)


def test_ordinary_patterns_still_compile() -> None:
    """The bound is conservative, not useless."""
    for pattern in (
        "SYN-heavy",
        r"TCP/\d+",
        "flood|scan",
        r"^Flow to (TCP|UDP)/443",
        r"[A-Z]{2,4}-\d+",
    ):
        assert compile_pattern(pattern, max_length=200, max_quantifiers=8) is not None


def test_the_length_and_quantifier_caps_fire() -> None:
    with pytest.raises(PatternTooComplex, match="the limit is"):
        compile_pattern("a" * 300, max_length=200, max_quantifiers=8)
    with pytest.raises(PatternTooComplex, match="repetition operators"):
        compile_pattern("a*b*c*d*e*", max_length=200, max_quantifiers=4)


def test_an_invalid_pattern_is_rejected_with_the_engine_s_own_message() -> None:
    with pytest.raises(PatternTooComplex, match="not a valid pattern"):
        compile_pattern("(unclosed", max_length=200, max_quantifiers=8)


def test_the_match_timeout_fires_on_a_pattern_that_beats_the_static_scan() -> None:
    """The second layer, tested WITHOUT the first.

    `safe_search` has to hold even for a pattern the static scan never saw —
    the scan is conservative and could be loosened, and a bound that only works
    when another bound already worked is not a bound. `(?:a|aa)+$` is compiled
    here directly, bypassing `compile_pattern`, and it backtracks exponentially
    against input that almost matches.
    """
    import regex

    compiled = regex.compile("(?:a|aa)+$", regex.IGNORECASE)
    started = time.perf_counter()
    outcome = safe_search(
        compiled,
        "a" * 40 + "b",
        timeout_seconds=0.05,
        max_subject_length=1024,
    )
    elapsed = time.perf_counter() - started

    assert outcome.matched is False
    assert outcome.timed_out is True
    assert "did not finish" in (outcome.note or "")
    assert elapsed < 1.0, "the deadline is what keeps a match from running forever"


def test_a_timed_out_condition_does_not_kill_the_rules_stage() -> None:
    """A rule that could not be evaluated does not get to change a verdict.

    The timeout is provoked with a hard deadline against a large subject rather
    than a pathological pattern, because the static scan already refuses those
    at creation. What is being asserted is the CONSEQUENCE of a timeout: false,
    recorded, and the stage still returns.
    """
    tight = RegexBounds(
        max_length=200,
        max_quantifiers=8,
        match_timeout_seconds=1e-6,
        max_subject_length=200_000,
    )
    rule = Rule(
        id="1",
        name="slow",
        conditions=(Condition("signature", "contains", r"needle\d+", tight),),
        actions=(Action("set_severity", "critical"),),
    )
    result = RuleEngine([rule]).run(alert(signature="x" * 100_000))

    assert result.severity == "medium", "a rule that cannot be evaluated does not win"
    assert result.traces[0].fired is False
    assert "did not finish" in (result.traces[0].conditions[0].note or "")


def test_the_subject_is_truncated_and_the_truncation_is_recorded() -> None:
    compiled = compile_pattern("needle", max_length=200, max_quantifiers=8)
    outcome = safe_search(
        compiled,
        "x" * 50 + "needle",
        timeout_seconds=0.05,
        max_subject_length=10,
    )
    assert outcome.matched is False
    assert "first 10 characters" in (outcome.note or "")


# ---------------------------------------------------------------------------
# the DB -> engine mapping
# ---------------------------------------------------------------------------


def test_the_ui_operators_map_onto_the_engine_s() -> None:
    assert OPERATOR_MAP == {
        "equals": "eq",
        "not_equals": "ne",
        "greater_than": "gt",
        "contains": "contains",
    }


def test_a_string_port_from_the_form_compares_against_an_integer_port() -> None:
    """WorkspacePanel.jsx:739 sends every value as a string, even dest_port.

    Without coercion `dest_port equals "443"` compares a string against the
    integer 443 and is false forever — a rule that looks correct on screen and
    never fires.
    """
    row = RuleRow(
        id=7,
        name="https",
        conditions={
            "logic": "AND",
            "conditions": [
                {"field": "dest_port", "operator": "equals", "value": "443"}
            ],
        },
        actions=[{"type": "set_severity", "value": "high"}],
        is_enabled=True,
    )
    result = RuleEngine([to_engine_rule(row)]).run(alert())
    assert result.severity == "high"


def test_validation_rejects_an_unknown_field_and_operator() -> None:
    with pytest.raises(RuleValidationError, match="is not a field"):
        validate_conditions(
            {
                "logic": "AND",
                "conditions": [
                    {"field": "password", "operator": "equals", "value": "x"}
                ],
            }
        )
    with pytest.raises(RuleValidationError, match="not a supported operator"):
        validate_conditions(
            {
                "logic": "AND",
                "conditions": [
                    {"field": "severity", "operator": "regex", "value": "x"}
                ],
            }
        )


def test_validation_rejects_an_empty_condition_list() -> None:
    """A rule with no conditions would match everything by accident."""
    with pytest.raises(RuleValidationError, match="at least one condition"):
        validate_conditions({"logic": "AND", "conditions": []})


def test_validation_rejects_an_unassignable_action_value() -> None:
    with pytest.raises(RuleValidationError, match="set_severity must be one of"):
        validate_actions([{"type": "set_severity", "value": "unknown"}])
    with pytest.raises(RuleValidationError, match="set_attack_type must be one of"):
        validate_actions([{"type": "set_attack_type", "value": "ransomware"}])


def test_the_drawer_payload_carries_every_rule_evaluated() -> None:
    """CONTRACT §2.6 #16 — despite the name, `matched_rules` is ALL of them.

    The UI renders non-firing rules with a "no match" chip and the full
    per-condition breakdown; filtering to fired rules deletes the drawer's best
    beat.
    """
    rules = [
        Rule(
            id="1",
            name="fires",
            conditions=(Condition("attack_type", "eq", "port_scan"),),
            actions=(Action("set_severity", "high"),),
        ),
        Rule(
            id="2",
            name="does not fire",
            conditions=(Condition("attack_type", "eq", "ddos"),),
            actions=(Action("set_severity", "critical"),),
        ),
    ]
    payload = trace_to_payload(RuleEngine(rules).run(alert()).traces)

    assert [entry["fired"] for entry in payload] == [True, False]
    assert [entry["rule_id"] for entry in payload] == [1, 2], "integer React keys"
    for entry in payload:
        for condition in entry["conditions"]:
            assert set(condition) >= {
                "field",
                "operator",
                "expected",
                "actual",
                "result",
            }
