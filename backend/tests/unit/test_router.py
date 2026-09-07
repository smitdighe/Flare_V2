"""Every routing function, every branch, in isolation. PLAN Part A.

The routers are pure `PipelineState -> str`, so each branch is exercised by
constructing a state and calling the function — no graph, no provider, no model
load. That is the property the design exists to have: a routing decision is
testable without running the thing it routes.
"""

from __future__ import annotations

import pytest

from app.agent.router import (
    escalation_reason,
    route_after_classify,
    route_after_enrich,
    route_after_reason,
)
from app.agent.state import PipelineState


def make_state(**overrides: object) -> PipelineState:
    base: dict[str, object] = {
        "alert_id": "ALT-000001",
        "source": "cicids_replay",
        "signature": "Flow to TCP/80 — nominal exchange (10 pkts, 500 bytes, 12 ms)",
        "src_ip": "118.25.6.39",
        "dest_ip": "192.168.10.50",
        "dest_port": 80,
        "protocol": "TCP",
        "severity": "high",
        "attack_type": "dos",
        "confidence": 1.0,
        "severity_floor": "high",
        "confidence_threshold": 0.99,
    }
    base.update(overrides)
    return PipelineState(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# route_after_classify
# ---------------------------------------------------------------------------


def test_route_after_classify_enriches_a_public_source() -> None:
    assert route_after_classify(make_state(src_ip="8.8.8.8")) == "enrich"


@pytest.mark.parametrize(
    "ip",
    [
        "192.168.10.50",
        "10.0.0.7",
        "172.16.4.1",
        "127.0.0.1",
        "169.254.1.1",
        # TEST-NET-3. Python's ipaddress reports the documentation ranges as
        # private, which is the behaviour we want and is easy to be surprised
        # by, so it is pinned here rather than discovered in a failing test.
        "203.0.113.9",
    ],
)
def test_route_after_classify_skips_enrich_for_unroutable_sources(ip: str) -> None:
    """PLAN §10.2 — no metered unit spent to learn nothing about RFC1918 space."""
    assert route_after_classify(make_state(src_ip=ip)) == "retrieve"


def test_route_after_classify_skips_enrich_in_offline_mode() -> None:
    state = make_state(src_ip="8.8.8.8", offline_mode=True)
    assert route_after_classify(state) == "retrieve"


# --- REGRESSION: the reasoning gate applies on the enrich-skipping edge too ---
#
# This was a real bug, found by a live run rather than by a test. The gate lived
# only on `route_after_enrich`, so the 90.5% of CICIDS replay rows with an
# RFC1918 source — which skip enrichment — reached the reason node with no
# severity floor and no rate budget applied at all. At the configured replay
# rate that is 30 Gemini calls a minute against a ~15 RPM free tier: a 429
# inside the first minute of the demo (T4).


@pytest.mark.parametrize("severity", ["low", "medium"])
def test_a_sub_floor_alert_that_skips_enrich_also_skips_reasoning(
    severity: str,
) -> None:
    state = make_state(src_ip="192.168.10.50", severity=severity, severity_floor="high")
    assert route_after_classify(state) == "recommend"


def test_a_high_alert_that_skips_enrich_still_reasons() -> None:
    state = make_state(
        src_ip="192.168.10.50", severity="high", reason_budget_available=True
    )
    assert route_after_classify(state) == "retrieve"


def test_the_budget_applies_on_the_enrich_skipping_edge() -> None:
    state = make_state(
        src_ip="192.168.10.50", severity="critical", reason_budget_available=False
    )
    assert route_after_classify(state) == "recommend"


def test_escalation_bypasses_the_gate_on_the_enrich_skipping_edge() -> None:
    state = make_state(
        src_ip="192.168.10.50",
        severity="low",
        classification_escalated=True,
        reason_budget_available=False,
    )
    assert route_after_classify(state) == "retrieve"


@pytest.mark.parametrize(
    ("severity", "escalated", "budget"),
    [
        ("low", False, True),
        ("medium", False, True),
        ("high", False, True),
        ("critical", False, True),
        ("unknown", False, True),
        ("high", False, False),
        ("low", True, False),
    ],
)
def test_both_reasoning_gates_agree(severity: str, escalated: bool, budget: bool) -> None:
    """The two edges must never disagree about whether an alert reasons.

    They are different edges reached on different paths, and if their answers
    could diverge then whether an alert gets an LLM narrative would depend on
    whether its source IP happened to be routable — which has nothing to do with
    whether an analyst needs the narrative.
    """
    common = {
        "severity": severity,
        "classification_escalated": escalated,
        "reason_budget_available": budget,
    }
    unroutable = make_state(src_ip="192.168.10.50", **common)
    routable = make_state(src_ip="8.8.8.8", **common)

    reasons_via_classify = route_after_classify(unroutable) == "retrieve"
    reasons_via_enrich = route_after_enrich(routable) == "retrieve"
    assert reasons_via_classify == reasons_via_enrich


# ---------------------------------------------------------------------------
# route_after_enrich — THE REASONING GATE
# ---------------------------------------------------------------------------


def test_reason_runs_on_a_fully_confident_alert_above_the_floor() -> None:
    """THE TEST THAT PROVES REASONING IS NOT GATED ON ESCALATION.

    Confidence is exactly 1.0, so the classification-escalation gate would never
    fire for this alert. Reasoning must still run: a perfectly-classified
    high-severity alert is precisely the one an analyst needs an explanation
    for. If this ever routes to `recommend`, the two gates have been wired
    together and the LLM tier will be idle on 99.7% of replay traffic.
    """
    state = make_state(
        severity="high",
        confidence=1.0,
        classification_escalated=False,
        reason_budget_available=True,
    )
    assert route_after_enrich(state) == "retrieve"


def test_reason_runs_on_critical() -> None:
    assert route_after_enrich(make_state(severity="critical")) == "retrieve"


@pytest.mark.parametrize("severity", ["low", "medium"])
def test_reason_skipped_below_the_floor(severity: str) -> None:
    state = make_state(severity=severity, severity_floor="high")
    assert route_after_enrich(state) == "recommend"


def test_reason_skipped_when_the_rate_budget_is_exhausted() -> None:
    """PLAN §10.4 — the floor is policy, the budget is the cap."""
    state = make_state(severity="critical", reason_budget_available=False)
    assert route_after_enrich(state) == "recommend"


def test_reason_skipped_on_unknown_severity() -> None:
    """PLAN D27 — `unknown` is outside the order and satisfies no threshold."""
    assert route_after_enrich(make_state(severity="unknown")) == "recommend"


def test_escalation_bypasses_the_floor_and_the_budget() -> None:
    """An alert the classifier could not resolve always gets the second opinion."""
    state = make_state(
        severity="low",
        classification_escalated=True,
        reason_budget_available=False,
    )
    assert route_after_enrich(state) == "retrieve"


def test_reclassify_request_bypasses_the_floor() -> None:
    state = make_state(
        severity="low", reclassify_requested=True, reason_budget_available=False
    )
    assert route_after_enrich(state) == "retrieve"


def test_router_sees_the_post_upgrade_severity() -> None:
    """PLAN Part D — intel escalation happens in enrich, BEFORE this router.

    A `low` alert that intel raised to `high` must route as `high`. If the
    router read a pre-upgrade value the escalation would be cosmetic.
    """
    before = make_state(severity="low", severity_floor="high")
    assert route_after_enrich(before) == "recommend"

    after = before.model_copy(
        update={"severity": "high", "intel_escalated": True, "reason_budget_available": True}
    )
    assert route_after_enrich(after) == "retrieve"


# ---------------------------------------------------------------------------
# route_after_reason
# ---------------------------------------------------------------------------


def test_recommend_runs_when_there_is_something_to_shape() -> None:
    assert route_after_reason(make_state(explanation="A SYN flood.")) == "recommend"
    assert route_after_reason(make_state(remediation="Block the source.")) == "recommend"


def test_recommend_skipped_when_reason_produced_nothing() -> None:
    """PLAN T12 — a recommendation derived from nothing is shaped like a real one."""
    state = make_state(explanation=None, remediation=None)
    assert route_after_reason(state) == "rules"


# ---------------------------------------------------------------------------
# escalation_reason — the OTHER gate, and it is genuinely independent
# ---------------------------------------------------------------------------


def test_no_escalation_on_a_confident_prediction() -> None:
    assert escalation_reason(make_state(confidence=1.0)) is None


def test_escalates_below_the_confidence_threshold() -> None:
    reason = escalation_reason(make_state(confidence=0.42))
    assert reason and "0.4200" in reason


def test_escalates_at_exactly_the_threshold_boundary() -> None:
    """Strictly below escalates; exactly at the threshold does not."""
    assert escalation_reason(make_state(confidence=0.99, confidence_threshold=0.99)) is None
    assert escalation_reason(make_state(confidence=0.98999, confidence_threshold=0.99))


@pytest.mark.parametrize("source", ["suricata_sample", "live_demo"])
def test_escalates_when_the_source_has_no_flow_features(source: str) -> None:
    """PLAN D25 — an EVE alert has no 77-column vector; the LLM is the only tier."""
    reason = escalation_reason(make_state(source=source, confidence=None))
    assert reason and "no flow features" in reason


def test_escalates_when_the_fast_tier_returned_unknown() -> None:
    reason = escalation_reason(make_state(attack_type="unknown", confidence=None))
    assert reason and "unknown" in reason


def test_escalates_on_intel_disagreement() -> None:
    reason = escalation_reason(
        make_state(attack_type="benign", severity="low", confidence=1.0, intel_malicious=True)
    )
    assert reason and "disagree" in reason


def test_no_intel_disagreement_when_the_model_already_says_attack() -> None:
    state = make_state(attack_type="dos", confidence=1.0, intel_malicious=True)
    assert escalation_reason(state) is None


def test_the_two_gates_are_independent() -> None:
    """D18, stated as an assertion rather than a comment.

    A fully-confident alert above the floor reasons and does not escalate.
    A low-confidence alert below the floor escalates and — because escalation
    bypasses the floor — also reasons. Neither gate implies the other.
    """
    confident_high = make_state(confidence=1.0, severity="high")
    assert escalation_reason(confident_high) is None
    assert route_after_enrich(confident_high) == "retrieve"

    unsure_low = make_state(confidence=0.10, severity="low", classification_escalated=True)
    assert escalation_reason(unsure_low) is not None
    assert route_after_enrich(unsure_low) == "retrieve"
