"""Conditional edges. PLAN Part A / Part B / D18 / D19 / D25.

**Every function here is pure `PipelineState -> str`.** No I/O, no settings
read, no clock, no provider. Every value they branch on was snapshotted into
state before the graph started, which is what makes each one unit-testable by
constructing a state and calling it — and what makes "the router sees the
POST-upgrade severity" a property a test can assert rather than a claim.

**STAGE SKIPPING LIVES HERE AND NOWHERE ELSE.** A node never returns early to
avoid work. An early return produces a payload byte-identical to a genuine
skip — same nulls, same absent fields — so a reader cannot tell "the router
decided not to" from "the node gave up halfway". Routing it in the edge makes
the decision an observable, named branch with a recorded reason.

---

**THE TWO GATES ARE INDEPENDENT, AND THAT IS THE POINT (D18).**

`escalation_reason` gates the LLM *classifier*: it fires on low calibrated
confidence, on an alert with no flow features (D25), or on intel disagreeing
with the model. Phase 2a measured that 99.7% of eval rows sit at confidence
exactly 1.0, so on replay data this fires roughly **three times per thousand
alerts**. That is a correct and honest outcome — the classifier really is that
confident on this distribution — and it is NOT a broken gate.

`route_after_enrich` gates the *reason* node, and it does NOT read confidence at
all. Reasoning is a different job from classification: narrative, MITRE mapping,
remediation. A perfectly-classified critical alert still needs an explanation
for the analyst. Wiring reasoning behind the escalation gate would mean the LLM
runs three times in a thousand alerts and the reasoning story is hollow on
stage; wiring escalation behind the severity floor would mean a low-confidence
`benign` never gets a second opinion. Neither gate is behind the other.
"""

from __future__ import annotations

from app.agent.state import PipelineState
from app.ingestion.labels import SEVERITY_ORDER, severity_rank
from app.intel.base import external_endpoint

UNKNOWN = "unknown"

# D25 — the sources that carry no CICIDS flow columns. Kept here rather than
# imported from the classifier so the router has no dependency that could drag
# a model load into a unit test.
NO_FLOW_FEATURE_SOURCES: frozenset[str] = frozenset({"suricata_sample", "live_demo"})


def escalation_reason(state: PipelineState) -> str | None:
    """Should the LLM classifier get this alert? PLAN D18/D19/D25.

    Returns the human-readable reason, or None. The reason is what lands in the
    trace, so a reader can see WHY the second tier ran rather than only that it
    did.

    Note the ordering dependency this function does NOT have: it is called twice
    in the run — once inside `classify` (confidence, missing features) and once
    inside `enrich` (intel disagreement), because intel disagreement is not
    knowable until enrichment has happened. Both calls read the same function,
    so the escalation policy has one definition.
    """
    if state.source in NO_FLOW_FEATURE_SOURCES:
        return (
            f"source {state.source!r} carries no flow features, so the fast tier "
            "was skipped and the LLM is the only tier that can classify it (D25)"
        )

    if state.attack_type == UNKNOWN:
        return "the fast tier returned unknown; a failed classification is not a verdict"

    if state.confidence is not None and state.confidence < state.confidence_threshold:
        return (
            f"calibrated confidence {state.confidence:.4f} is below the "
            f"{state.confidence_threshold} escalation threshold"
        )

    if state.intel_malicious and state.attack_type == "benign":
        return (
            "threat intel reports the externally-routable endpoint of this flow "
            "as malicious while the fast tier called it benign; the two disagree"
        )

    return None


def route_after_classify(state: PipelineState) -> str:
    """`enrich` | `retrieve` | `recommend`.

    Two independent questions, in this order:

    **Is there anything worth enriching?** `external_endpoint` picks whichever
    end of the flow is publicly routable — source first, destination second —
    and returns None when both ends are internal. Skipping the lookup then is a
    real saving: querying 192.168.10.50 spends a metered unit against a
    ~1000/day free tier (§10.1) to learn that no intel source has ever seen it.
    Offline mode skips it for a different reason — no network call is made at
    all, and an enrich node that "ran" without calling anything would report
    `ioc_checked` for a check that never happened.

    **Is this alert reasoning?** THE REASONING GATE APPLIES ON THIS EDGE TOO,
    and it has to. It used to live only on the enrich edge, and a live run
    showed the consequence: the 90.5% of alerts that skip enrichment reached the
    reason node with no floor and no rate budget applied at all, which at the
    configured replay rate is 30 Gemini calls a minute against a ~15 RPM free
    tier (T4). `classify` writes the admission decision for every alert
    (app/agent/admission.py) and this router reads it.
    """
    enrichable = not state.offline_mode and external_endpoint(
        state.src_ip, state.dest_ip
    ) is not None
    if enrichable:
        # `route_after_enrich` makes the reasoning call on that path, after
        # intel has had its chance to raise severity above the floor.
        return "enrich"
    if _reasons(state):
        return "retrieve"
    return "recommend"


def _reasons(state: PipelineState) -> bool:
    """Shared by both reasoning gates so they cannot drift apart."""
    if state.classification_escalated or state.reclassify_requested:
        return True
    if state.severity not in SEVERITY_ORDER:
        return False
    if severity_rank(state.severity) < severity_rank(state.severity_floor):
        return False
    return state.reason_budget_available


def route_after_enrich(state: PipelineState) -> str:
    """`retrieve` | `recommend` — THE REASONING GATE.

    Reads `state.severity`, which by this point is the POST-UPGRADE severity:
    the enrich node applies intel escalation before this router runs, so an
    alert that intel forced to `high` is routed as `high`. That ordering is the
    whole reason intel escalation is worth having, and it is asserted by a test.

    Three ways to be sent past the reason node, each with its own recorded
    reason on the state:

      below the floor   the alert does not warrant an LLM narrative
      no budget         PLAN §10.4 — Gemini's free tier is ~15 RPM and the floor
                        alone admits ~20/min at the configured replay rate, so
                        the rate budget is what actually keeps the demo under
                        cap. The skip is TRACED with the reason, never silent.
      unknown severity  D27 — `unknown` is outside the order and satisfies no
                        threshold. Reasoning about a classification that failed
                        would be narrating a verdict nobody produced.

    Classification escalation BYPASSES both the floor and the budget. It fires on
    ~0.3% of alerts, so it costs nothing to always honour, and an alert the
    classifier could not resolve is exactly the one an analyst needs a second
    opinion on.
    """
    return "retrieve" if _reasons(state) else "recommend"


def route_after_reason(state: PipelineState) -> str:
    """`recommend` | `rules` — is there anything to turn into a recommendation?

    The recommend node's job is to shape the model's remediation into the
    analyst-facing action. With no explanation and no remediation there is
    nothing to shape, and running it anyway would emit a recommendation derived
    from nothing — T12, a stage whose output is indistinguishable from a real
    one.
    """
    if state.explanation or state.remediation:
        return "recommend"
    return "rules"
