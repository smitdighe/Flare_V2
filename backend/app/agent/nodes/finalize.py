"""finalize — the I1 backstop. PLAN I1 / CONTRACT §4.0, §4.1.

Two jobs, both about the trace being trustworthy rather than merely present:

**BACKFILL.** Every node the routers skipped gets a `skipped` entry with a
human-readable reason. A gap in the array would force the reader to guess
between "the router skipped it", "it failed" and "it was never built" — the
exact ambiguity I1 exists to remove. Reasons recorded by the routers are used
where available so the entry says WHY this alert took this path, not just that
it did.

**STRIP CONSISTENCY.** The frozen `AlertTable` infers stage completion from
`severity` / `ioc_checked` / `explanation`, not from the trace (CONTRACT §4.1).
So a `failed` or `skipped` node that left its field populated would light the
table's strip green for a stage the drawer reports as broken. This node checks
the pairing and repairs it, and records what it repaired — a silent repair would
hide a real bug in a node.
"""

from __future__ import annotations

from typing import Any

from app.agent.state import NodeName, PipelineState, TraceStatus
from app.agent.trace import (
    STRIP_FIELD,
    TraceBuilder,
    backfill_skipped,
    strip_consistency_violations,
    traced,
)


def skip_reasons(state: PipelineState) -> dict[str, str]:
    """The specific reason each unreached node was not reached."""
    reasons: dict[str, str] = {}

    if not state.ran(NodeName.ENRICH.value):
        if state.offline_mode:
            reasons[NodeName.ENRICH.value] = (
                "offline mode is on, so no intel provider was called; reporting "
                "ioc_checked for a check that never happened would be a "
                "fabricated result"
            )
        else:
            reasons[NodeName.ENRICH.value] = (
                f"neither endpoint is publicly routable ({state.src_ip} -> "
                f"{state.dest_ip}), so no threat-intel source has data on this "
                "flow; the lookup was skipped rather than spending a metered "
                "quota unit to learn nothing (PLAN §10.2)"
            )

    reason_skip = state.reason_skip_reason
    for node in (NodeName.RETRIEVE, NodeName.REASON):
        if state.ran(node.value):
            continue
        reasons[node.value] = reason_skip or (
            "the alert did not reach the reasoning branch on this path"
        )
    if NodeName.RETRIEVE.value in reasons and reason_skip:
        reasons[NodeName.RETRIEVE.value] = (
            f"{reason_skip}; retrieval grounds the reasoning prompt, so with no "
            "reasoning to ground there is nothing to retrieve for"
        )

    if not state.ran(NodeName.RECOMMEND.value):
        reasons[NodeName.RECOMMEND.value] = (
            "the reasoning tier produced no explanation and no remediation, so "
            "there was nothing to turn into a recommended action; synthesizing "
            "one would be a payload shaped exactly like a real recommendation "
            "(PLAN T12)"
        )

    return reasons


@traced(NodeName.FINALIZE)
async def finalize_node(state: PipelineState, trace: TraceBuilder) -> dict[str, Any]:
    backfilled = backfill_skipped(state, skip_reasons(state))

    combined = list(state.trace) + backfilled
    update: dict[str, Any] = {}

    severity = state.severity
    ioc_checked = state.ioc_checked
    explanation = state.explanation

    violations = strip_consistency_violations(
        combined,
        severity=severity,
        ioc_checked=ioc_checked,
        explanation=explanation,
    )
    for violation in violations:
        # Repair, then say what was repaired. CONTRACT §4.1 is a hard
        # obligation; a violation reaching the payload makes the table and the
        # drawer disagree about the same stage.
        if "'explanation'" in violation:
            update["explanation"] = None
            explanation = None
        elif "'ioc_checked'" in violation:
            update["ioc_checked"] = False
            ioc_checked = False

    parts = [
        f"{len(state.trace)} node(s) ran, {len(backfilled)} backfilled as skipped"
    ]
    if state.errors:
        parts.append(f"{len(state.errors)} node error(s)")
    if state.budget_exhausted:
        parts.append("the whole-graph wall clock expired; state is PARTIAL")
    if state.offline_mode:
        parts.append(
            "OFFLINE MODE: no provider was called anywhere in this run, so every "
            "alert it produces is marked degraded (PLAN E9)"
        )
    elif state.degraded:
        parts.append("degraded: at least one tier did not answer")
    if violations:
        parts.append(
            f"repaired {len(violations)} stage-strip inconsistency(ies) "
            f"(CONTRACT §4.1): {'; '.join(violations)}"
        )

    trace.record(
        TraceStatus.OK,
        provider="pipeline",
        model="finalize",
        note=". ".join(parts),
    )
    update["trace"] = backfilled
    return update


__all__ = ["STRIP_FIELD", "finalize_node", "skip_reasons"]
