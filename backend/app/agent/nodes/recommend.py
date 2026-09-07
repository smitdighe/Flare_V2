"""recommend — the analyst-facing next action. PLAN §3.1 / T12.

The frozen drawer renders `remediation` under RECOMMENDED ACTION and falls back
to its own placeholder when the field is null. So this node's only job is to
make sure that when the field IS set, it is a real next action rather than a
restatement of the explanation.

**NO SYNTHESIS FROM NOTHING.** If the reason node produced neither an
explanation nor a remediation this node is not reached at all —
`route_after_reason` sends the run straight to `rules` and finalize backfills a
`skipped` entry with the reason. Emitting a plausible-sounding recommendation
for an alert nothing reasoned about is T12: quota spent or not, the payload
would be shaped exactly like a real one.

The severity-derived urgency line is a DERIVED fact, not an invented one: it
restates the severity the pipeline already assigned, in the imperative the
drawer's action panel expects.
"""

from __future__ import annotations

from typing import Any

from app.agent.state import NodeName, PipelineState, TraceStatus
from app.agent.trace import TraceBuilder, traced

URGENCY: dict[str, str] = {
    "critical": "Act now — contain before further triage.",
    "high": "Act this shift.",
    "medium": "Queue for triage.",
    "low": "Record and monitor.",
}


@traced(NodeName.RECOMMEND)
async def recommend_node(state: PipelineState, trace: TraceBuilder) -> dict[str, Any]:
    if not state.remediation:
        # Two different situations reach here and the note must not conflate
        # them: the reasoning tier never ran for this alert, or it ran and
        # answered half the question. Either way nothing is synthesized to fill
        # the field — a recommendation derived from nothing is shaped exactly
        # like a real one (T12).
        if state.ran(NodeName.REASON.value):
            note = (
                "the reasoning tier returned an explanation but no remediation; "
                "nothing is synthesized to fill the field"
            )
        else:
            note = (
                f"the reasoning tier did not run for this alert "
                f"({state.reason_skip_reason or 'not selected on this path'}), so "
                "there is no model remediation to shape"
            )
        trace.record(
            TraceStatus.SKIPPED, provider="pipeline", model="severity-urgency", note=note
        )
        return {}

    urgency = URGENCY.get(state.severity)
    remediation = state.remediation
    if urgency and not remediation.startswith(urgency):
        remediation = f"{urgency} {remediation}"

    note = f"urgency prefix from severity {state.severity!r}"
    if state.mitre_technique:
        note += f"; grounded on {state.mitre_technique}"
    if state.retrieval_low_confidence:
        note += " (weak retrieval match — treat the technique as a lead, not a finding)"

    trace.record(
        TraceStatus.OK, provider="pipeline", model="severity-urgency", note=note
    )
    return {"remediation": remediation}
