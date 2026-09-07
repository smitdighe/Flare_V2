"""enrich — threat intel, and the escalation that outranks the model.

PLAN Part D / §10.2 / T11 / T12.

**INTEL OUTRANKS THE MODEL.** A reputation score at or above the configured
threshold forces `high` when the model said less. The justification is not that
intel is smarter: it is that the two are evidence of different kinds. The model
infers from the SHAPE of one flow; AbuseIPDB reports what this address has
actually been observed doing across the internet. An address with a live abuse
record is not made benign by a flow that looks ordinary.

The upgrade is applied HERE, before `route_after_enrich` runs, so the router
sees the POST-UPGRADE severity and an intel-escalated alert is routed as `high`.
That ordering is the whole point of the escalation and it has its own test.

**T11 — nothing is synthesized into a lookup key.** Only an OBSERVED address is
queried, and only the end of the flow that is publicly routable — source first,
destination second, because a botnet beacon runs outbound from an internal host
and a source-only lookup never asks about the C2. `vt_hash` stays null on every
alert, because a flow record carries no file hash and inventing one produced a
guaranteed 404 that the prior codebase rendered to the analyst as a verdict.

**Reasoning admission is RE-decided here, not decided here.** `classify` makes
the call for every alert, because enrichment is skipped on 90.5% of CICIDS
replay rows (private source addresses) and a gate that only runs on the enrich
path is a gate that runs on a tenth of traffic. This node revisits it only when
intel RAISED severity across the floor. See `app/agent/admission.py`.
"""

from __future__ import annotations

from typing import Any

from app.agent.admission import reserve_reasoning, was_turned_away_by_budget
from app.agent.router import escalation_reason
from app.agent.state import NodeName, PipelineState, TraceStatus
from app.agent.trace import TraceBuilder, traced
from app.ingestion.labels import SEVERITY_ORDER, severity_rank
from app.intel.aggregator import get_aggregator
from app.intel.base import external_endpoint


@traced(NodeName.ENRICH)
async def enrich_node(state: PipelineState, trace: TraceBuilder) -> dict[str, Any]:
    # Source first, destination second. A botnet beacon runs outbound from an
    # internal host, so on that traffic the address worth asking about is the
    # DESTINATION — a source-only lookup never asks about the C2 once.
    endpoint = external_endpoint(state.src_ip, state.dest_ip)
    checked_ip, role = endpoint if endpoint else (state.src_ip, "source")
    verdict = await get_aggregator().lookup(checked_ip)

    update: dict[str, Any] = {
        "ioc_checked": verdict.checked,
        "ioc_reputation": verdict.score,
        # The frozen drawer renders this as a short verdict string next to the
        # reputation percentage (AlertDetailDrawer.jsx). It describes the IP
        # lookup — the only VirusTotal query this pipeline makes.
        "vt_ip": _vt_label(verdict),
        "vt_hash": None,
        "intel_malicious": verdict.malicious,
    }
    if verdict.degraded:
        update["degraded"] = True

    severity = state.severity
    if (
        verdict.score is not None
        and verdict.score >= state.intel_escalation_score
        and severity in SEVERITY_ORDER
        and severity_rank(severity) < severity_rank("high")
    ):
        note = (
            f"threat intel scored the {role} {checked_ip} at {verdict.score}/100, at or "
            f"above the {state.intel_escalation_score} escalation threshold, so "
            f"severity was raised from {severity!r} to 'high'. Intel outranks "
            "the model: it reports what this address has been observed doing, "
            "not what one flow looks like."
        )
        update["severity"] = "high"
        update["intel_escalated"] = True
        update["intel_escalation_note"] = note
        severity = "high"

    # Intel disagreeing with the model is an escalation trigger that only
    # becomes knowable here — it needs the lookup to have happened.
    decided = state.model_copy(update=update)
    if not state.classification_escalated and escalation_reason(decided):
        update["reclassify_requested"] = True

    # ---- reasoning admission, RE-decided only if intel raised severity ----
    #
    # `classify` already ran this for every alert. Intel escalation can only
    # ever RAISE severity, so an alert already admitted stays admitted and its
    # token is not spent again. The only case worth revisiting is one the FLOOR
    # turned away that intel has now lifted above it — and not one the BUDGET
    # turned away, because the budget is a cap and intel does not raise the cap.
    if not state.reason_budget_available and not was_turned_away_by_budget(
        state.reason_skip_reason
    ):
        admitted, skip_reason = reserve_reasoning(
            severity,
            state.severity_floor,
            escalated=bool(update.get("reclassify_requested")),
        )
        update["reason_budget_available"] = admitted
        update["reason_skip_reason"] = skip_reason

    trace.record(
        TraceStatus.OK if verdict.checked else TraceStatus.SKIPPED,
        provider="+".join(verdict.sources_ok) or "abuseipdb+virustotal",
        model="ip-reputation",
        note=f"checked the {role} {checked_ip}; " + verdict.note()
        + (f" | {update['intel_escalation_note']}" if update.get("intel_escalated") else ""),
    )
    return update


def _vt_label(verdict: Any) -> str | None:
    for result in verdict.results:
        if result.source != "virustotal":
            continue
        if result.status != "ok":
            return result.status
        if result.score is None:
            return "no data"
        return "malicious" if result.malicious else "clean"
    return None
