"""rules — runs LAST, wins over the model AND over intel escalation.

PLAN Part D. The precedence is `model < intel escalation < rules`, it is
enforced by ORDERING (this node is the last one before finalize, so it reads the
severity everything else already produced), and it has its own test.

**PHASE 4 — THE ACTIONS ARE LIVE.** `set_severity`, `add_tag` and
`set_attack_type` all change the alert that gets persisted and streamed:
severity lands on the payload and the header counters, the tag lands in
`alerts.tags`, the attack type lands on the vector column and the filter. In
the prior codebase this whole module was unreachable, so a rule could be
created, listed and deleted while changing nothing about any alert — an
endpoint that writes a row and executes nothing (T14).

The node reads the IN-MEMORY engine, never the database. The engine is rebuilt
from storage at startup and after every rule write
(`app/rules/store.refresh_rule_engine`), which keeps a per-alert DB round trip
off the hot path and keeps this node synchronous apart from its own await.

Every override is recorded on the trace entry, in `rule_outcomes` and in the
per-condition `rule_trace` the drawer renders, so the severity a user sees is
always attributable.
"""

from __future__ import annotations

from typing import Any

from app.agent.state import NodeName, PipelineState, RuleOutcome, TraceStatus
from app.agent.trace import TraceBuilder, traced
from app.rules.engine import get_rule_engine
from app.rules.store import trace_to_payload


@traced(NodeName.RULES)
async def rules_node(state: PipelineState, trace: TraceBuilder) -> dict[str, Any]:
    engine = get_rule_engine()

    alert = {
        "id": state.alert_id,
        "source": state.source,
        "severity": state.severity,
        "attack_type": state.attack_type,
        "src_ip": state.src_ip,
        "dest_ip": state.dest_ip,
        "dest_port": state.dest_port,
        "protocol": state.protocol,
        "signature": state.signature,
        "ioc_reputation": state.ioc_reputation,
        "confidence": state.confidence,
        "mitre_technique": state.mitre_technique,
        "tags": list(state.tags),
    }

    before_severity = state.severity
    before_attack_type = state.attack_type
    result = engine.run(alert)
    traces = result.traces

    outcomes = [
        RuleOutcome(
            rule_id=t.rule_id,
            rule_name=t.rule_name,
            fired=t.fired,
            action=t.action,
            from_severity=t.from_severity,
            to_severity=t.to_severity,
        )
        for t in traces
    ]

    update: dict[str, Any] = {
        "rule_outcomes": outcomes,
        "rule_trace": trace_to_payload(traces),
        "tags": result.tags,
    }
    fired = result.fired

    changes: list[str] = []
    if result.severity != before_severity:
        update["severity"] = result.severity
        update["rules_overrode"] = True
        overriding = next(
            (t.rule_name for t in fired if t.to_severity == result.severity), "a rule"
        )
        was = "the model"
        if state.intel_escalated:
            was = "intel escalation, which had itself overridden the model"
        changes.append(
            f"{overriding} set severity {before_severity!r} -> "
            f"{result.severity!r}, overriding {was}. Rules run last and win: a "
            "rule is the operator's explicit instruction about their own "
            "network, which neither a model trained on a 2017 capture nor "
            "internet-wide reputation can know."
        )
    if result.attack_type != before_attack_type:
        update["attack_type"] = result.attack_type
        update["rules_overrode"] = True
        changes.append(
            f"set attack_type {before_attack_type!r} -> {result.attack_type!r}"
        )
    added = [tag for tag in result.tags if tag not in state.tags]
    if added:
        changes.append(f"tagged {added}")

    if changes:
        note = "; ".join(changes)
    elif not engine.rules:
        note = (
            "0 rules configured — the engine ran and had nothing to evaluate. No "
            "example rule is shipped because seeded data is forbidden in every "
            "environment (PLAN I9)."
        )
    else:
        note = (
            f"{len(fired)} of {len(traces)} rules fired; nothing this alert "
            "carries was changed"
        )

    trace.record(
        TraceStatus.OK, provider="rules-engine", model=f"{len(traces)} rules", note=note
    )
    return update
