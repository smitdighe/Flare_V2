"""PipelineState -> NormalizedAlert. PLAN I4 / I12 / CONTRACT §4.0.

The graph is the only thing that may set a verdict on an alert. Before Phase 3
the replay parser stamped the DATASET's severity onto the alert and labelled it
as ground truth in the trace; that placeholder is gone, and every field below is
now the pipeline's own output.

I4 — `ground_truth_class` and `row_id` are untouched here. They stay on the
NormalizedAlert for the eval harness and are never serialized (see
`alert_to_dict`).
"""

from __future__ import annotations

from typing import Any

from app.agent.state import PipelineState


def apply_to_alert(alert: Any, state: PipelineState) -> Any:
    """Copy the pipeline's verdict onto the alert, in place."""
    alert.severity = state.severity
    alert.attack_type = state.attack_type
    alert.confidence = state.confidence
    alert.mitre_technique = state.mitre_technique
    alert.ioc_checked = state.ioc_checked
    alert.ioc_reputation = state.ioc_reputation
    alert.vt_ip = state.vt_ip
    alert.vt_hash = state.vt_hash
    alert.explanation = state.explanation
    alert.remediation = state.remediation
    alert.classify_latency_ms = state.classify_latency_ms
    alert.enrich_latency_ms = state.enrich_latency_ms
    alert.reasoning_latency_ms = state.reasoning_latency_ms
    alert.degraded = state.degraded
    alert.tags = list(state.tags)
    alert.rule_trace = list(state.rule_trace)
    alert.trace = [entry.as_payload() for entry in state.trace]
    return alert
