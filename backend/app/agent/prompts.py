"""Prompt construction. PLAN I4 / Part E / E11.

**I4 — THE LABEL NEVER ENTERS A PROMPT.** Nothing here reads
`ground_truth_class`; it is not a parameter of any function in this module, so
it cannot leak by accident, and a future edit that wanted to leak it would have
to change a signature. The prior codebase pasted the label verbatim into the
signature and then put the signature into the prompt, so 450/450 eval prompts
contained the answer in plain text.

**E11 — the prompt gets the real discriminative features.** A bare 5-tuple
starves the model and then reports a low score as a finding. The flow statistics
go in; the label does not.

**Part E — every interpolated field is escaped, capped and delimited**, with an
explicit untrusted-data instruction. See `app.security.sanitize` for why all
four layers are needed and why enum clamping does not replace the other three.
"""

from __future__ import annotations

from app.agent.state import PipelineState, RetrievedTechnique
from app.ingestion.labels import CANONICAL_CLASSES, SEVERITY_ORDER
from app.security.sanitize import UNTRUSTED_PREAMBLE, untrusted_block

# The subset of the 77 columns that actually discriminates, by gain, from
# metrics.json. The full 77 would blow the prompt budget and bury the signal;
# these are the columns the trained model splits on most.
PROMPT_FEATURES: tuple[str, ...] = (
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Bwd Packets/s",
    "Fwd Packet Length Std",
    "Average Packet Size",
    "Init_Win_bytes_backward",
    "PSH Flag Count",
    "SYN Flag Count",
    "ACK Flag Count",
    "act_data_pkt_fwd",
)

CLASSIFY_SYSTEM = (
    "You are a network intrusion classifier. You are given statistics for a "
    "single network flow and you return a JSON object, nothing else.\n\n"
    f"{UNTRUSTED_PREAMBLE}\n\n"
    "Reply with exactly this shape:\n"
    '{"attack_type": <one of '
    + "|".join(CANONICAL_CLASSES)
    + '>, "severity": <one of '
    + "|".join(SEVERITY_ORDER)
    + '>, "confidence": <number between 0 and 1>, '
    '"rationale": <one sentence, at most 200 characters>}\n\n'
    "Use only the values you are given. Do not invent fields. If the evidence "
    "does not support an attack, say benign."
)

REASON_SYSTEM = (
    "You are a SOC tier-2 analyst writing the evidence note for one alert. You "
    "return a JSON object, nothing else.\n\n"
    f"{UNTRUSTED_PREAMBLE}\n\n"
    "Reply with exactly this shape:\n"
    '{"explanation": <2-4 sentences for an analyst, at most 700 characters>, '
    '"remediation": <the single next action, at most 300 characters>, '
    '"technique_ids": <array of MITRE ATT&CK technique IDs, chosen ONLY from '
    "the candidate list you are given; return an empty array if none of the "
    'candidates fit>, "confidence": <number between 0 and 1>}\n\n'
    "You may NOT name a technique that is not in the candidate list. Techniques "
    "outside that list are dropped before the analyst sees them, so inventing "
    "one only removes information."
)

RECLASSIFY_INSTRUCTION = (
    ' Also return "attack_type" and "severity" using the same enums as the '
    "classifier, because this alert was escalated for a second opinion."
)


def flow_fields(state: PipelineState) -> dict[str, object]:
    """The observable facts about the flow. No label, no ground truth."""
    fields: dict[str, object] = {
        "src_ip": state.src_ip,
        "dest_ip": state.dest_ip,
        "dest_port": state.dest_port,
        "protocol": state.protocol,
        "signature": state.signature,
        "source": state.source,
    }
    for name in PROMPT_FEATURES:
        if name in state.features:
            fields[name] = round(state.features[name], 4)
    return fields


def build_classify_prompt(state: PipelineState) -> str:
    block = untrusted_block(flow_fields(state))
    return f"Classify this network flow.\n\n{block}"


def build_reason_prompt(
    state: PipelineState, candidates: list[RetrievedTechnique]
) -> str:
    """The reasoning prompt, grounded on retrieved candidates.

    The classifier's verdict is included and is labelled as a verdict from a
    named model, not as ground truth. That distinction matters: the LLM is being
    asked to explain a prediction, and telling it the prediction is a prediction
    is what stops it treating it as fact it must defend.
    """
    block = untrusted_block(flow_fields(state))

    candidate_lines = (
        "\n".join(
            f"  - {c.technique_id} ({c.name}) — retrieval score {c.score:.3f}"
            for c in candidates
        )
        or "  (none retrieved)"
    )

    verdict = (
        f"A trained LightGBM classifier (version {state.model_version}) predicted "
        f"attack_type={state.ml_attack_type or state.attack_type!r}, "
        f"severity={state.ml_severity or state.severity!r}"
    )
    if state.ml_confidence is not None:
        verdict += f" at calibrated confidence {state.ml_confidence:.4f}"
    verdict += ". It is a prediction, not ground truth, and it can be wrong."

    intel_line = ""
    if state.ioc_checked:
        score = "no score" if state.ioc_reputation is None else f"{state.ioc_reputation}/100"
        intel_line = (
            f"\nThreat intel on the source address: reputation {score}, "
            f"malicious={state.intel_malicious}."
        )
        if state.intel_escalated:
            intel_line += f" {state.intel_escalation_note}"

    return (
        f"{verdict}{intel_line}\n\n"
        f"Candidate MITRE ATT&CK techniques retrieved for this alert:\n"
        f"{candidate_lines}\n\n"
        f"{block}\n\n"
        "Write the analyst note."
    )
