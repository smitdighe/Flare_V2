"""classify — the fast tier, and the LLM tier when the fast tier is not enough.

PLAN D19 / D25 / I5 / I13 / I14 / I18.

Two tiers, one trace entry. The entry names the tier that produced the FINAL
verdict, and when the LLM overrode the model the note records what the model had
said and why it was overridden — so the drawer can always attribute the verdict
to an artifact (I16) and an analyst can always see that a second opinion was
taken.

I14: THE TRAINED MODEL GETS NO SPECIAL TRUST. Its output is clamped to the same
enums as an LLM's, it emits a trace entry like any other tier, it is subject to
intel escalation and to rule overrides, and it can be wrong.

D25: an alert with no flow features does not get a zero-filled vector scored as
a real prediction. The fast tier records an explicit `skipped` and the LLM is
the only tier that can classify it.

WHY THE ESCALATION IS NOT AN EDGE. The seven node names in CONTRACT §8.3 are
fixed and I1 allows exactly one trace entry per node, so an eighth graph node
for the second tier would put two entries under `classify`. The escalation
DECISION is still a pure, separately unit-tested function —
`router.escalation_reason` — and every branch of it is tested in isolation;
what lives inside this node is only the call it authorises.
"""

from __future__ import annotations

from typing import Any

from app.agent.admission import reserve_reasoning
from app.agent.router import escalation_reason
from app.agent.state import NodeName, PipelineState, TokenUsage, TraceStatus
from app.agent.trace import TraceBuilder, traced
from app.ingestion.labels import CANONICAL_CLASSES, SEVERITY_ORDER
from app.ml.classifier import get_classifier
from app.providers.base import ProviderError
from app.providers.keypool import AllKeysCoolingError, AllKeysDeadError
from app.providers.registry import call_with_rotation, get_registry
from app.security.sanitize import clamp_enum

UNKNOWN = "unknown"


@traced(NodeName.CLASSIFY)
async def classify_node(state: PipelineState, trace: TraceBuilder) -> dict[str, Any]:
    from app.agent.prompts import CLASSIFY_SYSTEM, build_classify_prompt

    registry = get_registry()
    update: dict[str, Any] = {}

    # ---- tier 1: the trained model ------------------------------------
    classifier = get_classifier()
    prediction = classifier.predict(_as_alert_view(state))

    update.update(
        {
            "ml_attack_type": prediction.attack_type,
            "ml_severity": prediction.severity,
            "ml_confidence": prediction.probability,
            "attack_type": prediction.attack_type,
            "severity": prediction.severity,
            "confidence": prediction.probability,
            "model_version": prediction.model_version,
        }
    )

    ml_status = prediction.trace.get("status", "ok")
    ml_note = prediction.trace.get("reason") or prediction.trace.get("detail")

    # The escalation decision reads the state AS UPDATED, not the state as it
    # arrived — otherwise it would judge the previous alert's confidence.
    decided = state.model_copy(update=update)
    reason = escalation_reason(decided)

    if reason is None:
        trace.record(
            TraceStatus(ml_status),
            provider="lightgbm",
            model="attack_type+severity",
            model_version=prediction.model_version,
            note=ml_note,
        )
        return _admit(state, update, escalated=False)

    update["classification_escalated"] = True
    update["classification_escalation_reason"] = reason

    # ---- tier 2: the LLM ----------------------------------------------
    if registry.offline_mode:
        # PLAN §10.4 / E9 — declared and labelled. Offline mode does not
        # silently substitute for a provider; it says so on the entry, on the
        # payload (`degraded`) and on /health/deep.
        trace.record(
            TraceStatus.SKIPPED,
            provider="offline",
            model="deterministic-template",
            model_version=prediction.model_version,
            note=(
                f"escalation warranted ({reason}) but offline mode is on, so no "
                "provider was called; the fast tier's verdict stands and the "
                "alert is marked degraded"
            ),
        )
        update["degraded"] = True
        return _admit(state, update, escalated=True)

    try:
        result = await call_with_rotation(
            registry.groq_pool,
            lambda: registry.groq.complete(
                CLASSIFY_SYSTEM, build_classify_prompt(decided), max_tokens=400
            ),
        )
    except (ProviderError, AllKeysCoolingError, AllKeysDeadError) as exc:
        # I13 — a failed escalation does not erase the fast tier's verdict, and
        # it does not become a silent `unknown`. The model's answer stands, the
        # trace says the escalation failed, and the alert is degraded.
        # AllKeysCoolingError and AllKeysDeadError are named here so an
        # exhausted pool and a revoked one still produce a provider-attributed
        # entry rather than an anonymous one. Neither subclasses ProviderError
        # — they come from the pool, not from a provider response — so leaving
        # them out sends the exception to the @traced backstop, which records a
        # correct-looking failure while skipping this branch's I13 handling.
        trace.record(
            TraceStatus.FAILED,
            provider="groq",
            model=registry.groq.model,
            model_version=prediction.model_version,
            key_id=getattr(exc, "key_id", None),
            note=(
                f"escalated because {reason}; the LLM tier failed "
                f"({type(exc).__name__}: {exc}). The fast tier's verdict "
                f"({prediction.attack_type}/{prediction.severity}) stands."
            ),
        )
        update["degraded"] = True
        return _admit(state, update, escalated=True)

    from app.providers.base import parse_json_content

    try:
        # I18 — a 200 with empty, unparseable or incomplete content raises here
        # and is recorded as a FAILED call, counted in the denominator.
        parsed = parse_json_content(
            "groq", result.model, result.content, required=("attack_type", "severity")
        )
    except ProviderError as exc:
        trace.record(
            TraceStatus.FAILED,
            provider="groq",
            model=result.model,
            model_version=prediction.model_version,
            key_id=result.key_id,
            tokens=TokenUsage(
                prompt=result.prompt_tokens, completion=result.completion_tokens
            ),
            note=(
                f"escalated because {reason}; {exc} The fast tier's verdict "
                f"({prediction.attack_type}/{prediction.severity}) stands."
            ),
        )
        update["degraded"] = True
        return _admit(state, update, escalated=True)

    attack_type = clamp_enum(parsed.get("attack_type"), CANONICAL_CLASSES, UNKNOWN)
    severity = clamp_enum(parsed.get("severity"), SEVERITY_ORDER, UNKNOWN)

    confidence = parsed.get("confidence")
    confidence = (
        float(confidence)
        if isinstance(confidence, int | float) and 0.0 <= float(confidence) <= 1.0
        else None
    )

    update.update(
        {"attack_type": attack_type, "severity": severity, "confidence": confidence}
    )

    trace.record(
        TraceStatus.OK,
        provider="groq",
        model=result.model,
        model_version=prediction.model_version,
        key_id=result.key_id,
        tokens=TokenUsage(
            prompt=result.prompt_tokens, completion=result.completion_tokens
        ),
        note=(
            f"escalated because {reason}. Fast tier said "
            f"{prediction.attack_type}/{prediction.severity}; the LLM tier "
            f"returned {attack_type}/{severity}."
        ),
    )
    return _admit(state, update, escalated=True)


def _admit(
    state: PipelineState, update: dict[str, Any], *, escalated: bool
) -> dict[str, Any]:
    """Decide reasoning admission for EVERY alert, on the path every alert takes.

    This used to live in `enrich`, and a live run showed why that was wrong:
    enrichment is skipped whenever the source address is not publicly routable,
    which on CICIDS2017 is 90.5% of replay rows. Those alerts reached the reason
    node with no floor and no budget applied, and the demo would have 429'd
    inside the first minute (T4). `enrich` still re-decides when intel raises
    severity across the floor.
    """
    admitted, skip_reason = reserve_reasoning(
        str(update.get("severity", "unknown")),
        state.severity_floor,
        escalated=escalated,
    )
    update["reason_budget_available"] = admitted
    update["reason_skip_reason"] = skip_reason
    return update


class _AlertView:
    """The three attributes `FastTierClassifier.predict` reads.

    A shim rather than a real NormalizedAlert because the graph state is the
    source of truth inside the pipeline, and constructing a full alert object
    here would mean two representations that can drift apart.
    """

    __slots__ = ("features", "source")

    def __init__(self, source: str, features: dict[str, float]) -> None:
        self.source = source
        self.features = features


def _as_alert_view(state: PipelineState) -> Any:
    return _AlertView(state.source, state.features)
