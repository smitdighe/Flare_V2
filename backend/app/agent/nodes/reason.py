"""reason — the quality tier. PLAN D18 / D30 / D31 / I18 / §4.4.

**THIS NODE IS NOT GATED ON CLASSIFICATION CONFIDENCE, AND THAT IS THE POINT.**
Phase 2a measured that 99.7% of eval rows sit at calibrated confidence exactly
1.0, so escalation fires roughly three times per thousand alerts. Wiring
reasoning behind that gate would mean the LLM effectively never runs during a
replay — the reasoning story would be hollow on stage and the drawer's
explanation field would be null on almost every alert. Reasoning is a different
job: narrative, MITRE mapping, remediation. A perfectly-classified high-severity
alert still needs an explanation for the analyst. The gate is a severity floor
plus a rate budget, applied in `route_after_enrich`.

**CROSS-PROVIDER FALLBACK — GEMINI PRIMARY, GROQ SECOND.** Measured during
Phase 3, `gemini-3.6-flash` returned 503 "the model is overloaded" on roughly
one call in eight. With a single provider that renders, once every eight
alerts, as a visibly failed reasoning stage in the drawer — honest, and it
looks broken at exactly the moment the reasoning tier is being demonstrated.
The classifier has had a Groq fallback since Phase 3; this gives the reason
node one too.

  * A 5xx, a TIMEOUT, or an exhausted key pool on Gemini advances to Groq.
    Those are the three shapes of "the primary cannot answer right now".
  * A 4xx, or an I18 empty-content failure, does NOT advance. A 400 means the
    request is wrong and Groq would reject the same request; retrying an
    unusable prompt on a second provider spends a second quota to reproduce
    the same failure.
  * Exhausting both is a FAILED stage carrying BOTH verbatim errors — the
    Gemini message and the Groq message, in one note, so an operator can see
    what each provider actually said.

**THE SUBSTITUTION IS NEVER HIDDEN.** The trace entry records the provider and
model that actually answered — `groq` / `openai/gpt-oss-120b`, distinct values,
not Gemini's — and the note says the primary failed and quotes why. An analyst
reading the drawer can always tell which provider wrote the narrative in front
of them.

**GROUNDING IS ENFORCED (§4.4).** Every technique ID the model returns that the
retriever did not return is DROPPED. The model can name anything it likes; only
retrieved IDs survive into the output. This is the half the prior codebase never
had — it printed whatever the model said.

**I18** — a 200 with empty, unparseable or field-missing content is a FAILED
call: `failed` in the trace, no explanation written, `degraded` on the payload.
It never becomes template text wearing a provider's name (T3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.agent.state import NodeName, PipelineState, TokenUsage, TraceStatus
from app.agent.trace import TraceBuilder, traced
from app.ingestion.labels import CANONICAL_CLASSES, SEVERITY_ORDER
from app.providers.base import (
    LLMResult,
    ProviderError,
    ProviderHTTPError,
    ProviderTimeout,
    parse_json_content,
)
from app.providers.keypool import AllKeysCoolingError, AllKeysDeadError
from app.providers.registry import call_with_rotation, get_registry
from app.security.sanitize import clamp_enum, clamp_text

UNKNOWN = "unknown"

# The failure shapes that mean "this provider cannot answer right now", as
# opposed to "this request is wrong". Only the first kind is worth a second
# provider.
FAILOVER_STATUS_CODES: frozenset[int] = frozenset({500, 502, 503, 504, 529})


@dataclass
class _Attempt:
    """One provider's turn: what answered, or what went wrong."""

    provider: str
    model: str
    result: LLMResult | None = None
    error: Exception | None = None

    @property
    def failed(self) -> bool:
        return self.result is None

    def describe_error(self) -> str:
        return f"{type(self.error).__name__}: {self.error}"


def should_failover(exc: Exception) -> bool:
    """Is this a provider that cannot answer, or a request that cannot work?

    Kept module-level and free of state so the decision is unit-testable
    without a graph, a registry or a network.
    """
    # AllKeysDeadError is here for the same reason AllKeysCoolingError is: the
    # primary cannot answer. It is in fact the STRONGER case — a cooling pool
    # recovers on its own and a dead one never does — so a dead Gemini pool
    # while Groq is healthy must reach Groq. PLAN D39.
    if isinstance(exc, ProviderTimeout | AllKeysCoolingError | AllKeysDeadError):
        return True
    if isinstance(exc, ProviderHTTPError):
        return exc.status_code in FAILOVER_STATUS_CODES
    return False


@traced(NodeName.REASON)
async def reason_node(state: PipelineState, trace: TraceBuilder) -> dict[str, Any]:
    from app.agent.prompts import (
        REASON_SYSTEM,
        RECLASSIFY_INSTRUCTION,
        build_reason_prompt,
    )

    registry = get_registry()

    if registry.offline_mode:
        offline = await registry.offline.reason(
            state.attack_type,
            state.severity,
            state.signature,
            [t.technique_id for t in state.retrieved],
        )
        trace.record(
            TraceStatus.OK,
            provider="offline",
            model=registry.offline.model,
            note=(
                "offline mode: the narrative is a deterministic template, not "
                "generated text, and the alert is marked degraded (PLAN E9)"
            ),
        )
        return {
            "explanation": str(offline.data["explanation"]),
            "remediation": str(offline.data["remediation"]),
            "degraded": True,
        }

    system = REASON_SYSTEM + (RECLASSIFY_INSTRUCTION if state.reclassify_requested else "")
    prompt = build_reason_prompt(state, state.retrieved)

    primary = _Attempt(provider="gemini", model=registry.gemini.model)
    try:
        primary.result = await call_with_rotation(
            registry.gemini_pool,
            lambda: registry.gemini.complete(system, prompt, max_tokens=900),
        )
    except (ProviderError, AllKeysCoolingError, AllKeysDeadError) as exc:
        primary.error = exc

    served = primary
    fallback: _Attempt | None = None

    if primary.failed and should_failover(primary.error or Exception()):
        fallback = _Attempt(provider="groq", model=registry.groq.model)
        try:
            fallback.result = await call_with_rotation(
                registry.groq_pool,
                lambda: registry.groq.complete(system, prompt, max_tokens=900),
            )
        except (ProviderError, AllKeysCoolingError, AllKeysDeadError) as exc:
            fallback.error = exc
        served = fallback

    if served.failed:
        # Both providers are named with their own verbatim message. A merged
        # "reasoning failed" would lose which one broke and how, which is the
        # only thing an operator can act on.
        parts = [
            f"primary gemini/{primary.model} failed — {primary.describe_error()}"
        ]
        if fallback is not None:
            parts.append(
                f"fallback groq/{fallback.model} also failed — "
                f"{fallback.describe_error()}"
            )
        elif primary.error is not None:
            parts.append(
                "no failover was attempted: this is a request-level failure, "
                "and a second provider would reject the same request while "
                "spending a second quota"
            )
        trace.record(
            TraceStatus.FAILED,
            provider=served.provider,
            model=served.model,
            key_id=getattr(served.error, "key_id", None),
            note="; ".join(parts),
        )
        # CONTRACT §4.1 — a failed reason node must leave `explanation` null, or
        # the table's stage strip renders the stage as complete.
        return {"explanation": None, "remediation": None, "degraded": True}

    result = served.result
    assert result is not None  # `served.failed` is False, so this is populated

    failover_note = (
        None
        if fallback is None
        else (
            f"answered by the FALLBACK provider {served.provider}/{result.model} "
            f"because the primary gemini/{primary.model} was unavailable "
            f"({primary.describe_error()})"
        )
    )

    def _fail(note: str) -> dict[str, Any]:
        trace.record(
            TraceStatus.FAILED,
            provider=served.provider,
            model=result.model,
            key_id=result.key_id,
            tokens=TokenUsage(
                prompt=result.prompt_tokens, completion=result.completion_tokens
            ),
            note="; ".join([note, failover_note]) if failover_note else note,
        )
        return {"explanation": None, "remediation": None, "degraded": True}

    try:
        parsed = parse_json_content(
            served.provider, result.model, result.content, required=("explanation",)
        )
    except ProviderError as exc:
        return _fail(str(exc))

    # PLAN §4.4 — grounding. Anything the retriever did not return is dropped.
    claimed = parsed.get("technique_ids")
    claimed_ids = [str(t) for t in claimed] if isinstance(claimed, list) else []
    allowed = {t.technique_id for t in state.retrieved}
    grounded = [t for t in claimed_ids if t in allowed]
    dropped = [t for t in claimed_ids if t not in allowed]

    update: dict[str, Any] = {
        "explanation": clamp_text(parsed.get("explanation"), 900),
        "remediation": clamp_text(parsed.get("remediation"), 400),
    }
    if grounded:
        update["mitre_technique"] = grounded[0]

    note_parts = [f"grounded {len(grounded)}/{len(claimed_ids)} technique ids"]
    if dropped:
        note_parts.append(
            f"dropped {dropped} — not returned by the retriever, so not evidence"
        )

    if state.reclassify_requested:
        attack_type = clamp_enum(parsed.get("attack_type"), CANONICAL_CLASSES, UNKNOWN)
        severity = clamp_enum(parsed.get("severity"), SEVERITY_ORDER, UNKNOWN)
        if attack_type != UNKNOWN:
            update["attack_type"] = attack_type
        if severity != UNKNOWN:
            update["severity"] = severity
        note_parts.append(
            f"second opinion requested; returned {attack_type}/{severity} against "
            f"the fast tier's {state.ml_attack_type}/{state.ml_severity}"
        )

    if state.retrieval_low_confidence:
        note_parts.append(
            "retrieval confidence was low for this alert, so the technique "
            "mapping is weaker than the narrative implies"
        )

    if update["explanation"] is None:
        # `required=("explanation",)` guarantees the KEY exists; it does not
        # guarantee the value is usable text. An empty string here is the same
        # class of failure as an empty body (I18).
        return _fail("returned an 'explanation' field with no usable text (PLAN I18)")

    if failover_note:
        note_parts.insert(0, failover_note)

    trace.record(
        TraceStatus.OK,
        provider=served.provider,
        model=result.model,
        key_id=result.key_id,
        tokens=TokenUsage(
            prompt=result.prompt_tokens, completion=result.completion_tokens
        ),
        note="; ".join(note_parts),
    )
    return update
