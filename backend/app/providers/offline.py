"""Deterministic offline provider. PLAN §10.4 / E9 / I5.

Exists so the system is demonstrable with the network down or every key
exhausted. It is a REAL, DECLARED tier, not a fallback that hides a failure:

  * `provider` in the trace is `offline`, never `groq` or `gemini`;
  * `model` is `deterministic-template`, which is what it is;
  * every alert it touches carries `degraded: true` on the payload;
  * /health/deep reports `offline_mode`.

The distinction that matters: this NEVER activates by itself. A provider
failure produces a `failed` trace entry and an `unknown` verdict. Only the
explicit `offline_mode` setting routes here. A fallback that silently
substitutes template text for model output is T3, and it is the single failure
this whole design is arranged against.

The text it produces describes the FLOW, never a verdict it did not compute.
It states what the classifier decided and what the retriever returned, and says
plainly that no model reasoned about it.
"""

from __future__ import annotations

import json

from app.providers.base import LLMResult

PROVIDER = "offline"
MODEL = "deterministic-template"

NOTICE = (
    "OFFLINE MODE — no language model was called for this alert. The verdict "
    "below is the trained classifier's, and the technique is the retriever's; "
    "the narrative is a template, not generated text."
)


class OfflineProvider:
    """Structured output with the same shape a real provider returns."""

    model = MODEL

    async def classify(
        self, attack_type: str, severity: str, signature: str
    ) -> LLMResult:
        payload: dict[str, object] = {
            "attack_type": attack_type,
            "severity": severity,
            "confidence": None,
            "rationale": NOTICE,
        }
        return self._result(payload)

    async def reason(
        self,
        attack_type: str,
        severity: str,
        signature: str,
        technique_ids: list[str],
    ) -> LLMResult:
        payload: dict[str, object] = {
            "explanation": (
                f"{NOTICE} Classifier verdict: {attack_type} at {severity} severity. "
                f"Observed flow shape: {signature}"
            ),
            "remediation": (
                "Offline mode: no model-generated remediation. Triage manually "
                "against the retrieved technique."
            ),
            "technique_ids": technique_ids,
            "confidence": None,
        }
        return self._result(payload)

    def _result(self, payload: dict[str, object]) -> LLMResult:
        return LLMResult(
            provider=PROVIDER,
            model=MODEL,
            key_id="offline",
            content=json.dumps(payload),
            # Zero because zero tokens were spent, not because the field is
            # unknown. PLAN §11 forbids a placeholder that reads as a real
            # measurement; here the real measurement IS zero.
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0.0,
            data=dict(payload),
        )
