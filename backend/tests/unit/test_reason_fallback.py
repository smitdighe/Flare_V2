"""Reason-node cross-provider fallback. PLAN Phase 4 item 0.2 / I18 / §10.3.

Measured in Phase 3: `gemini-3.6-flash` returned 503 on roughly one call in
eight. With one provider that renders as a visibly failed reasoning stage in
the drawer once every eight alerts — honest, and it looks broken at exactly the
moment the reasoning tier is being demonstrated.

These tests pin the three behaviours that make the fallback trustworthy:

  1. a 503 or a timeout on Gemini ADVANCES to Groq and the narrative arrives;
  2. the trace names the FALLBACK provider and model DISTINCTLY, and says the
     primary failed and why — a silent substitution would be worse than the
     failure it replaces, because an analyst would attribute Groq's words to
     Gemini;
  3. both providers failing is a FAILED stage carrying BOTH verbatim errors.

Plus the negative: a 400 does NOT fail over. A request the primary rejected as
malformed is a request the fallback will also reject, and trying it spends a
second quota to reproduce the same failure.

Providers are stubbed; the routers, the trace decorator, the grounding and the
finalize backfill are the real ones.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.agent.graph import reset_graph, run_pipeline
from app.agent.nodes.reason import should_failover
from app.agent.state import NodeName, TraceStatus
from app.config import Settings
from app.providers.base import ProviderHTTPError, ProviderTimeout
from app.providers.keypool import AllKeysCoolingError
from app.rag.retriever import Retrieved
from tests.unit.conftest_graph import (
    StubAggregator,
    StubClassifier,
    StubIntelVerdict,
    StubLLM,
    StubRetriever,
    alert_stub,
    stub_registry,
    trace_map,
)

REASON_PAYLOAD = {
    "explanation": "A burst of unanswered SYN packets consistent with a flood.",
    "remediation": "Rate-limit the source at the edge.",
    "technique_ids": ["T1498"],
}

HITS = [
    Retrieved(
        technique_id="T1498",
        name="Network Denial of Service",
        section="description",
        score=0.71,
    )
]


def settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "jwt_secret": "t" * 40,
        "environment": "test",
        "offline_mode": False,
        "reason_severity_floor": "low",
        "reason_calls_per_minute": 600.0,
        "escalation_confidence_threshold": 0.5,
    }
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch):
    """Same wiring as tests/unit/test_graph.py — stub the network, keep the graph."""

    def _wire(groq: StubLLM | None = None, gemini: StubLLM | None = None, **over: Any):
        config = settings(**over)
        registry = stub_registry(config, groq=groq, gemini=gemini)
        monkeypatch.setattr("app.providers.registry.get_registry", lambda: registry)
        monkeypatch.setattr("app.agent.nodes.reason.get_registry", lambda: registry)
        monkeypatch.setattr("app.agent.nodes.classify.get_registry", lambda: registry)
        monkeypatch.setattr(
            "app.agent.nodes.enrich.get_aggregator",
            lambda: StubAggregator(
                StubIntelVerdict(ip="118.25.6.39", checked=True, score=0)
            ),
        )
        monkeypatch.setattr(
            "app.agent.nodes.retrieve.get_retriever", lambda: StubRetriever(HITS)
        )
        monkeypatch.setattr(
            "app.agent.nodes.classify.get_classifier",
            lambda: StubClassifier("dos", "high", 1.0),
        )
        reset_graph()
        from app.agent.budget import reset_reason_budget

        reset_reason_budget(config.reason_calls_per_minute)
        return config

    return _wire


def _gemini_503() -> ProviderHTTPError:
    return ProviderHTTPError(
        "gemini",
        503,
        '{"error":{"code":503,"message":"The model is overloaded. '
        'Please try again later."}}',
        "gemini-dev",
    )


# ---------------------------------------------------------------------------
# the decision, on its own
# ---------------------------------------------------------------------------


def test_a_503_and_a_timeout_and_an_exhausted_pool_fail_over() -> None:
    assert should_failover(_gemini_503()) is True
    assert should_failover(ProviderTimeout("gemini", "25s exceeded", "gemini-dev")) is True
    assert should_failover(AllKeysCoolingError("gemini", 47.0)) is True


def test_a_client_error_does_not_fail_over() -> None:
    """A request the primary rejected is a request the fallback will reject too.

    Spending a second provider's quota to reproduce the same 400 is how a
    fallback turns one failure into two.
    """
    assert (
        should_failover(
            ProviderHTTPError("gemini", 400, "invalid argument", "gemini-dev")
        )
        is False
    )


# ---------------------------------------------------------------------------
# through the real graph
# ---------------------------------------------------------------------------


async def test_a_503_on_the_primary_advances_to_the_fallback(wire) -> None:
    groq = StubLLM("groq", "openai/gpt-oss-120b", payload=REASON_PAYLOAD)
    config = wire(
        gemini=StubLLM("gemini", "gemini-3.6-flash", error=_gemini_503()),
        groq=groq,
    )
    state = await run_pipeline(alert_stub(), config)
    entry = trace_map(state)["reason"]

    assert entry.status is TraceStatus.OK
    assert state.explanation == REASON_PAYLOAD["explanation"]
    # The reason node called Groq exactly once. (The classifier is confident,
    # so it did not escalate and did not call Groq itself.)
    assert len(groq.calls) == 1


async def test_the_trace_names_the_fallback_provider_and_model_distinctly(
    wire,
) -> None:
    """The substitution is visible, or it is a lie by omission.

    An analyst reading the drawer has to be able to tell which provider wrote
    the narrative in front of them. `provider` and `model` are the fallback's
    own values — not Gemini's — and the note quotes what the primary said.
    """
    config = wire(
        gemini=StubLLM("gemini", "gemini-3.6-flash", error=_gemini_503()),
        groq=StubLLM("groq", "openai/gpt-oss-120b", payload=REASON_PAYLOAD),
    )
    state = await run_pipeline(alert_stub(), config)
    entry = trace_map(state)["reason"]

    assert entry.provider == "groq"
    assert entry.model == "openai/gpt-oss-120b"
    assert entry.provider != "gemini"
    assert entry.model != "gemini-3.6-flash"
    note = entry.note or ""
    assert "FALLBACK" in note
    assert "gemini/gemini-3.6-flash" in note
    assert "The model is overloaded" in note, "the primary's own words, verbatim"
    assert entry.key_id == "groq-dev", "I16 — attributed to the serving key label"


async def test_a_timeout_on_the_primary_also_advances(wire) -> None:
    config = wire(
        gemini=StubLLM(
            "gemini",
            "gemini-3.6-flash",
            error=ProviderTimeout(
                "gemini", "gemini-3.6-flash exceeded 25.0s", "gemini-dev"
            ),
        ),
        groq=StubLLM("groq", "openai/gpt-oss-120b", payload=REASON_PAYLOAD),
    )
    state = await run_pipeline(alert_stub(), config)
    entry = trace_map(state)["reason"]

    assert entry.status is TraceStatus.OK
    assert entry.provider == "groq"
    assert "exceeded 25.0s" in (entry.note or "")


async def test_both_providers_failing_is_a_failed_stage_with_both_errors(
    wire,
) -> None:
    config = wire(
        gemini=StubLLM("gemini", "gemini-3.6-flash", error=_gemini_503()),
        groq=StubLLM(
            "groq",
            "openai/gpt-oss-120b",
            error=ProviderHTTPError("groq", 502, "upstream connect error", "groq-dev"),
        ),
    )
    state = await run_pipeline(alert_stub(), config)
    entry = trace_map(state)["reason"]

    assert entry.status is TraceStatus.FAILED
    note = entry.note or ""
    assert "The model is overloaded" in note, "gemini's error, verbatim"
    assert "upstream connect error" in note, "groq's error, verbatim"
    assert state.explanation is None, "CONTRACT §4.1 — the strip must not light up"
    assert state.degraded is True
    # I1 — one entry per node, even with two providers down.
    assert len(state.trace) == len(NodeName)


async def test_a_client_error_on_the_primary_does_not_spend_the_fallback(
    wire,
) -> None:
    groq = StubLLM("groq", "openai/gpt-oss-120b", payload=REASON_PAYLOAD)
    config = wire(
        gemini=StubLLM(
            "gemini",
            "gemini-3.6-flash",
            error=ProviderHTTPError("gemini", 400, "invalid argument", "gemini-dev"),
        ),
        groq=groq,
    )
    state = await run_pipeline(alert_stub(), config)
    entry = trace_map(state)["reason"]

    assert entry.status is TraceStatus.FAILED
    assert entry.provider == "gemini"
    assert groq.calls == [], "no failover, so no second quota was spent"
    assert "no failover was attempted" in (entry.note or "")


async def test_an_empty_content_failure_does_not_fail_over(wire) -> None:
    """I18 — a 200 with nothing usable is a failed call, not an outage.

    The provider answered; it answered badly. Advancing to a second provider
    would treat a content problem as an availability problem.
    """
    groq = StubLLM("groq", "openai/gpt-oss-120b", payload=REASON_PAYLOAD)
    config = wire(
        gemini=StubLLM("gemini", "gemini-3.6-flash", raw="   "),
        groq=groq,
    )
    state = await run_pipeline(alert_stub(), config)
    entry = trace_map(state)["reason"]

    assert entry.status is TraceStatus.FAILED
    assert entry.provider == "gemini"
    assert groq.calls == []
