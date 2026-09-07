"""Tokens, cost and the success rate. PLAN §11.

Two defects from the prior codebases are the subject here. One shipped an empty
price dict with a `0.0` default, so an un-priced model rendered as free. The
other counted "non-null severity plus non-null latency" as a successful call, so
its deterministic path scored 100% by construction and a real failure could not
be seen at all.
"""

import pytest

from app.eval import pricing
from app.eval.pricing import CallRecord, aggregate, categorize, cost_usd
from app.providers.base import (
    EmptyContentError,
    ProviderHTTPError,
    ProviderTimeout,
    RateLimited,
)
from app.providers.keypool import AllKeysCoolingError


def call(model: str | None, outcome: str, prompt: int = 0, completion: int = 0):
    return CallRecord(
        provider="groq",
        model=model,
        outcome=outcome,
        prompt_tokens=prompt,
        completion_tokens=completion,
    )


# ---------------------------------------------------------------------------
# PLAN §11 — cost is real or ABSENT, never a 0.0 that reads as free
# ---------------------------------------------------------------------------


def test_an_unpriced_model_has_no_cost_rather_than_a_zero():
    assert cost_usd("some/model-nobody-priced", 1_000_000, 1_000_000) is None


def test_the_payload_omits_cost_entirely_when_nothing_priced_was_called():
    payload = aggregate([call("some/unpriced", pricing.SUCCESS, 100, 50)])

    assert "cost_usd" not in payload
    assert payload["unpriced_models"] == ["some/unpriced"]
    assert payload["per_model"]["some/unpriced"]["cost_usd"] is None
    assert payload["per_model"]["some/unpriced"]["priced"] is False


def test_no_zero_default_masquerades_as_free():
    """The exact footgun: a 0.0 that a reader takes for 'this was free'."""
    payload = aggregate([call("some/unpriced", pricing.SUCCESS, 5_000_000, 0)])

    assert payload.get("cost_usd") is None
    assert payload["per_model"]["some/unpriced"]["cost_usd"] != 0.0


def test_a_priced_model_produces_a_real_arithmetic_cost():
    # gpt-oss-120b: $0.15/1M in, $0.60/1M out.
    payload = aggregate([call("openai/gpt-oss-120b", pricing.SUCCESS, 1_000_000, 1_000_000)])

    assert payload["cost_usd"] == pytest.approx(0.75)
    assert payload["per_model"]["openai/gpt-oss-120b"]["priced"] is True
    assert payload["per_model"]["openai/gpt-oss-120b"]["price_source"].startswith("http")


def test_every_price_carries_its_provenance():
    """A price with no source is a number somebody remembered."""
    assert pricing.PRICE_TABLE
    for model, price in pricing.PRICE_TABLE.items():
        assert price.source.startswith("https://"), model
        assert price.input_per_million > 0, model
        assert price.output_per_million > 0, model
    assert pricing.PRICES_AS_OF


def test_the_priced_models_are_the_ids_the_build_actually_calls():
    """PLAN D31 pinned these by live probe; a price for a model nobody calls
    would be decoration, and a missing one silently loses a cost."""
    from app.config import get_settings

    settings = get_settings()
    for model in (
        settings.groq_model_primary,
        settings.groq_model_fallback,
        settings.gemini_model,
    ):
        assert model in pricing.PRICE_TABLE, model


def test_the_pricing_note_says_the_spend_is_modelled_not_incurred():
    payload = aggregate([call("openai/gpt-oss-120b", pricing.SUCCESS, 10, 10)])
    assert "free tier" in payload["pricing_note"]


# ---------------------------------------------------------------------------
# PLAN §11 — a success rate that can see a failure
# ---------------------------------------------------------------------------


def test_empty_content_is_a_failure_not_an_answer():
    """PLAN I18 / D29 — a 200 carrying nothing usable is a FAILED call."""
    records = [
        call("openai/gpt-oss-120b", pricing.SUCCESS, 100, 20),
        call("openai/gpt-oss-120b", pricing.EMPTY_CONTENT),
    ]
    payload = aggregate(records)

    assert payload["calls_attempted"] == 2
    assert payload["calls_succeeded"] == 1
    assert payload["success_rate"] == 0.5
    assert payload["outcomes"][pricing.EMPTY_CONTENT] == 1


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (EmptyContentError("groq", "200 with nothing in it"), pricing.EMPTY_CONTENT),
        (ProviderHTTPError("groq", 400, "bad request"), pricing.HTTP_4XX),
        (ProviderHTTPError("groq", 503, "overloaded"), pricing.HTTP_5XX),
        (ProviderTimeout("groq", "took too long"), pricing.TIMEOUT),
        (RateLimited("groq", "groq-dev", 30.0), pricing.RATE_LIMITED),
        (AllKeysCoolingError("groq", 30.0), pricing.POOL_EXHAUSTED),
        (RuntimeError("something else"), pricing.OTHER_ERROR),
    ],
)
def test_each_failure_mode_is_its_own_category(exc: BaseException, expected: str):
    """Collapsing these would make a rate limit indistinguishable from a bug."""
    assert categorize(exc) == expected


def test_the_failure_categories_are_all_distinct_from_success():
    assert pricing.SUCCESS not in pricing.FAILURE_CATEGORIES
    assert len(set(pricing.FAILURE_CATEGORIES)) == len(pricing.FAILURE_CATEGORIES)


def test_a_success_rate_over_zero_calls_is_undefined_not_one_hundred_percent():
    payload = aggregate([])
    assert payload["success_rate"] is None
    assert payload["calls_attempted"] == 0


def test_skipped_stages_are_not_counted_as_attempted_calls():
    """A stage that made no request cannot have succeeded or failed at one."""
    payload = aggregate(
        [
            call("openai/gpt-oss-120b", pricing.SUCCESS, 10, 5),
            CallRecord(provider="offline", model=None, outcome=pricing.SKIPPED),
        ]
    )

    assert payload["calls_attempted"] == 1
    assert payload["success_rate"] == 1.0
    assert "unknown" not in payload["per_model"]
