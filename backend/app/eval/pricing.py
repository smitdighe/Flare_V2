"""Token and cost accounting. PLAN §11.

**A MISSING PRICE IS ABSENT, NEVER ZERO.** The prior codebase shipped an empty
price dict with a `0.0` default and two consumers that disagreed about what that
meant, so an un-priced model rendered as free. Here, `cost_usd` is `None` for a
model with no verified entry and the payload says which models were priced and
which were not. A null is a question; a zero is a wrong answer.

**THE PRICES ARE LIST PRICES, AND THIS PROJECT PAYS NONE OF THEM.** Every
provider key in this build is on a free tier (PLAN §21), so real spend is zero
and the figure below is what the same traffic WOULD cost at published rates. It
is reported as a modelled cost with that stated, because quoting it as spend
would be a fabrication in the other direction.

Each entry carries its source URL and the date it was read. A price with no
provenance is a number somebody remembered, and provider prices move.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

PRICES_AS_OF = "2026-09-05"


@dataclass(frozen=True)
class ModelPrice:
    """USD per 1,000,000 tokens, as published."""

    input_per_million: float
    output_per_million: float
    source: str
    note: str | None = None


# Verified against the providers' own pricing pages on PRICES_AS_OF, for the
# exact model ids PLAN D31 pinned by live probe. A model absent from this table
# is priced as None, not as free.
PRICE_TABLE: dict[str, ModelPrice] = {
    "openai/gpt-oss-120b": ModelPrice(
        input_per_million=0.15,
        output_per_million=0.60,
        source="https://console.groq.com/docs/model/openai/gpt-oss-120b",
        note="cached input is $0.075/1M; this build sends no cached prefixes, "
        "so the uncached input rate is the one that applies",
    ),
    "qwen/qwen3.8-27b": ModelPrice(
        input_per_million=0.80,
        output_per_million=4.00,
        source="https://console.groq.com/docs/models",
        note="Groq preview model; the classifier's second fallback",
    ),
    "gemini-3.6-flash": ModelPrice(
        input_per_million=0.75,
        output_per_million=3.75,
        source="https://ai.google.dev/gemini-api/docs/pricing",
        note="introductory rate through 2026-12-31; $1.50/$7.50 from 2027-01-01",
    ),
}


def price_for(model: str | None) -> ModelPrice | None:
    return PRICE_TABLE.get(model) if model else None


def cost_usd(model: str | None, prompt_tokens: int, completion_tokens: int) -> float | None:
    """None when the model has no verified price. Never 0.0 as a stand-in."""
    price = price_for(model)
    if price is None:
        return None
    return (
        prompt_tokens * price.input_per_million
        + completion_tokens * price.output_per_million
    ) / 1_000_000


# ---------------------------------------------------------------------------
# provider call outcomes — PLAN §11 "must be able to detect a failed call"
# ---------------------------------------------------------------------------

SUCCESS = "success"
EMPTY_CONTENT = "empty_content"
HTTP_4XX = "http_4xx"
HTTP_5XX = "http_5xx"
TIMEOUT = "timeout"
RATE_LIMITED = "rate_limited"
POOL_EXHAUSTED = "pool_exhausted"
SKIPPED = "skipped"
OTHER_ERROR = "other_error"

FAILURE_CATEGORIES: tuple[str, ...] = (
    EMPTY_CONTENT,
    HTTP_4XX,
    HTTP_5XX,
    TIMEOUT,
    RATE_LIMITED,
    POOL_EXHAUSTED,
    OTHER_ERROR,
)


def categorize(exc: BaseException) -> str:
    """Map a provider exception to a category the success rate can count.

    The prior codebase counted "non-null severity plus non-null latency" as
    success, so its deterministic path scored 100% by construction and a real
    failure was undetectable. These categories exist so that an I18 empty-content
    failure — a 200 that carried nothing usable — is a DIFFERENT observation
    from an answer, not the same one.
    """
    from app.providers.base import (
        EmptyContentError,
        ProviderHTTPError,
        ProviderTimeout,
        RateLimited,
    )
    from app.providers.keypool import AllKeysCoolingError, EmptyPoolError

    if isinstance(exc, EmptyContentError):
        return EMPTY_CONTENT
    if isinstance(exc, RateLimited):
        return RATE_LIMITED
    if isinstance(exc, AllKeysCoolingError | EmptyPoolError):
        return POOL_EXHAUSTED
    if isinstance(exc, ProviderTimeout | TimeoutError):
        return TIMEOUT
    if isinstance(exc, ProviderHTTPError):
        return HTTP_4XX if 400 <= exc.status_code < 500 else HTTP_5XX
    return OTHER_ERROR


@dataclass
class CallRecord:
    """One provider call the eval made or observed."""

    provider: str
    model: str | None
    outcome: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    duration_ms: float | None = None

    @property
    def succeeded(self) -> bool:
        return self.outcome == SUCCESS


def aggregate(records: list[CallRecord]) -> dict[str, Any]:
    """Tokens, cost and a success rate that can actually see a failure."""
    attempted = [r for r in records if r.outcome != SKIPPED]
    successes = [r for r in attempted if r.succeeded]

    per_model: dict[str, dict[str, Any]] = {}
    unpriced: set[str] = set()
    total_cost: float | None = None

    # Only calls that were actually ISSUED get a per-model line. A skipped
    # stage made no request, so pricing it would invent a model that was never
    # asked anything and list it as "unpriced".
    for record in attempted:
        key = record.model or "unknown"
        entry = per_model.setdefault(
            key,
            {
                "calls": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "cost_usd": None,
                "priced": False,
            },
        )
        entry["calls"] += 1
        entry["prompt_tokens"] += record.prompt_tokens
        entry["completion_tokens"] += record.completion_tokens

    for key, entry in per_model.items():
        price = price_for(key)
        if price is None:
            unpriced.add(key)
            continue
        entry["priced"] = True
        entry["cost_usd"] = round(
            (
                entry["prompt_tokens"] * price.input_per_million
                + entry["completion_tokens"] * price.output_per_million
            )
            / 1_000_000,
            8,
        )
        entry["price_source"] = price.source
        total_cost = (total_cost or 0.0) + entry["cost_usd"]

    payload: dict[str, Any] = {
        "calls_attempted": len(attempted),
        "calls_succeeded": len(successes),
        # None rather than 1.0 when nothing was attempted: a success rate over
        # zero calls is not 100%, it is undefined.
        "success_rate": (
            round(len(successes) / len(attempted), 6) if attempted else None
        ),
        "outcomes": dict(sorted(Counter(r.outcome for r in records).items())),
        "prompt_tokens": sum(r.prompt_tokens for r in attempted),
        "completion_tokens": sum(r.completion_tokens for r in attempted),
        "per_model": dict(sorted(per_model.items())),
        "prices_as_of": PRICES_AS_OF,
        "pricing_note": (
            "List prices for the paid tier. Every provider key in this build is "
            "on a free tier, so actual spend is zero and this figure is what the "
            "same traffic would cost at published rates."
        ),
    }

    # PLAN §11 — the field is real or it is ABSENT. It is never a 0.0 that reads
    # as free.
    if total_cost is not None:
        payload["cost_usd"] = round(total_cost, 8)
    if unpriced:
        payload["unpriced_models"] = sorted(unpriced)
    return payload
