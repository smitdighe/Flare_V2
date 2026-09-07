"""Failure injection — the provider half. PLAN §12.

Every test here breaks a provider on purpose and asserts the SPECIFIC shape the
system is supposed to take on. The point of the layer is not that nothing
crashes; it is that each distinct failure stays distinguishable all the way to
the trace, the payload and the denominator. A build that collapses "timeout",
"rate limited" and "the model answered nonsense" into one `unknown` has lost the
information an operator needs, and it would still pass a test that only asserted
"no exception escaped".

The transport is `httpx.MockTransport` throughout: no key here is real and no
request leaves the machine, so a failing provider is injected rather than waited
for.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from app.providers.base import (
    EmptyContentError,
    KeyRevoked,
    ProviderError,
    ProviderHTTPError,
    ProviderTimeout,
    RateLimited,
    key_revocation_reason,
)
from app.providers.gemini import GeminiClient
from app.providers.groq import GroqClient
from app.providers.keypool import (
    AllKeysCoolingError,
    AllKeysDeadError,
    KeyPool,
)
from app.providers.registry import call_with_rotation

pytestmark = pytest.mark.failure


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _mock_transport(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    """Swap `httpx.AsyncClient` for the duration of one test, then restore.

    The CONSTRUCTOR still runs inside the client's own `try`, which is the T1
    property: a client that builds its transport outside the try turns a
    connection failure into an unhandled exception rather than a ProviderError.
    """
    import app.providers.gemini as gemini_mod
    import app.providers.groq as groq_mod

    slot: dict[str, object] = {}
    real = httpx.AsyncClient

    class _Client(real):  # type: ignore[misc,valid-type]
        def __init__(self, **kwargs: object) -> None:
            handler = slot["handler"]
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(groq_mod.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(gemini_mod.httpx, "AsyncClient", _Client)
    yield slot


@pytest.fixture
def install(_mock_transport: dict[str, object]):
    def _install(handler) -> None:
        _mock_transport["handler"] = handler

    return _install


def groq_client(
    install, handler, keys: dict[str, str | None] | None = None
) -> tuple[GroqClient, KeyPool]:
    install(handler)
    key_pool = KeyPool("groq", keys or {"dev": "k-dev"}, default_cooldown_seconds=60.0)
    return (
        GroqClient(
            key_pool,
            model="openai/gpt-oss-120b",
            timeout_seconds=5.0,
            reasoning_format="hidden",
            reasoning_effort="low",
        ),
        key_pool,
    )


def gemini_client(
    install, handler, keys: dict[str, str | None] | None = None
) -> tuple[GeminiClient, KeyPool]:
    install(handler)
    key_pool = KeyPool(
        "gemini", keys or {"dev": "k-dev"}, default_cooldown_seconds=60.0
    )
    return (
        GeminiClient(
            key_pool,
            model="gemini-3.6-flash",
            timeout_seconds=5.0,
            thinking_level="low",
        ),
        key_pool,
    )


def chat_body(content: str) -> dict[str, object]:
    return {
        "model": "openai/gpt-oss-120b",
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


# ---------------------------------------------------------------------------
# provider down — the connection never completes
# ---------------------------------------------------------------------------


async def test_provider_down_is_a_provider_error_not_a_crash(install) -> None:
    """A refused connection must not escape as a bare httpx exception.

    `run_pipeline` catches `ProviderError`. An httpx `ConnectError` reaching it
    unwrapped is an unhandled exception in a graph node, which is I1's failure
    mode: the node's trace entry never gets written.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client, _ = groq_client(install, handler)
    with pytest.raises(ProviderError) as caught:
        await client.complete("system", "user")

    assert not isinstance(caught.value, ProviderTimeout), (
        "a refused connection is not a timeout; conflating them tells an "
        "operator to raise a timeout that was never the problem"
    )
    assert caught.value.provider == "groq"
    assert caught.value.key_id == "groq-dev"
    assert "ConnectError" in str(caught.value)


async def test_provider_down_mid_response_is_still_a_provider_error(install) -> None:
    """A read error after the request went out is the same category."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadError("peer reset the connection", request=request)

    client, _ = gemini_client(install, handler)
    with pytest.raises(ProviderError) as caught:
        await client.complete("system", "user")
    assert "ReadError" in str(caught.value)


async def test_a_5xx_is_an_http_error_carrying_the_real_status(install) -> None:
    """D36 routes on 5xx vs 4xx, so the status has to survive the exception."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="the model is overloaded")

    client, _ = gemini_client(install, handler)
    with pytest.raises(ProviderHTTPError) as caught:
        await client.complete("system", "user")

    assert caught.value.status_code == 503
    assert "HTTP 503" in str(caught.value), (
        "the eval recovers the category by matching `HTTP {code}` out of the "
        "trace note, so the formatting is load-bearing"
    )
    assert "overloaded" in str(caught.value)


# ---------------------------------------------------------------------------
# 429 — cools, never dies
# ---------------------------------------------------------------------------


async def test_a_429_raises_rate_limited_and_does_not_kill_the_key(install) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"retry-after": "17"})

    client, key_pool = groq_client(install, handler)
    with pytest.raises(RateLimited) as caught:
        await client.complete("system", "user")

    assert caught.value.retry_after_seconds == 17.0
    key_pool.mark_rate_limited("groq-dev", caught.value.retry_after_seconds)

    snapshot = key_pool.snapshot()[0]
    assert snapshot["cooling"] is True
    assert snapshot["dead"] is False, "a rate limit is temporary — PLAN D39"
    assert key_pool.live == 1


async def test_a_429_on_every_key_is_an_honest_503_not_a_fabricated_answer(
    install,
) -> None:
    """PLAN §10.3 — all keys cooling raises. It never degrades to template text."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return httpx.Response(429)

    client, key_pool = groq_client(
        install, handler, keys={"dev": "k1", "reserved": "k2", "spare": "k3"}
    )

    with pytest.raises(AllKeysCoolingError):
        await call_with_rotation(key_pool, lambda: client.complete("s", "u"))

    assert len(seen) == 3, "one attempt per key, and no key retried"
    assert len(set(seen)) == 3, "three DIFFERENT keys, not the same one three times"
    assert key_pool.live == 3, "cooling is not death"


# ---------------------------------------------------------------------------
# dead key — PLAN D39 / adjudication 0.3
# ---------------------------------------------------------------------------


def test_the_revocation_classifier_is_narrow_on_purpose() -> None:
    """A false positive here removes a WORKING key until restart."""
    assert key_revocation_reason(403, "project has been denied access") is not None
    assert key_revocation_reason(401, "unauthenticated") is not None
    assert key_revocation_reason(400, "API_KEY_INVALID") is not None

    # A bare 400 is an ordinary malformed request, and killing a key over one
    # would take a healthy credential out of rotation for a bug in our payload.
    assert key_revocation_reason(400, "missing required field 'contents'") is None
    # A 429 is temporary and belongs to the cooling path.
    assert key_revocation_reason(429, "rate limit exceeded") is None
    assert key_revocation_reason(503, "the model is overloaded") is None
    assert key_revocation_reason(500, "internal") is None


async def test_a_403_project_denied_raises_key_revoked_not_rate_limited(
    install,
) -> None:
    """The real observed failure: one Gemini key answers 403 forever."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "error": {
                    "code": 403,
                    "status": "PERMISSION_DENIED",
                    "message": "Requests to this API method are blocked: the "
                    "project has been denied access.",
                }
            },
        )

    client, _ = gemini_client(install, handler)
    with pytest.raises(KeyRevoked) as caught:
        await client.complete("system", "user")

    assert not isinstance(caught.value, RateLimited), (
        "PLAN D39 — a 403 project-denied is a permanent statement about the "
        "credential and must not be routed through the cooling path"
    )
    assert caught.value.status_code == 403
    assert caught.value.key_id == "gemini-dev"
    assert "denied" in caught.value.reason.lower()


async def test_a_403_removes_the_key_permanently_and_a_429_only_cools_it(
    install,
) -> None:
    """The distinction the adjudication asks for, asserted side by side."""
    responses: dict[str, httpx.Response] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        return responses[request.headers["x-goog-api-key"]]

    client, key_pool = gemini_client(
        install, handler, keys={"dev": "k1", "reserved": "k2", "spare": "k3"}
    )
    responses["k1"] = httpx.Response(403, text="the project has been denied access")
    responses["k2"] = httpx.Response(429, headers={"retry-after": "30"})
    responses["k3"] = httpx.Response(
        200,
        json={
            "candidates": [{"content": {"parts": [{"text": '{"ok": true}'}]}}],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 2},
        },
    )

    result = await call_with_rotation(key_pool, lambda: client.complete("s", "u"))
    assert result.key_id == "gemini-spare", "rotation walked past both bad keys"

    by_id = {row["key_id"]: row for row in key_pool.snapshot()}
    assert by_id["gemini-dev"]["dead"] is True
    assert by_id["gemini-dev"]["cooling"] is False, (
        "a dead key reports cooling=false — it is not waiting for a window"
    )
    assert by_id["gemini-dev"]["dead_reason"]
    assert by_id["gemini-reserved"]["dead"] is False
    assert by_id["gemini-reserved"]["cooling"] is True
    assert key_pool.live == 2


async def test_a_dead_key_is_never_retried_no_matter_how_long_you_wait(
    install,
) -> None:
    """Retrying a revoked key every cooldown spends a request to learn nothing."""
    attempts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.headers["authorization"])
        return httpx.Response(403, text="invalid_api_key")

    client, key_pool = groq_client(install, handler, keys={"dev": "k1", "reserved": "k2"})

    with pytest.raises(AllKeysDeadError):
        await call_with_rotation(key_pool, lambda: client.complete("s", "u"))
    assert len(attempts) == 2

    # A second call, with the cooldown long since irrelevant, must not reach the
    # provider at all: `acquire` has no live key to hand out.
    before = len(attempts)
    with pytest.raises(AllKeysDeadError):
        await call_with_rotation(key_pool, lambda: client.complete("s", "u"))
    assert len(attempts) == before, "a dead pool costs zero further requests"


async def test_an_all_dead_pool_says_dead_not_cooling(install) -> None:
    """The operator's remedy differs, so the error type has to differ."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthenticated")

    client, key_pool = groq_client(install, handler, keys={"dev": "k1"})

    with pytest.raises(AllKeysDeadError) as caught:
        await call_with_rotation(key_pool, lambda: client.complete("s", "u"))

    assert not isinstance(caught.value, AllKeysCoolingError)
    assert "provision a replacement key" in str(caught.value)
    assert "groq-dev" in caught.value.reasons


def test_marking_a_key_dead_twice_logs_once() -> None:
    """A line repeated on every cooldown is a line nobody reads.

    A handler is attached directly rather than using `caplog`: the app installs
    its own root handler and sets a level, so the fixture's capture depends on
    whichever test configured logging last. Attaching here makes the assertion
    about this logger and nothing else.
    """
    import logging

    key_pool = KeyPool("groq", {"dev": "k1"}, default_cooldown_seconds=60.0)
    captured: list[logging.LogRecord] = []

    class _Sink(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    logger = logging.getLogger("flare.providers")
    sink = _Sink(level=logging.ERROR)
    logger.addHandler(sink)
    previous = logger.level
    logger.setLevel(logging.ERROR)
    try:
        key_pool.mark_dead("groq-dev", "403 forbidden")
        key_pool.mark_dead("groq-dev", "403 forbidden")
    finally:
        logger.removeHandler(sink)
        logger.setLevel(previous)

    records = [r for r in captured if "permanently rejected" in r.getMessage()]
    assert len(records) == 1, "the second mark_dead is a no-op, including its log"
    assert records[0].levelno == logging.ERROR, "startup-visible, not debug"
    assert records[0].key_id == "groq-dev"  # type: ignore[attr-defined]
    assert records[0].reason == "403 forbidden"  # type: ignore[attr-defined]
    assert "k1" not in str(records[0].__dict__), (
        "PLAN I16 — key material never reaches a log record, in any field"
    )


# ---------------------------------------------------------------------------
# timeout
# ---------------------------------------------------------------------------


async def test_a_timeout_is_its_own_category_and_names_the_budget(install) -> None:
    """PLAN I7/D30 — the message has to tell an operator which knob to turn."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client, _ = gemini_client(install, handler)
    with pytest.raises(ProviderTimeout) as caught:
        await client.complete("system", "user")

    message = str(caught.value)
    assert "5.0s" in message
    assert "thinkingLevel" in message, (
        "PLAN D30 — the timeout and the thinking level move together, so the "
        "error names both rather than only the one that expired"
    )


async def test_a_timeout_does_not_burn_the_rest_of_the_pool(install) -> None:
    """Rotating on a timeout spends every key on whatever is actually broken."""
    attempts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.headers["authorization"])
        raise httpx.ReadTimeout("timed out", request=request)

    client, key_pool = groq_client(
        install, handler, keys={"dev": "k1", "reserved": "k2", "spare": "k3"}
    )

    with pytest.raises(ProviderTimeout):
        await call_with_rotation(key_pool, lambda: client.complete("s", "u"))

    assert len(attempts) == 1, "one attempt — a timeout is not a rotation signal"
    assert key_pool.live == 3


# ---------------------------------------------------------------------------
# malformed model output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "why"),
    [
        ("this is not json at all", "prose instead of an object"),
        ('{"attack_type": "dos"', "truncated — the stream was cut"),
        ("[1, 2, 3]", "valid JSON of the wrong type"),
        ('{"severity": "high"}', "parses, but the required field is missing"),
        ("null", "valid JSON, not an object"),
    ],
)
async def test_malformed_model_output_is_a_failed_call(
    install, content: str, why: str
) -> None:
    """PLAN I18 — none of these may become a silent default."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=chat_body(content))

    from app.providers.base import parse_json_content

    client, _ = groq_client(install, handler)
    result = await client.complete("system", "user")

    with pytest.raises(EmptyContentError, match=r".+"):
        parse_json_content(
            "groq", result.model, result.content, required=("attack_type", "severity")
        )


async def test_a_wrong_enum_value_is_clamped_rather_than_rendered(install) -> None:
    """A model that invents a class must not put that class on a screen."""
    from app.ingestion.labels import CANONICAL_CLASSES
    from app.security.sanitize import clamp_enum

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=chat_body('{"attack_type": "cyber_attack", "severity": "URGENT"}'),
        )

    from app.providers.base import parse_json_content

    client, _ = groq_client(install, handler)
    result = await client.complete("system", "user")
    parsed = parse_json_content(
        "groq", result.model, result.content, required=("attack_type", "severity")
    )

    assert parsed["attack_type"] == "cyber_attack", "the raw value did arrive"
    assert clamp_enum(parsed["attack_type"], CANONICAL_CLASSES, "unknown") == "unknown"


# ---------------------------------------------------------------------------
# I18 — a 200 carrying nothing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("content", ["", "   ", "\n\t  \n"])
async def test_i18_a_200_with_empty_content_is_a_failure(
    install, content: str
) -> None:
    """PLAN I18/D29. This one has actually happened on GPT OSS."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=chat_body(content))

    client, _ = groq_client(install, handler)
    with pytest.raises(EmptyContentError) as caught:
        await client.complete("system", "user")
    assert "200" in str(caught.value)


async def test_i18_gemini_max_tokens_with_no_text_is_a_failure(install) -> None:
    """The thinking budget ate the output allowance. Still a failed call."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "candidates": [{"content": {"parts": []}, "finishReason": "MAX_TOKENS"}],
                "usageMetadata": {"promptTokenCount": 20, "thoughtsTokenCount": 900},
            },
        )

    client, _ = gemini_client(install, handler)
    with pytest.raises(EmptyContentError) as caught:
        await client.complete("system", "user")
    assert "MAX_TOKENS" in str(caught.value)


async def test_i18_does_not_rotate_the_pool(install) -> None:
    """The provider answered; it answered badly. That is not an availability
    problem, and spending a second key to reproduce it would be a category
    error (PLAN D36)."""

    attempts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.headers["authorization"])
        return httpx.Response(200, json=chat_body("   "))

    client, key_pool = groq_client(
        install, handler, keys={"dev": "k1", "reserved": "k2"}
    )

    with pytest.raises(EmptyContentError):
        await call_with_rotation(key_pool, lambda: client.complete("s", "u"))

    assert len(attempts) == 1
    assert key_pool.live == 2
