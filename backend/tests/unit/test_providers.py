"""Providers: I18, key rotation, timeouts, and key-material discipline.

PLAN I7 / I16 / I18 / D26 / D29 / §10.3.

Every provider call here is intercepted with an httpx MockTransport, so the
suite is hermetic: no key is real, no request leaves the machine, and the tests
assert on the request the client BUILT rather than on a live provider's mood.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from app.providers.base import (
    EmptyContentError,
    ProviderError,
    ProviderHTTPError,
    ProviderTimeout,
    parse_json_content,
)
from app.providers.gemini import GeminiClient
from app.providers.groq import GroqClient
from app.providers.keypool import AllKeysCoolingError, EmptyPoolError, KeyPool
from app.providers.registry import call_with_rotation


def pool(**secrets: str | None) -> KeyPool:
    return KeyPool(
        "groq",
        {purpose: secrets.get(purpose) for purpose in ("dev", "reserved", "spare")},
        default_cooldown_seconds=60.0,
    )


@pytest.fixture(autouse=True)
def _mock_transport(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    """Route every provider request through a MockTransport, then restore.

    Only `AsyncClient` is swapped, and only for the duration of one test —
    `monkeypatch` puts the real class back, so nothing here can leak a stale
    handler into another module's tests. The CONSTRUCTOR still runs inside the
    client's try block, which is the T1 property under test.
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


def groq_with(
    install, handler, keys: dict[str, str | None] | None = None
) -> tuple[GroqClient, KeyPool]:
    install(handler)
    key_pool = KeyPool(
        "groq", keys or {"dev": "k-dev"}, default_cooldown_seconds=60.0
    )
    client = GroqClient(
        key_pool,
        model="openai/gpt-oss-120b",
        timeout_seconds=5.0,
        reasoning_format="hidden",
        reasoning_effort="low",
    )
    return client, key_pool


def gemini_with(install, handler) -> tuple[GeminiClient, KeyPool]:
    install(handler)
    key_pool = KeyPool("gemini", {"dev": "k-dev"}, default_cooldown_seconds=60.0)
    client = GeminiClient(
        key_pool, model="gemini-3.6-flash", timeout_seconds=5.0, thinking_level="low"
    )
    return client, key_pool


# ---------------------------------------------------------------------------
# I18 — a 200 is not a success
# ---------------------------------------------------------------------------


async def test_groq_empty_content_is_a_failure(install) -> None:
    """PLAN D29 — GPT OSS has returned 200 with empty content. Not a success."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": ""}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 0},
            },
        )

    client, _ = groq_with(install, handler)
    with pytest.raises(EmptyContentError) as excinfo:
        await client.complete("sys", "user")
    assert "empty message.content" in str(excinfo.value)


async def test_groq_whitespace_only_content_is_a_failure(install) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "   \n\t  "}}], "usage": {}}
        )

    client, _ = groq_with(install, handler)
    with pytest.raises(EmptyContentError):
        await client.complete("sys", "user")


async def test_gemini_no_parts_is_a_failure(install) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "candidates": [{"content": {"parts": []}, "finishReason": "MAX_TOKENS"}],
                "usageMetadata": {"promptTokenCount": 12},
            },
        )

    client, _ = gemini_with(install, handler)
    with pytest.raises(EmptyContentError) as excinfo:
        await client.complete("sys", "user")
    assert "MAX_TOKENS" in str(excinfo.value)


async def test_gemini_no_candidates_is_a_failure(install) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"promptFeedback": {"blockReason": "SAFETY"}, "candidates": []}
        )

    client, _ = gemini_with(install, handler)
    with pytest.raises(EmptyContentError) as excinfo:
        await client.complete("sys", "user")
    assert "SAFETY" in str(excinfo.value)


def test_unparseable_json_is_a_failure() -> None:
    with pytest.raises(EmptyContentError) as excinfo:
        parse_json_content("groq", "m", "I think this flow is a port scan.")
    assert "not JSON" in str(excinfo.value)


def test_missing_required_field_is_a_failure() -> None:
    with pytest.raises(EmptyContentError) as excinfo:
        parse_json_content(
            "gemini", "m", '{"severity": "high"}', required=("attack_type", "severity")
        )
    assert "attack_type" in str(excinfo.value)


def test_json_in_a_markdown_fence_still_parses() -> None:
    parsed = parse_json_content("groq", "m", '```json\n{"attack_type": "dos"}\n```')
    assert parsed == {"attack_type": "dos"}


def test_a_json_array_is_a_failure() -> None:
    with pytest.raises(EmptyContentError):
        parse_json_content("groq", "m", "[1, 2, 3]")


# ---------------------------------------------------------------------------
# I7 — a timeout on every call
# ---------------------------------------------------------------------------


async def test_groq_timeout_raises_provider_timeout(install) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    client, _ = groq_with(install, handler)
    with pytest.raises(ProviderTimeout) as excinfo:
        await client.complete("sys", "user")
    assert "5.0s" in str(excinfo.value)


async def test_gemini_timeout_names_the_thinking_level(install) -> None:
    """PLAN D30 — the timeout and the thinking level move together, so the
    error says which pair blew up rather than leaving it to be guessed."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    client, _ = gemini_with(install, handler)
    with pytest.raises(ProviderTimeout) as excinfo:
        await client.complete("sys", "user")
    message = str(excinfo.value)
    assert "'low'" in message and "D30" in message


async def test_transport_error_becomes_a_provider_error_not_a_crash(install) -> None:
    """PLAN T1 — the client is constructed inside the try, so a connection
    failure is a ProviderError rather than a response that dies mid-body."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host", request=request)

    client, _ = groq_with(install, handler)
    with pytest.raises(ProviderError):
        await client.complete("sys", "user")


# ---------------------------------------------------------------------------
# D26 / §10.3 — key rotation
# ---------------------------------------------------------------------------


def test_selection_is_sticky_not_round_robin() -> None:
    """Round-robin burns three quotas in parallel and buys nothing."""
    p = pool(dev="a", reserved="b", spare="c")
    assert [p.acquire().key_id for _ in range(5)] == ["groq-dev"] * 5


def test_a_429_advances_to_the_next_key() -> None:
    p = pool(dev="a", reserved="b", spare="c")
    assert p.acquire().key_id == "groq-dev"
    p.mark_rate_limited("groq-dev")
    assert p.acquire().key_id == "groq-reserved"
    p.mark_rate_limited("groq-reserved")
    assert p.acquire().key_id == "groq-spare"


def test_all_keys_cooling_raises_rather_than_degrading() -> None:
    """PLAN §10.3 — an honest 503, never a silent fall back to template text."""
    p = pool(dev="a", reserved="b")
    for key_id in ("groq-dev", "groq-reserved"):
        p.mark_rate_limited(key_id, retry_after_seconds=30)
    with pytest.raises(AllKeysCoolingError) as excinfo:
        p.acquire()
    assert excinfo.value.retry_after_seconds > 0


def test_retry_after_is_honoured_when_the_provider_sends_one() -> None:
    p = pool(dev="a")
    p.mark_rate_limited("groq-dev", retry_after_seconds=120)
    snapshot = p.snapshot()[0]
    assert snapshot["cooling"] is True
    assert 119 <= float(snapshot["cooling_for_seconds"]) <= 120


def test_an_empty_pool_fails_closed() -> None:
    with pytest.raises(EmptyPoolError):
        pool().require_configured()


async def test_rotation_issues_a_fresh_call_and_never_retries_the_cooling_key(install) -> None:
    """PLAN §10.3, the whole rule in one test.

    The first key 429s. The pool cools it, advances, and a NEW request goes out
    on the NEXT key. The cooling key must not be seen again.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        token = request.headers["Authorization"].removeprefix("Bearer ")
        seen.append(token)
        if token == "k-dev":
            return httpx.Response(429, headers={"Retry-After": "45"})
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"ok": true}'}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3},
            },
        )

    client, key_pool = groq_with(
        install,
        handler, {"dev": "k-dev", "reserved": "k-reserved", "spare": "k-spare"}
    )
    result = await call_with_rotation(
        key_pool, lambda: client.complete("sys", "user")
    )

    assert seen == ["k-dev", "k-reserved"], "the cooling key must not be retried"
    assert result.key_id == "groq-reserved"
    assert key_pool.snapshot()[0]["cooling"] is True
    assert 44 <= float(key_pool.snapshot()[0]["cooling_for_seconds"]) <= 45


async def test_rotation_exhausts_and_returns_all_keys_cooling(install) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    client, key_pool = groq_with(install, handler, {"dev": "a", "reserved": "b", "spare": "c"})
    with pytest.raises(AllKeysCoolingError):
        await call_with_rotation(key_pool, lambda: client.complete("sys", "user"))
    assert all(row["cooling"] for row in key_pool.snapshot())


async def test_rotation_does_not_burn_keys_on_a_non_429(install) -> None:
    """A 500 is broken, not rate limited. Rotating would spend every key on it."""
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500, text="upstream exploded")

    client, key_pool = groq_with(install, handler, {"dev": "a", "reserved": "b", "spare": "c"})
    with pytest.raises(ProviderHTTPError):
        await call_with_rotation(key_pool, lambda: client.complete("sys", "user"))
    assert calls == 1
    assert not any(row["cooling"] for row in key_pool.snapshot())


# ---------------------------------------------------------------------------
# I16 — labels, never material
# ---------------------------------------------------------------------------


def test_a_lease_never_reprs_its_secret() -> None:
    lease = pool(dev="super-secret-value").acquire()
    assert "super-secret-value" not in repr(lease)
    assert lease.key_id == "groq-dev"


def test_a_pool_snapshot_carries_no_key_material() -> None:
    rendered = repr(pool(dev="super-secret-value").snapshot())
    assert "super-secret-value" not in rendered


async def test_a_successful_result_carries_a_label_not_a_key(install) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"ok": true}'}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 2},
            },
        )

    client, _ = groq_with(install, handler, {"dev": "super-secret-value"})
    result = await client.complete("sys", "user")
    assert result.key_id == "groq-dev"
    assert "super-secret-value" not in repr(result)


# ---------------------------------------------------------------------------
# D29 / D31 — the settings that make the answer land in `content`
# ---------------------------------------------------------------------------


async def test_groq_sets_reasoning_format_explicitly(install) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"ok": true}'}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    client, _ = groq_with(install, handler)
    await client.complete("sys", "user")
    assert captured["reasoning_format"] == "hidden"
    assert captured["reasoning_effort"] == "low"
    assert captured["model"] == "openai/gpt-oss-120b"


async def test_gemini_sets_the_thinking_level_explicitly(install) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "candidates": [{"content": {"parts": [{"text": '{"ok": true}'}]}}],
                "usageMetadata": {
                    "promptTokenCount": 5,
                    "candidatesTokenCount": 3,
                    "thoughtsTokenCount": 11,
                },
            },
        )

    client, _ = gemini_with(install, handler)
    result = await client.complete("sys", "user")
    config = captured["generationConfig"]
    assert config["thinkingConfig"] == {"thinkingLevel": "low"}  # type: ignore[index]
    # Thought tokens are billed and are not inside candidatesTokenCount, so
    # excluding them would under-report what the call cost (PLAN §11).
    assert result.completion_tokens == 14


async def test_tokens_come_from_real_usage_fields(install) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "{}"}}],
                "usage": {"prompt_tokens": 186, "completion_tokens": 66},
            },
        )

    client, _ = groq_with(install, handler)
    result = await client.complete("sys", "user")
    assert (result.prompt_tokens, result.completion_tokens) == (186, 66)
