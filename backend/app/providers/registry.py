"""Provider singleton and the rotation loop. PLAN D26 / §10.3 / I7 / I16.

`call_with_rotation` is where D26's rule actually lives:

    lease a key -> call -> on 429, cool THAT key, advance, issue a FRESH call
    with the NEXT key -> repeat at most once per key -> all cooling => 503.

"Fresh call" is literal. The failed request object is discarded; the retry is a
new request built from the same arguments. Retrying the same in-flight call on
a cooling key is what turns a rate limit into a retry storm.

Anything that is not a 429 does not rotate: a timeout, a 5xx, or an empty-content
failure is a FAILED call. Rotating on those would spend every key in the pool on
whatever is actually broken.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

from app.config import Settings, get_settings
from app.providers.base import KeyRevoked, LLMResult, RateLimited
from app.providers.gemini import GeminiClient
from app.providers.groq import GroqClient
from app.providers.keypool import AllKeysCoolingError, AllKeysDeadError, KeyPool
from app.providers.offline import OfflineProvider

logger = logging.getLogger("flare.providers")

T = TypeVar("T")


@dataclass
class ProviderRegistry:
    settings: Settings
    groq_pool: KeyPool
    gemini_pool: KeyPool
    groq: GroqClient
    gemini: GeminiClient
    offline: OfflineProvider

    @property
    def offline_mode(self) -> bool:
        return self.settings.offline_mode

    def snapshot(self) -> dict[str, object]:
        """Health view. Key LABELS only — never material (I16).

        PLAN D39 — `live_keys` and `dead_keys` are reported per provider so an
        operator reading `/health/deep` can tell a pool that is waiting out a
        rate limit from a pool that has lost a credential permanently. The two
        look identical if you only count keys, and they need opposite responses.

        `unprobed_keys` is the THIRD state and the one that has actually bitten:
        selection is sticky, so `/health/deep`'s single probe per provider only
        ever exercises the current key. A revoked `reserved` or `spare` key sits
        in `live_keys` reporting `dead=false` until something calls it — which,
        on demo day, is the first alert. Only `scripts.verify_keys` clears it.
        """
        return {
            "offline_mode": self.offline_mode,
            "groq": {
                "model": self.groq.model,
                "fallback_model": self.settings.groq_model_fallback,
                "keys": self.groq_pool.snapshot(),
                "live_keys": self.groq_pool.live,
                "dead_keys": self.groq_pool.dead_keys,
                # `live_keys` counts keys NOT KNOWN to be dead, which is not the
                # same as keys known to work. This names the difference.
                "unprobed_keys": self.groq_pool.unprobed_keys,
            },
            "gemini": {
                "model": self.gemini.model,
                "thinking_level": self.settings.gemini_thinking_level,
                "keys": self.gemini_pool.snapshot(),
                "live_keys": self.gemini_pool.live,
                "dead_keys": self.gemini_pool.dead_keys,
                "unprobed_keys": self.gemini_pool.unprobed_keys,
            },
        }


async def call_with_rotation(
    pool: KeyPool, make_call: Callable[[], Awaitable[LLMResult]]
) -> LLMResult:
    """Run `make_call`, advancing the pool on each 429.

    `make_call` acquires its own lease, so calling it again genuinely produces a
    NEW call on whatever key the pool now points at. At most one attempt per
    key: a pool that 429s on every key is exhausted, and looping would only
    delay the honest 503.

    **A revoked key (PLAN D39) advances the same way a 429 does and for the same
    reason — the next call should go somewhere else — but the key is marked DEAD
    rather than cooling, so it never comes back and never costs another request.
    A pool whose last live key is revoked raises `AllKeysDeadError`, which is a
    different operator instruction than `AllKeysCoolingError`: wait fixes one and
    only a new credential fixes the other.**
    """
    attempts = max(len(pool), 1)
    for attempt in range(attempts):
        try:
            return await make_call()
        except KeyRevoked as exc:
            # PLAN D39 — NOT a rate limit, and it must not be treated as one.
            # HTTP 403 "project has been denied access" is a permanent statement
            # about the credential: cooling it and retrying every cooldown spends
            # a request to be told the same thing again and reports a dead key as
            # temporarily degraded. It leaves rotation for the process lifetime
            # and the pool logs it once.
            assert exc.key_id is not None
            pool.mark_dead(exc.key_id, exc.reason)
            if pool.live == 0:
                raise AllKeysDeadError(pool.provider, pool.dead_keys) from exc
            # A key was removed, not rate limited, so the loop budget is spent
            # on live keys rather than on the one that just died.
            continue
        except RateLimited as exc:
            # RateLimited always carries the label of the key that 429'd; the
            # base class types it Optional because other provider errors can be
            # raised before a lease exists.
            assert exc.key_id is not None
            pool.mark_rate_limited(exc.key_id, exc.retry_after_seconds)
            logger.warning(
                "provider key rate limited",
                extra={
                    "request_id": "-",
                    "provider": pool.provider,
                    # I16 — the LABEL. Raw material never reaches a log line.
                    "key_id": exc.key_id,
                    "retry_after_seconds": exc.retry_after_seconds,
                    "attempt": attempt + 1,
                },
            )
            if attempt == attempts - 1:
                raise AllKeysCoolingError(
                    pool.provider, exc.retry_after_seconds or 0.0
                ) from exc
    raise AllKeysCoolingError(pool.provider, 0.0)


_registry: ProviderRegistry | None = None


def build_registry(settings: Settings | None = None) -> ProviderRegistry:
    settings = settings or get_settings()

    groq_pool = KeyPool(
        "groq",
        {
            "dev": settings.groq_api_key_dev,
            "reserved": settings.groq_api_key_reserved,
            "spare": settings.groq_api_key_spare,
        },
        default_cooldown_seconds=settings.key_cooldown_seconds,
    )
    gemini_pool = KeyPool(
        "gemini",
        {
            "dev": settings.gemini_api_key_dev,
            "reserved": settings.gemini_api_key_reserved,
            "spare": settings.gemini_api_key_spare,
        },
        default_cooldown_seconds=settings.key_cooldown_seconds,
    )

    # PLAN §10.3 — a provider enabled with an empty pool fails CLOSED, here, at
    # startup. Discovering it on the first alert means discovering it in front
    # of an audience. Offline mode is the declared way to run without keys.
    if not settings.offline_mode:
        groq_pool.require_configured()
        gemini_pool.require_configured()

    return ProviderRegistry(
        settings=settings,
        groq_pool=groq_pool,
        gemini_pool=gemini_pool,
        groq=GroqClient(
            groq_pool,
            model=settings.groq_model_primary,
            timeout_seconds=settings.llm_timeout_seconds_groq,
            reasoning_format=settings.groq_reasoning_format,
            reasoning_effort=settings.groq_reasoning_effort,
        ),
        gemini=GeminiClient(
            gemini_pool,
            model=settings.gemini_model,
            timeout_seconds=settings.llm_timeout_seconds_gemini,
            thinking_level=settings.gemini_thinking_level,
        ),
        offline=OfflineProvider(),
    )


def load_registry(settings: Settings | None = None) -> ProviderRegistry:
    global _registry
    _registry = build_registry(settings)
    return _registry


def get_registry() -> ProviderRegistry:
    global _registry
    if _registry is None:
        _registry = build_registry()
    return _registry


def set_registry(registry: ProviderRegistry) -> None:
    """Test seam, matching `set_rule_engine`. Production never calls this.

    Exists so a test can install a registry with real key LABELS without
    reaching into the module's globals — which is what the health-deep dead-key
    test was doing, and which breaks silently the day the global is renamed.
    """
    global _registry
    _registry = registry


def reset_registry() -> None:
    """Test seam. Production builds once in the lifespan."""
    global _registry
    _registry = None
