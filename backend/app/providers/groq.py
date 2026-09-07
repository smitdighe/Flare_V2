"""Groq client. PLAN D28 / D29 / D31 / I7 / I18 / T1.

Model IDs verified live against this project's own key (D31), not read off a
docs page:
    openai/gpt-oss-120b   primary
    qwen/qwen3.8-27b      fallback, deliberately a different model family so a
                          provider-side problem with one is unlikely to hit both

D29 / I18: GPT OSS is a reasoning model. `reasoning_format="hidden"` is set
EXPLICITLY so the final answer lands in `message.content` instead of a sibling
channel. The default happens to populate `content` today, but it also emits a
`reasoning` key, which means the placement is the provider's choice and not
ours. An empty `content` raises EmptyContentError and is recorded as a FAILED
call — a 200 is not a success.

T1: THE CLIENT IS CONSTRUCTED INSIDE THE TRY. A constructor that raises outside
its try kills the response mid-body on a missing key, which reads to the user as
the server dying rather than as a configuration error.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from app.providers.base import (
    EmptyContentError,
    KeyRevoked,
    LLMResult,
    ProviderError,
    ProviderHTTPError,
    ProviderTimeout,
    RateLimited,
    key_revocation_reason,
    retry_after_seconds,
)
from app.providers.keypool import KeyPool

CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"
PROVIDER = "groq"


class GroqClient:
    def __init__(
        self,
        pool: KeyPool,
        *,
        model: str,
        timeout_seconds: float,
        reasoning_format: str,
        reasoning_effort: str,
    ) -> None:
        self._pool = pool
        self.model = model
        self._timeout = timeout_seconds
        self._reasoning_format = reasoning_format
        self._reasoning_effort = reasoning_effort

    async def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 700,
        model: str | None = None,
    ) -> LLMResult:
        """One call, one key, one timeout.

        A 429 does NOT retry here — it propagates as RateLimited so the registry
        cools that key and issues a FRESH call on the next one (PLAN §10.3).
        Retrying inside this method would retry on the cooling key.
        """
        lease = self._pool.acquire()
        chosen = model or self.model
        started = time.perf_counter()

        try:
            # T1 — inside the try. A missing key, a bad base URL or a proxy
            # misconfiguration raises here and becomes a ProviderError, not a
            # half-written response body.
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    CHAT_URL,
                    headers={
                        "Authorization": f"Bearer {lease.secret}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": chosen,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "temperature": 0,
                        "max_completion_tokens": max_tokens,
                        "response_format": {"type": "json_object"},
                        "reasoning_format": self._reasoning_format,
                        "reasoning_effort": self._reasoning_effort,
                    },
                )
        except httpx.TimeoutException as exc:
            raise ProviderTimeout(
                PROVIDER, f"{chosen} exceeded {self._timeout}s", lease.key_id
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(PROVIDER, f"{type(exc).__name__}: {exc}", lease.key_id) from exc

        duration_ms = (time.perf_counter() - started) * 1000

        if response.status_code == 429:
            raise RateLimited(
                PROVIDER, lease.key_id, retry_after_seconds(response.headers)
            )
        if response.status_code != 200:
            # PLAN D39 — a HARD auth rejection is a permanent fact about this
            # key, not a transient failure. It leaves rotation for the process
            # lifetime instead of being cooled and retried every cooldown.
            revoked = key_revocation_reason(response.status_code, response.text)
            if revoked is not None:
                raise KeyRevoked(
                    PROVIDER,
                    lease.key_id,
                    response.status_code,
                    response.text,
                    revoked,
                )
            raise ProviderHTTPError(
                PROVIDER, response.status_code, response.text, lease.key_id
            )

        body: dict[str, Any] = response.json()
        choices = body.get("choices") or []
        if not choices:
            raise EmptyContentError(
                PROVIDER, f"{chosen} returned 200 with no choices (PLAN I18)", lease.key_id
            )

        message = choices[0].get("message") or {}
        content = (message.get("content") or "").strip()
        if not content:
            # PLAN D29 verbatim: this HAS happened, and treating it as a success
            # produces a silent `unknown` that reads as a real verdict.
            raise EmptyContentError(
                PROVIDER,
                f"{chosen} returned HTTP 200 with empty message.content. Reasoning "
                f"output may have routed to a separate channel despite "
                f"reasoning_format={self._reasoning_format!r}. A 200 is not a "
                "success (PLAN I18/D29).",
                lease.key_id,
            )

        usage = body.get("usage") or {}
        return LLMResult(
            provider=PROVIDER,
            model=chosen,
            key_id=lease.key_id,
            content=content,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            duration_ms=duration_ms,
        )
