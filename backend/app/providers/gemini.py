"""Gemini client. PLAN D30 / D31 / I7 / I18 / T1 / T3.

Model ID verified by a live `generateContent` call, not by reading the models
listing (D31). That distinction is the whole of T3 here: `gemini-2.5-flash` IS
returned by `GET /v1beta/models` and returns 404 when actually called —
"no longer available to new users … use models/gemini-3.6-flash". A listing
proves a name exists, not that a key can call it.

D30 — THINKING LEVEL AND TIMEOUT ARE ONE SETTING IN TWO FIELDS. Measured at
`thinkingLevel="low"`: 3.1-5.0s median with a 20.6s tail. The previous build's
12s ceiling would have failed roughly one call in eight. `config.py` enforces
the pairing so neither can be changed alone.
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

BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
PROVIDER = "gemini"


class GeminiClient:
    def __init__(
        self,
        pool: KeyPool,
        *,
        model: str,
        timeout_seconds: float,
        thinking_level: str,
    ) -> None:
        self._pool = pool
        self.model = model
        self._timeout = timeout_seconds
        self._thinking_level = thinking_level

    async def complete(
        self, system: str, user: str, *, max_tokens: int = 900
    ) -> LLMResult:
        lease = self._pool.acquire()
        started = time.perf_counter()

        try:
            # T1 — construction inside the try.
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{BASE_URL}/models/{self.model}:generateContent",
                    headers={
                        "x-goog-api-key": lease.secret,
                        "Content-Type": "application/json",
                    },
                    json={
                        "systemInstruction": {"parts": [{"text": system}]},
                        "contents": [{"role": "user", "parts": [{"text": user}]}],
                        "generationConfig": {
                            "temperature": 0,
                            "responseMimeType": "application/json",
                            "maxOutputTokens": max_tokens,
                            "thinkingConfig": {"thinkingLevel": self._thinking_level},
                        },
                    },
                )
        except httpx.TimeoutException as exc:
            raise ProviderTimeout(
                PROVIDER,
                f"{self.model} exceeded {self._timeout}s at thinkingLevel="
                f"{self._thinking_level!r} (PLAN D30: raise the timeout or lower "
                "the thinking level — they move together)",
                lease.key_id,
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
        candidates = body.get("candidates") or []
        if not candidates:
            # A prompt-feedback block with no candidate means the request was
            # filtered. That is a failed call with a reason, not an empty answer.
            feedback = body.get("promptFeedback") or {}
            raise EmptyContentError(
                PROVIDER,
                f"{self.model} returned 200 with no candidates; promptFeedback="
                f"{feedback} (PLAN I18)",
                lease.key_id,
            )

        candidate = candidates[0]
        parts = (candidate.get("content") or {}).get("parts") or []
        content = "".join(part.get("text", "") for part in parts).strip()
        if not content:
            finish = candidate.get("finishReason")
            raise EmptyContentError(
                PROVIDER,
                f"{self.model} returned HTTP 200 with no text parts "
                f"(finishReason={finish}). A 200 is not a success (PLAN I18). "
                "MAX_TOKENS here usually means the thinking budget consumed the "
                "output allowance.",
                lease.key_id,
            )

        usage = body.get("usageMetadata") or {}
        return LLMResult(
            provider=PROVIDER,
            model=self.model,
            key_id=lease.key_id,
            content=content,
            prompt_tokens=int(usage.get("promptTokenCount") or 0),
            # Thought tokens are billed and are NOT in candidatesTokenCount, so
            # excluding them would under-report what the call actually cost.
            completion_tokens=int(usage.get("candidatesTokenCount") or 0)
            + int(usage.get("thoughtsTokenCount") or 0),
            duration_ms=duration_ms,
        )
