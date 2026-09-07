"""Shared provider contract. PLAN §11 / I7 / I18 / D29.

THE CENTRAL RULE HERE IS I18: A 200 IS NOT A SUCCESS.

Every provider in this package converts a structurally-OK-but-useless response
into an EmptyContentError, which is a FAILURE — a `failed` trace entry, counted
in the denominator, rendered as `unknown`. The three shapes that qualify:

  * empty or whitespace-only content (D29 — GPT OSS has done exactly this when
    reasoning routed to a separate channel);
  * content that does not parse as JSON;
  * JSON that parses but is missing a field the caller declared required.

The prior codebase's success metric counted any non-null severity plus a
non-null latency, so a failure was undetectable by construction. Here the
failure has its own exception type and its own trace status.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


class ProviderError(RuntimeError):
    """Base for every provider failure. Carries the label of the serving key."""

    def __init__(self, provider: str, message: str, key_id: str | None = None) -> None:
        super().__init__(message)
        self.provider = provider
        self.key_id = key_id


class ProviderTimeout(ProviderError):
    """PLAN I7 — no LLM or HTTP call without a timeout."""


class ProviderHTTPError(ProviderError):
    def __init__(
        self, provider: str, status_code: int, body: str, key_id: str | None = None
    ) -> None:
        super().__init__(provider, f"HTTP {status_code}: {body[:200]}", key_id)
        self.status_code = status_code


class RateLimited(ProviderError):
    """A 429. The pool cools this key and the caller retries on the NEXT one."""

    def __init__(
        self, provider: str, key_id: str, retry_after_seconds: float | None
    ) -> None:
        super().__init__(provider, f"{key_id} is rate limited", key_id)
        self.retry_after_seconds = retry_after_seconds


class KeyRevoked(ProviderError):
    """PLAN D39 — a HARD auth rejection. This key is dead, not cooling.

    A 403 `project has been denied access` is a permanent statement about the
    credential: the project is gone, the key is revoked, billing is suspended.
    Cooling it and retrying every cooldown spends a request to be told the same
    thing again, and — worse — reports the pool as temporarily degraded when one
    of its keys is permanently unusable. The pool removes it for the process
    lifetime and `/health/deep` shows it as `dead`.
    """

    def __init__(
        self, provider: str, key_id: str, status_code: int, body: str, reason: str
    ) -> None:
        super().__init__(provider, f"HTTP {status_code}: {body[:200]}", key_id)
        self.status_code = status_code
        # The short human-readable classification, carried so the pool can log
        # WHY a key left rotation rather than just that it did.
        self.reason = reason


class EmptyContentError(ProviderError):
    """PLAN I18 / D29 — a 200 that carries nothing usable is a FAILED call."""


@dataclass(frozen=True)
class LLMResult:
    """One completed provider call.

    `prompt_tokens` / `completion_tokens` come from the SDK's real usage fields,
    never estimated from string length. PLAN §11.
    """

    provider: str
    model: str
    key_id: str
    content: str
    prompt_tokens: int
    completion_tokens: int
    duration_ms: float
    data: dict[str, Any] = field(default_factory=dict)


_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def parse_json_content(
    provider: str, model: str, content: str, required: tuple[str, ...] = ()
) -> dict[str, Any]:
    """Content -> dict, or a FAILURE. PLAN I18.

    Every branch below raises rather than returning a default. A default here is
    the exact failure mode this project exists to eliminate: an `unknown` that
    looks like a verdict.
    """
    text = content.strip()
    if not text:
        raise EmptyContentError(
            provider,
            f"{model} returned HTTP 200 with empty content. A 200 is not a "
            "success (PLAN I18/D29) — this is counted as a failed call.",
        )

    # Some models wrap JSON in a markdown fence even under a JSON response
    # format. Stripping it is parsing, not repairing: nothing is invented.
    text = _FENCE.sub("", text).strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EmptyContentError(
            provider,
            f"{model} returned content that is not JSON ({exc}); the first 120 "
            f"characters were {text[:120]!r}",
        ) from exc

    if not isinstance(parsed, dict):
        raise EmptyContentError(
            provider, f"{model} returned JSON of type {type(parsed).__name__}, expected an object"
        )

    missing = [key for key in required if key not in parsed]
    if missing:
        raise EmptyContentError(
            provider,
            f"{model} returned JSON missing required field(s) {missing}. A "
            "structurally-OK response with a missing field is a failed call "
            "(PLAN I18).",
        )
    return parsed


# Body markers that make a status code that is otherwise ambiguous into an
# unambiguous statement about the credential. Google returns 400
# INVALID_ARGUMENT for a revoked key as well as for a malformed request, so the
# status alone cannot be trusted at 400 — the body can.
_REVOKED_BODY_MARKERS: tuple[str, ...] = (
    "api_key_invalid",
    "api key not valid",
    "api key expired",
    "invalid_api_key",
    "project has been denied",
    "consumer_suspended",
    "permission_denied",
    "account_deactivated",
)


def key_revocation_reason(status_code: int, body: str) -> str | None:
    """Is this response a PERMANENT statement about the key? PLAN D39.

    Returns a short reason when it is, `None` when it is not. Deliberately
    narrow, because the cost of a false positive is a working key removed from
    rotation for the process lifetime:

      * **401** — the request was not authenticated. On a key-authenticated API
        that is a statement about the key and nothing else.
      * **403** — the caller is authenticated and not permitted. For an API key
        this is the revoked / denied / suspended case.
      * **400 with an explicit key marker in the body** — Google's
        `API_KEY_INVALID` arrives as a 400, and a bare 400 is an ordinary
        malformed request, so only the marked ones qualify.

    A 429 is NOT here and must be checked first: a rate limit is temporary and
    the pool cools it.
    """
    lowered = (body or "").lower()
    if status_code == 401:
        return "401 unauthenticated: the provider did not accept this key"
    if status_code == 403:
        for marker in _REVOKED_BODY_MARKERS:
            if marker in lowered:
                return f"403 {marker}"
        return "403 forbidden: the provider refused this key's project"
    if status_code == 400 and any(m in lowered for m in _REVOKED_BODY_MARKERS):
        return "400 with an explicit invalid-key marker in the body"
    return None


def retry_after_seconds(headers: Any) -> float | None:
    """Parse `Retry-After`. Providers send it as whole seconds here."""
    raw = None
    try:
        raw = headers.get("retry-after") or headers.get("Retry-After")
    except AttributeError:
        return None
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None
