"""Sticky-until-exhausted key rotation. PLAN D26 / §10.3 / I16.

Free tiers are metered PER KEY, so N keys with declared purposes turn one hard
cap into N sequential windows. The selection rule is the whole point:

  STICKY, NOT ROUND-ROBIN. Round-robin spends all N quotas in parallel and
  arrives at the same wall at the same time — it buys nothing. Sticky uses one
  key until it 429s, then advances, so `reserved` still has a full daily window
  on demo day after `dev` has been burned to the ground in rehearsal.

On a 429 the failed call is NOT retried on the same key. That key is marked
cooling (from `Retry-After` when the provider sends one, else a configured
default), the pool advances, and the caller issues a FRESH call with the next
key. Retrying the cooling key is how a rate limit becomes a retry storm.

All keys cooling is an honest 503 `rate_limited`, never a silent degrade to
template text.

KEY MATERIAL NEVER LEAVES THIS MODULE IN ANY FORM A CALLER CAN LOG. `Lease`
carries the secret for the duration of one call and its `key_id` — the label,
`"groq-reserved"` — is the only form that may enter a trace, a log, a payload
or an error message (I16). `__repr__` is overridden on both classes because the
default would print the secret into any exception context that includes them.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger("flare.providers")

PURPOSES: tuple[str, ...] = ("dev", "reserved", "spare")


class EmptyPoolError(RuntimeError):
    """A provider was enabled with no keys. PLAN §10.3: fail closed at startup."""


class AllKeysDeadError(RuntimeError):
    """PLAN D39 — every key in the pool was permanently rejected.

    Distinct from `AllKeysCoolingError` because the remedy is different and an
    operator has to be able to tell them apart: cooling clears on its own, dead
    needs a human to provision a credential. Waiting for a dead pool is waiting
    for something that will not happen.
    """

    def __init__(self, provider: str, reasons: dict[str, str]) -> None:
        super().__init__(
            f"every {provider} key has been permanently removed from rotation: "
            + "; ".join(f"{key_id} ({reason})" for key_id, reason in reasons.items())
            + ". This does not clear on its own — provision a replacement key."
        )
        self.provider = provider
        self.reasons = dict(reasons)


class AllKeysCoolingError(RuntimeError):
    """Every key in the pool is rate-limited. Surfaces as 503 `rate_limited`."""

    def __init__(self, provider: str, retry_after_seconds: float) -> None:
        super().__init__(
            f"every {provider} key is cooling; next available in "
            f"{retry_after_seconds:.0f}s"
        )
        self.provider = provider
        self.retry_after_seconds = retry_after_seconds


@dataclass
class _Key:
    provider: str
    purpose: str
    secret: str
    cooling_until: float = 0.0
    calls: int = 0
    rate_limited: int = 0
    # PLAN D39 — permanent, for the lifetime of this process. A dead key is not
    # a cooling key: nothing it is waiting for will ever arrive.
    dead: bool = False
    dead_reason: str | None = None

    @property
    def key_id(self) -> str:
        return f"{self.provider}-{self.purpose}"

    def available(self, now: float) -> bool:
        return not self.dead and now >= self.cooling_until

    def __repr__(self) -> str:
        return (
            f"<_Key {self.key_id} dead={self.dead} "
            f"cooling_until={self.cooling_until:.0f}>"
        )


@dataclass(frozen=True)
class Lease:
    """One key, checked out for exactly one call.

    `secret` is passed straight to the HTTP client and never stored, formatted
    into a message, or attached to a trace. `key_id` is what the trace records.
    """

    key_id: str
    secret: str = field(repr=False)

    def __repr__(self) -> str:
        return f"<Lease {self.key_id}>"


class KeyPool:
    """N keys for one provider, consumed in declared order.

    Cooling state is in-memory and per-process, which matches the one-stream-
    loop-per-server design (T4). A second process would keep its own view; that
    is a known and accepted limit of running without shared state.
    """

    def __init__(
        self,
        provider: str,
        secrets: dict[str, str | None],
        *,
        default_cooldown_seconds: float,
    ) -> None:
        self.provider = provider
        self.default_cooldown_seconds = default_cooldown_seconds
        self._keys: list[_Key] = [
            _Key(provider=provider, purpose=purpose, secret=secret)
            for purpose in PURPOSES
            if (secret := secrets.get(purpose))
        ]
        self._cursor = 0

    def __len__(self) -> int:
        return len(self._keys)

    @property
    def configured(self) -> bool:
        return bool(self._keys)

    def require_configured(self) -> None:
        """PLAN §10.3 — a provider enabled with an empty pool fails closed."""
        if not self._keys:
            names = "/".join(
                f"{self.provider.upper()}_API_KEY_{purpose.upper()}"
                for purpose in PURPOSES
            )
            raise EmptyPoolError(
                f"{self.provider} is enabled but has no keys configured. Set at "
                f"least one of {names}, or disable the provider. A provider with "
                "an empty pool would fail on the first alert instead of at startup."
            )

    def acquire(self) -> Lease:
        """The current key if it is available, else the next one that is.

        Sticky: the cursor only advances when a key is cooling. A healthy key is
        used until it stops being healthy.
        """
        self.require_configured()
        now = time.monotonic()

        for offset in range(len(self._keys)):
            index = (self._cursor + offset) % len(self._keys)
            key = self._keys[index]
            if key.available(now):
                self._cursor = index
                key.calls += 1
                return Lease(key_id=key.key_id, secret=key.secret)

        # PLAN D39 — an all-dead pool must not report itself as cooling. The
        # caller's remedy for cooling is to wait; for dead it is to provision a
        # key, and telling an operator to wait for a revoked credential is the
        # exact confusion this state exists to remove.
        live = [k for k in self._keys if not k.dead]
        if not live:
            raise AllKeysDeadError(
                self.provider,
                {k.key_id: k.dead_reason or "revoked" for k in self._keys},
            )

        soonest = min(k.cooling_until for k in live) - now
        raise AllKeysCoolingError(self.provider, max(soonest, 0.0))

    def mark_rate_limited(
        self, key_id: str, retry_after_seconds: float | None = None
    ) -> None:
        """Cool this key and advance. The caller then issues a FRESH call.

        `retry_after_seconds` comes from the provider's `Retry-After` header
        when it sends one — honouring the provider's own number is both more
        accurate and more polite than a fixed guess.
        """
        for index, key in enumerate(self._keys):
            if key.key_id != key_id:
                continue
            cooldown = (
                retry_after_seconds
                if retry_after_seconds is not None and retry_after_seconds > 0
                else self.default_cooldown_seconds
            )
            key.cooling_until = time.monotonic() + cooldown
            key.rate_limited += 1
            self._cursor = (index + 1) % len(self._keys)
            return

    def mark_dead(self, key_id: str, reason: str) -> None:
        """Remove this key from rotation for the process lifetime. PLAN D39.

        Logged ONCE, at ERROR, on the transition — an operator needs to see this
        the way they would see a failure at startup, and a line repeated on
        every cooldown is a line nobody reads. Re-marking an already-dead key is
        a no-op so a second rejection cannot re-log it.
        """
        for index, key in enumerate(self._keys):
            if key.key_id != key_id:
                continue
            if key.dead:
                return
            key.dead = True
            key.dead_reason = reason
            logger.error(
                "provider key permanently rejected and removed from rotation",
                extra={
                    "request_id": "-",
                    "provider": self.provider,
                    # I16 — the LABEL. Raw material never reaches a log line.
                    "key_id": key.key_id,
                    "reason": reason,
                    "live_keys_remaining": sum(1 for k in self._keys if not k.dead),
                },
            )
            self._cursor = (index + 1) % len(self._keys)
            return

    @property
    def live(self) -> int:
        """Keys still in rotation. Zero means the pool needs a human."""
        return sum(1 for key in self._keys if not key.dead)

    @property
    def dead_keys(self) -> dict[str, str]:
        return {
            key.key_id: key.dead_reason or "revoked"
            for key in self._keys
            if key.dead
        }

    def snapshot(self) -> list[dict[str, object]]:
        """Health view. Labels and counters only — no secrets, ever (I16)."""
        now = time.monotonic()
        return [
            {
                "key_id": key.key_id,
                "purpose": key.purpose,
                # PLAN D39 — `dead` and `cooling` are separate facts and the
                # health screen must not conflate them. A dead key reports
                # cooling=false: it is not waiting for a window, it is gone.
                "dead": key.dead,
                "dead_reason": key.dead_reason,
                "cooling": not key.dead and not key.available(now),
                "cooling_for_seconds": (
                    0.0 if key.dead else round(max(key.cooling_until - now, 0.0), 1)
                ),
                "calls": key.calls,
                "rate_limited": key.rate_limited,
            }
            for key in self._keys
        ]

    def __repr__(self) -> str:
        return f"<KeyPool {self.provider} n={len(self._keys)} live={self.live}>"
