import time
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any, Literal

Status = Literal["ok", "rate_limited", "error", "unknown"]

# CONTRACT §2.4 / PLAN §10: these are the four metered dependencies. Phase 1
# reports them as never-probed; Phase 3's /health/deep fills the cache.
TRACKED_SERVICES: tuple[str, ...] = ("groq", "gemini", "abuseipdb", "virustotal")


@dataclass
class ServiceState:
    name: str
    status: Status = "unknown"
    latency_ms: float | None = None
    message: str | None = None
    checked_at: float | None = None  # monotonic clock
    checked_at_iso: str | None = None


@dataclass
class HealthCache:
    """Locally held provider state. Serving this NEVER touches a provider.

    CONTRACT §9.5 / PLAN §10:
      * results are served for `ttl` seconds;
      * past `stale_after` seconds they are refreshed on the next request —
        from local state, not the network;
      * the 30s dashboard poll therefore costs zero provider quota.

    Only /health/deep (Phase 3) performs a real probe and calls `record`.
    """

    ttl_seconds: int
    stale_after_seconds: int
    _services: dict[str, ServiceState] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in TRACKED_SERVICES:
            self._services[name] = ServiceState(name=name)

    def record(
        self,
        name: str,
        status: Status,
        latency_ms: float | None,
        message: str | None = None,
    ) -> None:
        from datetime import datetime

        self._services[name] = ServiceState(
            name=name,
            status=status,
            latency_ms=latency_ms,
            message=message,
            checked_at=time.monotonic(),
            checked_at_iso=datetime.now(UTC).isoformat(),
        )

    def age_seconds(self, state: ServiceState) -> float | None:
        if state.checked_at is None:
            return None
        return time.monotonic() - state.checked_at

    def snapshot(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name in TRACKED_SERVICES:
            state = self._services[name]
            age = self.age_seconds(state)

            if age is None:
                # Never probed. Reporting "ok" here would claim a check that
                # never happened (PLAN I2).
                status: Status = "unknown"
                latency = None
                message: str | None = "not yet probed"
            elif age > self.stale_after_seconds:
                status = state.status
                latency = state.latency_ms
                message = f"stale ({int(age)}s old); refresh via /health/deep"
            else:
                status = state.status
                latency = state.latency_ms
                message = state.message or None

            out.append(
                {
                    "name": name,
                    "status": status,
                    "latency_ms": latency,
                    "message": message,
                    "checked_at": state.checked_at_iso,
                }
            )
        return out


_cache: HealthCache | None = None


def get_health_cache() -> HealthCache:
    global _cache
    if _cache is None:
        from app.config import get_settings

        settings = get_settings()
        _cache = HealthCache(
            ttl_seconds=settings.health_cache_ttl_seconds,
            stale_after_seconds=settings.health_cache_stale_seconds,
        )
    return _cache


def reset_health_cache() -> None:
    global _cache
    _cache = None
