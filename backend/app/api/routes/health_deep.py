"""GET /health/deep — the real four-provider probe. CONTRACT §9.5 / PLAN §10.4.

**MANUAL REFRESH ONLY. THIS SPENDS METERED QUOTA ON EVERY CALL.** The Health
screen polls `/health` on a 30-second timer; if that timer ever pointed here it
would burn four quotas every 30 seconds per open tab (T4) and exhaust Gemini's
free tier before the demo started. `/health` stays local-only and serves the
cache this endpoint writes.

The four probes run CONCURRENTLY and each carries its own timeout (I7), so the
worst case is one timeout rather than four in series.

Groq and Gemini are probed with a genuine minimal completion, not a models-list
call. That is deliberate and it is D31's lesson: `gemini-2.5-flash` appears in
the models listing and 404s on generateContent. Only a real call proves a real
model ID works, which is exactly what an operator running the demo-day quota
check (PLAN §19 step 3) needs to know.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request, status

from app.api.deps import CurrentUser
from app.api.envelope import enveloped_response
from app.api.errors import AppError
from app.config import get_settings
from app.core.health_state import get_health_cache
from app.core.user_rate_limit import get_limiter
from app.intel.aggregator import get_aggregator
from app.notifications.dispatcher import get_dispatcher
from app.providers.base import ProviderError, RateLimited
from app.providers.keypool import (
    AllKeysCoolingError,
    AllKeysDeadError,
    EmptyPoolError,
)
from app.providers.registry import get_registry

router = APIRouter(tags=["health"])

PROBE_SYSTEM = "Reply with JSON only."
PROBE_USER = 'Return exactly {"ok": true}'


async def _probe_groq() -> dict[str, Any]:
    registry = get_registry()
    try:
        result = await registry.groq.complete(PROBE_SYSTEM, PROBE_USER, max_tokens=32)
    except AllKeysDeadError as exc:
        # PLAN D39 — NOT `rate_limited`. A rate limit clears on its own and the
        # operator's move is to wait; a dead pool clears only when somebody
        # provisions a key, and reporting it as amber "rate limited" would tell
        # them to do the one thing that cannot work. The per-key `dead` flags in
        # `providers` carry the machine-readable detail.
        return {"status": "error", "latency_ms": None, "message": str(exc)}
    except (RateLimited, AllKeysCoolingError) as exc:
        return {"status": "rate_limited", "latency_ms": None, "message": str(exc)}
    except (ProviderError, EmptyPoolError) as exc:
        # Raw error text, per PLAN §11 — the operator needs the provider's own
        # words, not a category.
        return {"status": "error", "latency_ms": None, "message": str(exc)}
    return {
        "status": "ok",
        "latency_ms": round(result.duration_ms, 3),
        "message": f"{result.model} via {result.key_id}",
    }


async def _probe_gemini() -> dict[str, Any]:
    registry = get_registry()
    try:
        result = await registry.gemini.complete(PROBE_SYSTEM, PROBE_USER, max_tokens=32)
    except AllKeysDeadError as exc:
        # PLAN D39 — NOT `rate_limited`. A rate limit clears on its own and the
        # operator's move is to wait; a dead pool clears only when somebody
        # provisions a key, and reporting it as amber "rate limited" would tell
        # them to do the one thing that cannot work. The per-key `dead` flags in
        # `providers` carry the machine-readable detail.
        return {"status": "error", "latency_ms": None, "message": str(exc)}
    except (RateLimited, AllKeysCoolingError) as exc:
        return {"status": "rate_limited", "latency_ms": None, "message": str(exc)}
    except (ProviderError, EmptyPoolError) as exc:
        return {"status": "error", "latency_ms": None, "message": str(exc)}
    return {
        "status": "ok",
        "latency_ms": round(result.duration_ms, 3),
        "message": f"{result.model} via {result.key_id}",
    }


async def _probe_intel(name: str) -> dict[str, Any]:
    """A real lookup against a routable address.

    8.8.8.8 is used because it is public, stable, and universally known to both
    sources — so a non-answer is a fact about the provider, not about the
    address.
    """
    result = await get_aggregator().probe(name, "8.8.8.8")
    status = {"ok": "ok", "rate_limited": "rate_limited", "skipped": "error"}.get(
        result.status, "error"
    )
    return {
        "status": status,
        "latency_ms": round(result.duration_ms, 3) if result.duration_ms else None,
        "message": result.detail,
    }


@router.get("/health/deep")
async def health_deep(request: Request, user: CurrentUser) -> Any:
    # CONTRACT §9.5 — A PER-USER BUDGET, ON TOP OF THE GLOBAL LIMITER.
    # The global limiter allows 120 requests a minute, which is right for
    # reading alerts and wrong for a route that spends four metered provider
    # quotas per call: at that rate one operator holding the refresh button
    # draws 480 provider calls a minute. The contract says this route is
    # manual-refresh-only, and this is what makes that a property of the server
    # rather than a hope about the client.
    settings = get_settings()
    retry_after = get_limiter(
        "health_deep", settings.health_deep_calls_per_minute
    ).check(user.id)
    if retry_after is not None:
        raise AppError(
            "rate_limited",
            "/health/deep probes four metered providers on every call and is "
            f"limited to {settings.health_deep_calls_per_minute:g} per minute "
            "per user. The cheap /health endpoint serves the cached result of "
            "the last probe and is what the 30-second poll should use.",
            status.HTTP_429_TOO_MANY_REQUESTS,
            {"retry_after_seconds": round(retry_after, 1)},
        )

    registry = get_registry()
    cache = get_health_cache()

    if registry.offline_mode:
        # PLAN §10.4 / E9 — offline mode is declared, never silent. No provider
        # is probed, and the payload says so rather than reporting four errors
        # that would look like an outage.
        for name in ("groq", "gemini", "abuseipdb", "virustotal"):
            cache.record(name, "unknown", None, "offline mode: no probe issued")
        return enveloped_response(_payload(cache, registry, offline=True), request)

    names = ("groq", "gemini", "abuseipdb", "virustotal")
    probes = await asyncio.gather(
        _probe_groq(),
        _probe_gemini(),
        _probe_intel("abuseipdb"),
        _probe_intel("virustotal"),
        return_exceptions=True,
    )

    for name, probe in zip(names, probes, strict=True):
        if isinstance(probe, BaseException):
            cache.record(name, "error", None, f"{type(probe).__name__}: {probe}")
            continue
        cache.record(name, probe["status"], probe["latency_ms"], probe["message"])

    return enveloped_response(_payload(cache, registry, offline=False), request)


def _payload(cache: Any, registry: Any, *, offline: bool) -> dict[str, Any]:
    from app.agent.budget import get_reason_budget
    from app.agent.graph import in_flight
    from app.ingestion.feed import get_feed
    from app.rules.engine import get_rule_engine
    from app.workers.scheduler import JOBS, get_scheduler

    stats = get_feed().stats()
    scheduler = get_scheduler()

    return {
        "services": cache.snapshot(),
        "queue_depth": {
            stats["queue"]["name"]: stats["queue"]["depth"],
            "subscribers": stats["subscribers"],
        },
        "in_flight": in_flight(),
        "dropped": {
            "triage_queue": stats["queue"]["dropped"],
            "subscribers": stats["subscriber_dropped"],
            "persist_failures": stats["persist_failures"],
            "triage_failures": stats["triage_failures"],
        },
        "degraded": any(
            service["status"] not in ("ok", "unknown") for service in cache.snapshot()
        ),
        "offline_mode": offline,
        # PLAN I16 — labels and counters. No key material, ever.
        "providers": registry.snapshot(),
        "reason_budget": get_reason_budget().stats(),
        "intel_cache": get_aggregator().cache_stats,
        # PLAN §4.1 — the Phase 4 surfaces an operator needs to see the state
        # of before a demo. `rules` is the count actually LOADED into the
        # engine, not the row count: a rule that exists in the database and did
        # not load changes nothing about any alert, and that gap is exactly
        # what this number makes visible.
        "rules_loaded": len(get_rule_engine()),
        "scheduler": {
            "running": bool(scheduler and scheduler.running),
            # `jobs` is every job this build KNOWS HOW TO RUN; `scheduled` is
            # what is actually on a timer right now. Phase 5 made the two able
            # to differ — `notifications.flush` is registered only when
            # notifications are enabled — and reporting only the registry would
            # name a job that is never going to fire.
            "jobs": sorted(JOBS),
            "scheduled": sorted(job.id for job in scheduler.get_jobs())
            if scheduler
            else [],
            "playbooks_triggered": stats["playbooks_triggered"],
            "playbook_failures": stats["playbook_failures"],
        },
        # PLAN §8 — what an operator checks before rehearsing the notification
        # beat: whether the worker is running, and whether anything has been
        # sent, suppressed or failed since boot.
        "notifications": get_dispatcher().stats(),
    }
