"""GET /eval. CONTRACT §2.4 / PLAN E6 / E10 / §19 step 8.

**THE DEFAULT CALL SERVES THE CACHE, AND THAT IS THE POINT.** A fresh run is
eighty rows through the real graph plus eighty live provider calls. Doing that
on every page load would rate-limit the demo, and doing it while a judge watches
would put a spinner where the headline number should be. `?force=true` — the
Refresh button — is the only thing that re-runs.

**A RUN IS SERIALISED FOR ONE USER AT A TIME.** Two concurrent forced runs would
double the provider spend to produce the same numbers, and the second would be
scored against a key pool the first had already drawn down. The lock makes the
second caller wait for the first result rather than starting a rival run.

**GUARD TRIPS ARE SERVED, NOT SWALLOWED.** A tripped band means the numbers are
not to be quoted until it is adjudicated, and the payload says so on `guards`,
on `guards_tripped` and in `run_notice`. Returning a 500 would hide the evidence
needed to adjudicate it.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Query, Request, status

from app.api.deps import CurrentUser
from app.api.envelope import enveloped_response
from app.api.errors import AppError
from app.config import get_settings
from app.eval import cache
from app.eval.harness import EvalConfig, EvalDataError, EvalHarness

logger = logging.getLogger("flare.eval")

router = APIRouter(tags=["eval"])

_run_lock = asyncio.Lock()


@router.get("/eval")
async def get_eval(
    request: Request,
    user: CurrentUser,
    force: str | None = Query(default=None),
) -> Any:
    """Held-out evaluation results. Cached unless `?force=true`."""
    if force != "true":
        cached = cache.read()
        if cached is not None:
            return enveloped_response(cached, request)

    settings = get_settings()
    async with _run_lock:
        # Re-check inside the lock: while this caller waited, the run it was
        # waiting for may have finished and written exactly what it wanted.
        if force != "true":
            cached = cache.read()
            if cached is not None:
                return enveloped_response(cached, request)
        try:
            harness = EvalHarness(settings, EvalConfig.from_settings(settings))
            payload = await harness.run()
        except (EvalDataError, FileNotFoundError) as exc:
            raise AppError(
                "eval_unavailable",
                str(exc),
                status.HTTP_503_SERVICE_UNAVAILABLE,
            ) from exc

    cache.write(payload)
    tripped = payload.get("guards_tripped") or []
    if tripped:
        logger.error(
            "eval guard band tripped",
            extra={"request_id": "-", "guards": tripped},
        )
    return enveloped_response({**payload, "cached": False}, request)
