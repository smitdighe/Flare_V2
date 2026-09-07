"""The cached run. PLAN E6 / §19 step 8.

**A FILE, NOT A TABLE.** The demo runbook opens every session with a fresh
database (§19 step 2, so run 2 does not show run 1's alerts) and also expects
the eval to be pre-executed and cached (§19 step 8). A cache in the database
satisfies neither of those at once — the fresh DB wipes it, and the panel would
be waiting on eighty live provider calls in front of a judge. On disk it
survives, and it is the same kind of artifact `metrics.json` is: a measurement,
committed as evidence rather than regenerated on demand.

**A CACHED RUN SAYS SO.** `cached: true` and the original `generated_at` travel
with the payload, so a number on screen can always be dated. A cache that
presented itself as a fresh run would be a small lie that makes every other
number harder to trust.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("flare.eval")

CACHE_PATH = Path(__file__).resolve().parents[2] / "data" / "eval" / "latest.json"


def read(path: Path | None = None) -> dict[str, Any] | None:
    # Resolved at CALL time, not bound as a default at import time: a default
    # argument would freeze the module constant and make the path impossible to
    # redirect, which is how a test ends up reading the committed run.
    path = path or CACHE_PATH
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A corrupt cache is not a reason to fail the request; it is a reason to
        # re-run. Saying so is what stops it being mistaken for "no run yet".
        logger.warning(
            "eval cache is unreadable and will be regenerated",
            extra={"request_id": "-"},
        )
        return None
    if not isinstance(payload, dict):
        return None
    payload["cached"] = True
    return payload


# The keys only a real harness run produces. A payload without them is a
# hand-built dict, and this file is served to the Evaluation screen as a
# measurement.
RUN_MARKERS: tuple[str, ...] = ("tiers", "partition", "usage", "run_notice")


class NotAMeasurementError(ValueError):
    """Something tried to cache a payload no eval run produced."""


def write(payload: dict[str, Any], path: Path | None = None) -> None:
    """Store a run. REFUSES anything that is not one.

    Added after a test fixture reached this file for real: `read`/`write` bound
    `CACHE_PATH` as a DEFAULT ARGUMENT, so patching the module attribute did not
    redirect them and a synthetic payload was written over the shipped run. The
    binding is fixed above; this is the second lock, because the failure mode —
    a fabricated number served to the screen as a measurement — is the exact
    thing this whole phase exists to prevent.
    """
    missing = [key for key in RUN_MARKERS if key not in payload]
    if missing:
        raise NotAMeasurementError(
            f"refusing to cache a payload missing {missing}. Only the output of "
            "EvalHarness.run() belongs in the eval cache; this file is served to "
            "the Evaluation screen as a measurement."
        )
    path = path or CACHE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    stored = {**payload, "cached": False, "cached_at": datetime.now(UTC).isoformat()}
    path.write_text(json.dumps(stored, indent=2, sort_keys=True), encoding="utf-8")


def clear(path: Path | None = None) -> None:
    (path or CACHE_PATH).unlink(missing_ok=True)
