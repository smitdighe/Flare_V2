"""Reasoning admission. PLAN Part B / §10.4 / D27.

ONE definition of "does this alert get an LLM narrative", called from the two
nodes that can change the answer:

  `classify` decides from the model's severity. It ALWAYS runs, which is what
      makes this the load-bearing call.
  `enrich`  re-decides only when intel RAISED severity across the floor. Intel
      escalation can only ever raise, so an alert already admitted stays
      admitted and its token is never spent twice.

**WHY THIS DOES NOT LIVE ONLY IN `enrich`.** It used to, and that was a real
bug caught by a live run: enrichment is skipped whenever the source address is
not publicly routable, and on CICIDS2017 that is 90.5% of replay rows. Those
alerts went classify -> retrieve -> reason with no gate at all, so the severity
floor and the rate budget applied to under a tenth of traffic and the demo would
have 429'd inside the first minute (T4). Admission has to live on the path every
alert takes.

The routers stay pure: this writes a BOOLEAN and a REASON onto the state, and
`route_after_classify` / `route_after_enrich` read them. Reserving a token is a
side effect, and a side effect does not belong in a routing function.
"""

from __future__ import annotations

from app.agent.budget import get_reason_budget
from app.ingestion.labels import SEVERITY_ORDER, severity_rank

# Written into `reason_skip_reason` when the budget, not the policy, is what
# turned the alert away. `enrich` uses it to tell "the floor rejected this, and
# intel has now raised it" apart from "there was no quota left".
BUDGET_EXHAUSTED_MARKER = "reasoning rate budget"


def reserve_reasoning(
    severity: str, severity_floor: str, *, escalated: bool
) -> tuple[bool, str | None]:
    """Returns (admitted, skip_reason). Consumes a budget token iff admitted.

    Classification escalation bypasses BOTH the floor and the budget: it fires
    on roughly 0.3% of alerts, so it costs nothing to always honour, and an
    alert the classifier could not resolve is exactly the one that needs a
    second opinion.
    """
    if escalated:
        return True, None

    if severity not in SEVERITY_ORDER:
        return False, (
            "severity is 'unknown', which is outside the order and satisfies no "
            "threshold (PLAN D27); there is no verdict to narrate"
        )

    if severity_rank(severity) < severity_rank(severity_floor):
        return False, f"severity {severity!r} is below the {severity_floor!r} reasoning floor"

    budget = get_reason_budget()
    if not budget.try_acquire():
        return False, (
            f"the {BUDGET_EXHAUSTED_MARKER} of {budget.calls_per_minute:g} "
            "calls/min is exhausted for this window (PLAN §10.4); the alert is "
            "above the severity floor but the free-tier cap is not"
        )
    return True, None


def was_turned_away_by_budget(reason: str | None) -> bool:
    return bool(reason) and BUDGET_EXHAUSTED_MARKER in (reason or "")
