"""StateGraph assembly, the wall clock, and the production entry point.

PLAN §4.2 / Part A / I1 / I6 / I7 / E3.

**THE SHAPE**

    START -> classify
    classify  --route_after_classify--> { enrich | retrieve | recommend }
    enrich    --route_after_enrich  --> { retrieve | recommend }
    retrieve  -> reason
    reason    --route_after_reason  --> { recommend | rules }
    recommend -> rules
    rules     -> finalize -> END

Seven nodes, exactly the seven CONTRACT §8.3 names, one trace entry each.
Three real conditional edges, each a pure `state -> str` function in
`app/agent/router.py`, each unit-tested branch by branch with no graph running.

**THE WALL CLOCK**

Every provider call has its own timeout (I7), and that is still not enough: a
run can spend a timeout in classify AND a timeout in reason and still be inside
both. `graph_budget_seconds` bounds the WHOLE run and, on expiry, returns
PARTIAL STATE rather than hanging — the alert emits with whatever stages
completed, the rest backfilled as skipped with the wall clock named as the
reason. A hung run holds a triage slot forever and reads to a viewer as the feed
having died.

Cancelling mid-graph would lose the trace entries already collected, so the
budget is enforced by racing the graph against a timer and finalizing the
snapshot the nodes have written so far.

**E3** — the eval calls `run_pipeline`. The same function, the same graph, the
same arguments production uses. The prior codebase's eval called a shortcut that
skipped three of four stages and then reported the result as the system's.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from langgraph.graph import END, START, StateGraph

from app.agent.nodes.classify import classify_node
from app.agent.nodes.enrich import enrich_node
from app.agent.nodes.finalize import finalize_node, skip_reasons
from app.agent.nodes.reason import reason_node
from app.agent.nodes.recommend import recommend_node
from app.agent.nodes.retrieve import retrieve_node
from app.agent.nodes.rules import rules_node
from app.agent.router import (
    route_after_classify,
    route_after_enrich,
    route_after_reason,
)
from app.agent.state import NodeName, PipelineState, TraceNode, TraceStatus
from app.agent.trace import backfill_skipped, order_trace
from app.config import Settings, get_settings

logger = logging.getLogger("flare.agent")


def build_graph() -> Any:
    graph: StateGraph[PipelineState] = StateGraph(PipelineState)

    graph.add_node(NodeName.CLASSIFY.value, classify_node)
    graph.add_node(NodeName.ENRICH.value, enrich_node)
    graph.add_node(NodeName.RETRIEVE.value, retrieve_node)
    graph.add_node(NodeName.REASON.value, reason_node)
    graph.add_node(NodeName.RECOMMEND.value, recommend_node)
    graph.add_node(NodeName.RULES.value, rules_node)
    graph.add_node(NodeName.FINALIZE.value, finalize_node)

    graph.add_edge(START, NodeName.CLASSIFY.value)
    graph.add_conditional_edges(
        NodeName.CLASSIFY.value,
        route_after_classify,
        {
            "enrich": NodeName.ENRICH.value,
            "retrieve": NodeName.RETRIEVE.value,
            "recommend": NodeName.RECOMMEND.value,
        },
    )
    graph.add_conditional_edges(
        NodeName.ENRICH.value,
        route_after_enrich,
        {"retrieve": NodeName.RETRIEVE.value, "recommend": NodeName.RECOMMEND.value},
    )
    graph.add_edge(NodeName.RETRIEVE.value, NodeName.REASON.value)
    graph.add_conditional_edges(
        NodeName.REASON.value,
        route_after_reason,
        {"recommend": NodeName.RECOMMEND.value, "rules": NodeName.RULES.value},
    )
    graph.add_edge(NodeName.RECOMMEND.value, NodeName.RULES.value)
    graph.add_edge(NodeName.RULES.value, NodeName.FINALIZE.value)
    graph.add_edge(NodeName.FINALIZE.value, END)

    return graph.compile()


_compiled: Any = None
_semaphore: asyncio.Semaphore | None = None
_in_flight = 0


def in_flight() -> int:
    """How many graph runs are executing right now. Reported on /health/deep."""
    return _in_flight


def get_compiled_graph() -> Any:
    global _compiled
    if _compiled is None:
        _compiled = build_graph()
    return _compiled


def get_semaphore() -> asyncio.Semaphore:
    """Bound concurrent runs.

    At the configured replay rate an alert arrives every ~2s and a run can take
    up to the wall-clock budget, so without a bound the number of in-flight
    graphs grows until something falls over. This is also what keeps provider
    concurrency sane: N in-flight graphs is at most N in-flight provider calls
    per stage.
    """
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(get_settings().max_concurrent_pipelines)
    return _semaphore


def reset_graph() -> None:
    """Test seam."""
    global _compiled, _semaphore, _in_flight
    _compiled = None
    _semaphore = None
    _in_flight = 0


def initial_state(alert: Any, settings: Settings | None = None) -> PipelineState:
    """NormalizedAlert -> PipelineState, with the config snapshot the routers read.

    PLAN I4 — `ground_truth_class` is NOT copied. It is not a field of
    PipelineState at all, so no node and no prompt builder can reach it.
    """
    settings = settings or get_settings()
    return PipelineState(
        alert_id=alert.id,
        source=alert.source,
        signature=alert.signature,
        src_ip=alert.src_ip,
        dest_ip=alert.dest_ip,
        dest_port=alert.dest_port,
        protocol=alert.protocol,
        features=dict(alert.features),
        severity_floor=settings.reason_severity_floor,
        confidence_threshold=settings.escalation_confidence_threshold,
        intel_escalation_score=settings.intel_escalation_score,
        retrieval_low_confidence_score=settings.retrieval_low_confidence_score,
        offline_mode=settings.offline_mode,
        # PLAN §10.4 / E9 — in offline mode EVERY alert is degraded, set here
        # rather than by whichever node happens to notice. An alert that never
        # needed a provider would otherwise emit undegraded, and the analyst
        # would have no way to tell "this one was fine" from "the whole pipeline
        # is running without providers". The flag describes the SYSTEM the
        # verdict was produced by, not just the stages that happened to run.
        degraded=settings.offline_mode,
    )


async def run_pipeline(alert: Any, settings: Settings | None = None) -> PipelineState:
    """THE production entry point. The eval calls this exact function (E3).

    Returns a fully-populated PipelineState whose `trace` holds exactly one
    entry per node in pipeline order, whatever happened.
    """
    global _in_flight

    settings = settings or get_settings()
    state = initial_state(alert, settings)

    async with get_semaphore():
        _in_flight += 1
        try:
            raw = await asyncio.wait_for(
                get_compiled_graph().ainvoke(state),
                timeout=settings.graph_budget_seconds,
            )
        except TimeoutError:
            # PLAN Part C — partial state, never a hang. The graph's own writes
            # are gone with the cancelled task, so the run is reconstructed from
            # the entry state and every node is backfilled with the wall clock
            # named as the reason.
            logger.warning(
                "graph wall clock expired",
                extra={
                    "request_id": "-",
                    "alert": state.alert_id,
                    "budget_seconds": settings.graph_budget_seconds,
                },
            )
            return _partial(state, settings)
        finally:
            _in_flight -= 1

    final = PipelineState.model_validate(raw)
    final.trace = order_trace(final.trace)
    return final


def _partial(state: PipelineState, settings: Settings) -> PipelineState:
    """A timed-out run, finalized honestly. PLAN I1 still holds."""
    note = (
        f"the whole-graph wall clock of {settings.graph_budget_seconds}s expired "
        "before this node ran; the alert is emitted with partial state rather "
        "than holding a triage slot open indefinitely"
    )
    state.budget_exhausted = True
    state.degraded = True
    state.errors = [*state.errors, f"graph: wall clock {settings.graph_budget_seconds}s expired"]

    reasons = dict.fromkeys(
        (n.value for n in NodeName if n is not NodeName.FINALIZE), note
    )
    reasons.update(skip_reasons(state))
    entries = backfill_skipped(state, reasons)
    entries.append(
        TraceNode(
            node=NodeName.FINALIZE.value,
            status=TraceStatus.FAILED,
            duration_ms=round(settings.graph_budget_seconds * 1000, 3),
            provider="pipeline",
            model="finalize",
            note=note,
        )
    )
    state.trace = order_trace([*state.trace, *entries])
    return state
