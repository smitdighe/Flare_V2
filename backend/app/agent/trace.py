"""@traced and the finalize backfill. PLAN I1 / CONTRACT §4.0, §8.3.

I1: **the trace contains exactly one entry per node, always, including on an
unhandled exception.** Two mechanisms enforce it and they cover different holes.

`@traced` covers the node that RAN. It wraps the body in try/except/finally, so
a node that raises still contributes exactly one entry — `status: failed`, with
the exception type and message in `note`. The prior codebase's bare `except`
swallowed a whole stage with no marker at all (T13), which is the same
observable state as a stage that was never wired up.

`backfill_skipped` covers the node that DID NOT RUN. Every node the routers
skipped gets a `skipped` entry with a HUMAN-READABLE reason before the payload
leaves. A gap in the array would force the reader to guess between "skipped",
"failed" and "never implemented" — the exact ambiguity I1 exists to remove.

CONSISTENCY OBLIGATION (CONTRACT §4.1). The table's three-square strip infers
stage completion from `severity` / `ioc_checked` / `explanation`, not from the
trace. So a node whose entry is `failed` or `skipped` must NOT leave one of
those fields populated, or the strip lights up green for a stage that did not
succeed. `assert_strip_consistency` checks the pairing and is asserted in tests.
"""

from __future__ import annotations

import functools
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from app.agent.state import NodeName, PipelineState, TraceNode, TraceStatus

logger = logging.getLogger("flare.agent")

# A node receives the state and the builder it may write ONE entry into.
# `@traced` adapts it to the single-argument callable LangGraph invokes.
NodeFn = Callable[[PipelineState, "TraceBuilder"], Awaitable[dict[str, Any]]]


class GraphFn(Protocol):
    """What `add_node` accepts.

    A Protocol rather than a `Callable[...]` alias because LangGraph's own node
    protocol declares the parameter BY NAME (`state`), and a Callable alias is
    positional-only — so the alias would not satisfy it and every `add_node`
    call would fail to type-check.
    """

    async def __call__(self, state: PipelineState) -> dict[str, Any]: ...

# The scalar each node must agree with. CONTRACT §8.3: `duration_ms` must agree
# with the matching `*_latency_ms`.
LATENCY_FIELD: dict[str, str] = {
    NodeName.CLASSIFY.value: "classify_latency_ms",
    NodeName.ENRICH.value: "enrich_latency_ms",
    NodeName.REASON.value: "reasoning_latency_ms",
}

# CONTRACT §4.1 — the field the frozen table's strip reads for each stage.
STRIP_FIELD: dict[str, str] = {
    NodeName.CLASSIFY.value: "severity",
    NodeName.ENRICH.value: "ioc_checked",
    NodeName.REASON.value: "explanation",
}


class TraceBuilder:
    """Collects the one entry a node is allowed to emit.

    A node calls `record(...)` to describe what happened. If it never does — the
    normal case for a plain success — `@traced` writes an `ok` entry for it. If
    it raises, `@traced` overwrites with `failed`, because what actually
    happened is the exception, not whatever the node believed a moment earlier.
    """

    def __init__(self, node: str) -> None:
        self.node = node
        self.status: TraceStatus = TraceStatus.OK
        self.fields: dict[str, Any] = {}

    def record(self, status: TraceStatus, **fields: Any) -> None:
        self.status = status
        self.fields.update({k: v for k, v in fields.items() if v is not None})

    def build(self, duration_ms: float) -> TraceNode:
        return TraceNode(
            node=self.node,
            status=self.status,
            duration_ms=round(duration_ms, 3),
            **self.fields,
        )


def traced(node: NodeName) -> Callable[[NodeFn], GraphFn]:
    """Exactly one TraceNode per invocation, including on an unhandled raise."""

    def decorator(fn: NodeFn) -> GraphFn:
        @functools.wraps(fn)
        async def wrapper(state: PipelineState) -> dict[str, Any]:
            builder = TraceBuilder(node.value)
            started = time.perf_counter()
            update: dict[str, Any] = {}
            failure: str | None = None

            try:
                update = await fn(state, builder)
            except Exception as exc:
                # T13 — never a bare swallow. The stage is marked failed, the
                # exception is preserved in the note and in `errors`, and the
                # graph continues so the remaining stages still produce output.
                failure = f"{type(exc).__name__}: {exc}"
                builder.status = TraceStatus.FAILED
                builder.fields["note"] = failure
                logger.exception(
                    "graph node failed",
                    extra={"request_id": "-", "node": node.value, "alert": state.alert_id},
                )
                update = {}

            duration_ms = (time.perf_counter() - started) * 1000
            entry = builder.build(duration_ms)

            # APPEND, never replace. `finalize` returns its backfilled entries
            # under this key, and overwriting them here would delete the very
            # thing I1 exists to guarantee — with the node's own entry still
            # present, so the loss would look like a correct trace.
            update["trace"] = [*update.get("trace", []), entry]
            update["visited"] = [node.value]
            if failure:
                update["errors"] = [f"{node.value}: {failure}"]
                # A failed stage must not leave the strip's field populated
                # (CONTRACT §4.1). Clearing it here is what keeps the two views
                # of the same stage from disagreeing.
                strip = STRIP_FIELD.get(node.value)
                if strip == "explanation":
                    update["explanation"] = None
                elif strip == "ioc_checked":
                    update["ioc_checked"] = False

            latency_field = LATENCY_FIELD.get(node.value)
            if latency_field:
                update[latency_field] = entry.duration_ms
            return update

        return wrapper

    return decorator


def backfill_skipped(state: PipelineState, reasons: dict[str, str]) -> list[TraceNode]:
    """I1 — a `skipped` entry, with a reason, for every node that never ran.

    `reasons` carries the specific explanation a router recorded. A node with no
    recorded reason still gets an entry: a generic reason is worse than a
    specific one and enormously better than a gap.
    """
    present = {entry.node for entry in state.trace}
    missing = []
    for node in NodeName:
        if node.value in present or node is NodeName.FINALIZE:
            continue
        missing.append(
            TraceNode(
                node=node.value,
                status=TraceStatus.SKIPPED,
                duration_ms=0.0,
                note=reasons.get(
                    node.value,
                    "the router did not select this node on this alert's path",
                ),
            )
        )
    return missing


def order_trace(entries: list[TraceNode]) -> list[TraceNode]:
    """Pipeline order. CONTRACT §4.0: FE-7 renders the array AS RECEIVED."""
    position = {node.value: index for index, node in enumerate(NodeName)}
    return sorted(entries, key=lambda e: position.get(e.node, len(position)))


def strip_consistency_violations(
    trace: list[TraceNode], *, severity: str, ioc_checked: bool, explanation: str | None
) -> list[str]:
    """CONTRACT §4.1 — the strip's fields must agree with `trace[].status`.

    The frozen `AlertTable` infers stage completion from field presence, not from
    the trace. A `failed` or `skipped` node that left its field populated makes
    the strip claim a stage succeeded when the drawer says it did not.
    """
    values: dict[str, object] = {
        "severity": severity if severity != "unknown" else "",
        "ioc_checked": ioc_checked,
        "explanation": explanation,
    }
    violations: list[str] = []
    for entry in trace:
        field = STRIP_FIELD.get(entry.node)
        if field is None or entry.status is TraceStatus.OK:
            continue
        if values.get(field):
            violations.append(
                f"node {entry.node!r} is {entry.status.value} but {field!r} is "
                f"populated ({values[field]!r}); the table's stage strip would "
                "render this stage as complete (CONTRACT §4.1)"
            )
    return violations
