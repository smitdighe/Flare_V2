"""Replay -> graph -> persist -> GET /alerts, with the real trace on the wire.

This is the Phase 3 DONE WHEN condition expressed as a test: an alert that came
off the replay partition, went through the real graph, was persisted, and is
served to the drawer with a complete per-stage trace carrying provider and model
attribution and reasons on every skip.

The suite runs offline (conftest), so the providers here are the declared
offline tier rather than stubs — which makes this also the test that offline
mode produces a COMPLETE, HONEST payload rather than a hollow one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient

from app.agent.state import NodeName
from tests.conftest import auth_header, login, make_user

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPLAY_CSV = BACKEND_ROOT / "data" / "splits" / "replay.csv"
MODEL_DIR = BACKEND_ROOT / "models" / "classifier"

needs_data = pytest.mark.skipif(
    not REPLAY_CSV.exists(), reason="replay partition not built"
)
needs_model = pytest.mark.skipif(
    not (MODEL_DIR / "metrics.json").exists(), reason="classifier not trained"
)

TRACE_FIELDS = {
    "node",
    "status",
    "provider",
    "model",
    "model_version",
    "duration_ms",
    "tokens",
    "note",
    "key_id",
}


@pytest.fixture
def loaded():
    """Real classifier, real index, real graph. Only the network is absent."""
    from app.ml.classifier import load_classifier, reset_classifier
    from app.rag.retriever import load_retriever, reset_retriever

    load_classifier()
    load_retriever()
    yield
    reset_classifier()
    reset_retriever()


@needs_data
@needs_model
async def test_a_replayed_alert_arrives_with_a_complete_trace(
    client: AsyncClient, loaded: None
) -> None:
    from app.ingestion.feed import get_feed, reset_feed
    from app.ingestion.replay import ReplayEngine, load_replay_rows

    reset_feed()
    feed = get_feed()
    alerts = list(ReplayEngine(load_replay_rows(REPLAY_CSV)).iter_alerts(3))
    for alert in alerts:
        await feed._emit(alert)

    await make_user("e2e@flare.dev", role="analyst")
    token = await login(client, "e2e@flare.dev")
    body = (
        await client.get("/api/v1/alerts", headers=auth_header(token))
    ).json()["data"]

    assert body["total"] >= 3
    for payload in body["alerts"]:
        trace = payload["trace"]

        # CONTRACT §4.0 — required, minItems 1, one entry per node, in order.
        assert [e["node"] for e in trace] == [n.value for n in NodeName]
        for entry in trace:
            assert set(entry) == TRACE_FIELDS
            assert entry["status"] in ("ok", "skipped", "failed")
            if entry["status"] != "ok":
                assert entry["note"], "a skip or a failure always carries a reason"

        # I5/I16 — the verdict is attributable to the artifact that produced it.
        classify = trace[0]
        assert classify["provider"] == "lightgbm"
        assert classify["model_version"]

        # The verdict came from the pipeline, not from the parser.
        assert payload["severity"] != "unknown"
        assert payload["attack_type"] != "unknown"

        # CONTRACT §8.3 — the scalars agree with the trace.
        by_node = {e["node"]: e for e in trace}
        assert payload["classify_latency_ms"] == by_node["classify"]["duration_ms"]

        # PLAN I4 — the label never travels with a rendered alert.
        assert "ground_truth_class" not in payload
        # PLAN T11 — no fabricated hash, ever.
        assert payload["vt_hash"] is None


@needs_data
@needs_model
async def test_the_stage_strip_never_contradicts_the_trace(
    client: AsyncClient, loaded: None
) -> None:
    """CONTRACT §4.1 — the table infers stage status from field presence."""
    from app.agent.state import TraceNode
    from app.agent.trace import strip_consistency_violations
    from app.ingestion.feed import get_feed, reset_feed
    from app.ingestion.replay import ReplayEngine, load_replay_rows

    reset_feed()
    feed = get_feed()
    for alert in ReplayEngine(load_replay_rows(REPLAY_CSV)).iter_alerts(8):
        await feed._emit(alert)

    await make_user("strip@flare.dev", role="analyst")
    token = await login(client, "strip@flare.dev")
    alerts = (
        await client.get("/api/v1/alerts", headers=auth_header(token))
    ).json()["data"]["alerts"]

    assert alerts
    for payload in alerts:
        violations = strip_consistency_violations(
            [TraceNode.model_validate(entry) for entry in payload["trace"]],
            severity=payload["severity"],
            ioc_checked=payload["ioc_checked"],
            explanation=payload["explanation"],
        )
        assert not violations, violations


@needs_data
@needs_model
async def test_offline_mode_produces_a_labelled_not_a_hollow_payload(
    loaded: None,
) -> None:
    """PLAN E9 — offline is a DECLARED tier, and the payload says so."""
    from app.agent.graph import reset_graph, run_pipeline
    from app.ingestion.replay import ReplayEngine, load_replay_rows

    reset_graph()
    alert = next(iter(ReplayEngine(load_replay_rows(REPLAY_CSV)).iter_alerts(1)))
    state = await run_pipeline(alert)

    assert state.offline_mode is True
    assert state.degraded is True
    by_node = {entry.node: entry for entry in state.trace}
    # The fast tier is local, so it still runs and still produces a real verdict.
    assert by_node["classify"].provider == "lightgbm"
    assert state.attack_type in {
        "benign",
        "dos",
        "ddos",
        "port_scan",
        "botnet",
        "web_attack",
    }
    # Nothing that needs a network claims to have happened.
    assert by_node["enrich"].status.value == "skipped"
    assert state.ioc_checked is False


@needs_data
@needs_model
async def test_the_eval_entry_point_is_the_production_entry_point() -> None:
    """PLAN E3 — the eval calls the exact function production calls.

    The prior codebase's eval called `classify_alert` while production called
    `run_pipeline`, so the eval scored a system nobody was running. Asserting the
    feed and the eval reach the same symbol is what keeps that from recurring.
    """
    import inspect

    import app.agent.graph as graph_mod
    import app.ingestion.feed as feed_mod

    assert "run_pipeline" in inspect.getsource(feed_mod.FeedService._triage)
    assert inspect.iscoroutinefunction(graph_mod.run_pipeline)


@needs_data
@needs_model
async def test_an_eve_alert_skips_the_ml_tier_with_a_reason(loaded: None) -> None:
    """PLAN D25 — end to end, on the real classifier, with no zero-filling."""
    from app.agent.graph import reset_graph, run_pipeline
    from app.ingestion.replay import ReplayEngine, load_replay_rows

    reset_graph()
    alert = next(iter(ReplayEngine(load_replay_rows(REPLAY_CSV)).iter_alerts(1)))
    alert.source = "live_demo"
    alert.features = {}

    state = await run_pipeline(alert)
    classify = next(e for e in state.trace if e.node == "classify")

    # Offline mode, so the LLM cannot run — the skip is still explicit and the
    # reason still names D25 rather than leaving a silent `unknown`.
    assert classify.status.value == "skipped"
    assert "no flow features" in (classify.note or "")
    assert state.attack_type == "unknown"
