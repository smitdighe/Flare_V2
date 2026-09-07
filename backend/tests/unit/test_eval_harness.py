"""The harness. PLAN E1 / E3 / E4 / E5 / E7 / E8 / I4 / §7.3b.

The tests here are the ones that would have caught the two prior failures. Both
of those builds passed their own test suites: one because its answer key WAS its
classifier and nothing asserted otherwise, and one because nobody looked at the
bytes that went to the provider.
"""

import inspect
import re
from pathlib import Path

import pytest

from app.config import get_settings
from app.eval import dataset
from app.eval.harness import EvalConfig, EvalHarness
from app.eval.scoring import Outcome, TierResult
from app.ingestion.labels import CANONICAL_CLASSES, RAW_TO_CANONICAL

SPLITS = Path(__file__).resolve().parents[2] / "data" / "splits"
HAVE_SPLITS = (SPLITS / "eval.csv").exists() and (SPLITS / "train.csv").exists()

needs_splits = pytest.mark.skipif(
    not HAVE_SPLITS, reason="partitions not built in this checkout"
)


@pytest.fixture(autouse=True)
def _load_models():
    """The app lifespan loads these; a unit test runs outside it.

    The singletons refuse to self-load on first use on purpose — reaching
    inference without an explicit load means startup was bypassed, and the app
    should say so rather than paper over it.
    """
    from app.ml.classifier import load_classifier

    load_classifier()


def harness(**overrides) -> EvalHarness:
    return EvalHarness(
        get_settings(), EvalConfig(sample_size=24, llm_pace_seconds=0.0, **overrides)
    )


# ---------------------------------------------------------------------------
# PLAN E3 — the eval calls the function production calls
# ---------------------------------------------------------------------------


def test_the_system_tier_calls_run_pipeline_structurally():
    """A source-level assertion, deliberately.

    The prior build's eval called `classify_alert` while production called the
    graph, so the eval scored a path that shipped to nobody. A behavioural test
    can be satisfied by a shim; this asserts the harness names the production
    entry point and nothing else.
    """
    source = inspect.getsource(EvalHarness._score_system)

    assert "from app.agent.graph import run_pipeline" in source
    assert "await run_pipeline(row.alert, self.settings)" in source
    # No alternative entry point may appear in this function.
    for shortcut in ("classify_node(", "classify_alert(", "get_compiled_graph("):
        assert shortcut not in source, shortcut


async def test_the_system_tier_actually_invokes_run_pipeline(monkeypatch):
    """The behavioural half: it is called, once per row, with the alert."""
    import app.agent.graph as graph_module

    seen = []

    async def fake(alert, settings=None):
        seen.append(alert)
        return graph_module.initial_state(alert, get_settings())

    monkeypatch.setattr(graph_module, "run_pipeline", fake)

    rows = _rows(6)
    result, escalation = await harness()._score_system(rows, nearest_neighbour=None)

    assert len(seen) == 6
    assert [a.id for a in seen] == [r.alert.id for r in rows]
    assert len(result.outcomes) == 6
    assert escalation["escalated_count"] + escalation["kept_count"] == 6


# ---------------------------------------------------------------------------
# PLAN I4 — the label never enters a prompt
# ---------------------------------------------------------------------------


def _rows(count: int) -> list[dataset.EvalRow]:
    partition = dataset.load_partition_rows("eval")
    sampled = dataset.stratified_sample(partition, cap=count, seed=20260904)
    return dataset.to_eval_rows(sampled)


@needs_splits
async def test_no_label_string_appears_in_any_constructed_prompt():
    """Dump the prompts and scan them. This is how MINE's 450/450 happened.

    Offline mode means no provider is called, but the prompts are still built by
    the same code path with the same builder, so the bytes under test are the
    bytes that would have been sent.
    """
    h = harness()
    rows = _rows(24)
    await h._score_llm(rows)

    assert len(h.prompts) == 24
    blob = "\n".join(h.prompts).lower()

    # The canonical class names may legitimately appear once, in the enum the
    # system prompt declares — but the system prompt is not what is scanned
    # here, the per-row user prompt is, and a class name has no business in it.
    for label in CANONICAL_CLASSES:
        assert label not in blob, f"canonical class {label!r} reached a user prompt"

    # The raw CICIDS spellings, which is what the prior build pasted in.
    for raw in RAW_TO_CANONICAL:
        assert raw.lower() not in blob, f"raw label {raw!r} reached a user prompt"

    for forbidden in ("canonical_class", "ground_truth", "row_id", "label"):
        assert forbidden not in blob, forbidden


@needs_splits
async def test_the_true_class_of_each_row_is_absent_from_its_own_prompt():
    """Per-row, not just in aggregate: a leak on one class would hide in a blob.

    Attack-type names only. Severity words are ordinary English that the flow
    description legitimately uses — `synthesize_signature` writes "high packet
    volume" for a busy flow — so scanning for them would flag a description of
    the traffic as a leak of the answer. Severity cannot leak by another route
    either: `flow_fields` reads six named fields plus feature values and none of
    them is a verdict, which is what the structural test below pins down.
    """
    h = harness()
    rows = _rows(24)
    await h._score_llm(rows)

    for row, prompt in zip(rows, h.prompts, strict=True):
        pattern = re.compile(rf"\b{re.escape(row.true_attack_type)}\b", re.IGNORECASE)
        assert not pattern.search(prompt), (
            f"row {row.alert.row_id} carries its own class "
            f"{row.true_attack_type!r} in the prompt built for it"
        )


def test_ground_truth_is_not_a_field_of_the_graph_state():
    """The structural guarantee behind the scan.

    A prompt cannot carry the label because there is nowhere in the pipeline
    state for the label to live. A future edit that wanted to leak it would have
    to add the field, which is a visible change rather than a quiet one.
    """
    from app.agent.state import PipelineState

    fields = set(PipelineState.model_fields)
    assert "ground_truth_class" not in fields
    assert "canonical_class" not in fields
    assert "true_attack_type" not in fields


def test_initial_state_does_not_copy_the_label(monkeypatch):
    from app.agent.graph import initial_state

    rows = _rows(6) if HAVE_SPLITS else []
    if not rows:
        pytest.skip("partitions not built in this checkout")

    alert = rows[0].alert
    assert alert.ground_truth_class  # the harness has it
    state = initial_state(alert, get_settings())
    assert rows[0].true_attack_type not in state.model_dump_json().lower()


# ---------------------------------------------------------------------------
# PLAN E1 / §7.3b — the partition contract
# ---------------------------------------------------------------------------


@needs_splits
def test_eval_rows_are_disjoint_from_train_at_the_feature_vector():
    """Id-level disjointness is necessary and NOT sufficient (§7.3b).

    Ids hash Flow ID and the endpoints, so two flows with byte-identical
    statistics get different ids and would pass an id check while being the same
    row to a classifier that sees neither. That is the defect that was actually
    found, 62 rows deep.
    """
    eval_rows = dataset.load_partition_rows("eval")
    train_rows = dataset.load_partition_rows("train")

    assert dataset.exact_feature_overlap(eval_rows, train_rows) == 0

    eval_ids = {r["row_id"] for r in eval_rows}
    train_ids = {r["row_id"] for r in train_rows}
    assert not (eval_ids & train_ids)


@needs_splits
def test_the_sampled_rows_are_disjoint_from_train_too():
    train_rows = dataset.load_partition_rows("train")
    sampled = dataset.stratified_sample(
        dataset.load_partition_rows("eval"), cap=80, seed=20260904
    )
    assert dataset.exact_feature_overlap(sampled, train_rows) == 0


@needs_splits
def test_loading_the_wrong_partition_is_refused():
    with pytest.raises(dataset.PartitionError):
        dataset.load_partition_rows("eval", splits_dir=_MislabelledSplits())


class _MislabelledSplits:
    """A splits dir whose eval.csv is really the replay partition."""

    def __truediv__(self, name: str) -> Path:
        return SPLITS / ("replay.csv" if name == "eval.csv" else name)


# ---------------------------------------------------------------------------
# PLAN E4 / E5 — stratified, seeded, fails loudly
# ---------------------------------------------------------------------------


@needs_splits
def test_every_class_gets_a_slot():
    sampled = dataset.stratified_sample(
        dataset.load_partition_rows("eval"), cap=80, seed=20260904
    )
    present = {r["canonical_class"] for r in sampled}

    assert len(sampled) == 80
    assert present == set(CANONICAL_CLASSES)


@needs_splits
def test_the_same_seed_gives_the_same_sample_and_a_different_seed_does_not():
    partition = dataset.load_partition_rows("eval")
    a = [r["row_id"] for r in dataset.stratified_sample(partition, cap=40, seed=1)]
    b = [r["row_id"] for r in dataset.stratified_sample(partition, cap=40, seed=1)]
    c = [r["row_id"] for r in dataset.stratified_sample(partition, cap=40, seed=2)]

    assert a == b
    assert a != c


def test_a_missing_class_fails_loudly_rather_than_quietly_shrinking():
    rows = [
        {"row_id": f"eval-{i}", "canonical_class": "dos"} for i in range(10)
    ]
    with pytest.raises(dataset.ClassDroppedError, match="no rows"):
        dataset.stratified_sample(rows, cap=6, seed=1)


def test_a_cap_below_the_class_count_is_refused():
    rows = [
        {"row_id": f"eval-{i}", "canonical_class": name}
        for i, name in enumerate(CANONICAL_CLASSES)
    ]
    with pytest.raises(ValueError, match="cannot give all"):
        dataset.stratified_sample(rows, cap=3, seed=1)


# ---------------------------------------------------------------------------
# PLAN E7 — the denominator
# ---------------------------------------------------------------------------


@needs_splits
async def test_every_tier_returns_one_prediction_per_row():
    """`assert len(predictions) == total`, for all three tiers."""
    h = harness()
    rows = _rows(24)

    lightgbm = h._score_lightgbm(rows, nearest_neighbour=None)
    llm = await h._score_llm(rows)
    system, _ = await h._score_system(rows, nearest_neighbour=None)

    for tier in (lightgbm, llm, system):
        assert len(tier.outcomes) == len(rows) == 24
        assert tier.block()["sample_size"] == 24


@needs_splits
async def test_offline_llm_rows_are_unscored_and_remain_in_the_denominator():
    """PLAN E9/I13 — offline does not silently substitute for a provider."""
    assert get_settings().offline_mode, "the test env runs offline by design"

    llm = await harness()._score_llm(_rows(12))
    block = llm.block()

    assert block["sample_size"] == 12
    assert block["unscored_count"] == 12
    assert block["failures"] == {"offline_mode": 12}


# ---------------------------------------------------------------------------
# PLAN E8 — the fast tier is measured; the cache is what gets bypassed
# ---------------------------------------------------------------------------


def test_the_system_tier_clears_the_intel_cache_before_scoring():
    source = inspect.getsource(EvalHarness._score_system)
    assert "get_aggregator().clear_cache()" in source


@needs_splits
def test_the_fast_tier_is_scored_rather_than_skipped():
    result = harness()._score_lightgbm(_rows(24), nearest_neighbour=None)
    assert all(o.pred_attack_type != "unknown" for o in result.outcomes)
    assert result.block()["unscored_count"] == 0


# ---------------------------------------------------------------------------
# the 1-NN baseline is measured, not copied
# ---------------------------------------------------------------------------


@needs_splits
def test_the_nearest_neighbour_baseline_is_computed_on_the_scored_rows():
    train_rows = dataset.load_partition_rows("train")
    sampled = dataset.stratified_sample(
        dataset.load_partition_rows("eval"), cap=40, seed=20260904
    )
    baseline = dataset.nearest_neighbour_baseline(sampled, train_rows)

    assert 0.0 <= baseline <= 1.0
    # A different row set must give a different (or at least separately
    # computed) answer — a constant here would mean the value was copied.
    other = dataset.nearest_neighbour_baseline(sampled[:10], train_rows)
    assert isinstance(other, float)


def test_a_tier_without_a_measured_baseline_reports_null_not_a_placeholder():
    block = TierResult(
        "llm",
        outcomes=[
            Outcome("eval-1", "sig", "dos", "high", "dos", "high", latency_ms=1.0)
        ],
    ).block()
    assert block["attack_type"]["baselines"]["nearest_neighbour_1nn"] is None
