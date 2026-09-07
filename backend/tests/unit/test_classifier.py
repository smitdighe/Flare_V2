"""Fast-tier training guards and serving behaviour. PLAN §4.3 / §12 / D25 / I13."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.ingestion.labels import CANONICAL_CLASSES, SEVERITY_ORDER
from app.ingestion.normalize import NormalizedAlert
from app.ml.classifier import (
    SCOREABLE_SOURCES,
    FastTierClassifier,
    ModelLoadError,
    get_classifier,
    load_classifier,
    reset_classifier,
)
from app.ml.features import (
    EXCLUDED_IDENTIFIERS,
    FEATURE_COLUMNS,
    build_matrix,
    build_vector,
    schema_fingerprint,
)

BACKEND = Path(__file__).resolve().parents[2]
MODEL_DIR = BACKEND / "models" / "classifier"
SPLITS = BACKEND / "data" / "splits"

needs_model = pytest.mark.skipif(
    not (MODEL_DIR / "metrics.json").exists(),
    reason="classifier not trained — run scripts.train_classifier",
)
needs_data = pytest.mark.skipif(
    not (SPLITS / "eval.csv").exists(), reason="partitions not built"
)


@pytest.fixture(scope="module")
def classifier() -> FastTierClassifier:
    return FastTierClassifier(MODEL_DIR)


@pytest.fixture(scope="module")
def metrics() -> dict:
    return json.loads((MODEL_DIR / "metrics.json").read_text(encoding="utf-8"))


def _alert(source: str = "cicids_replay", features: dict | None = None) -> NormalizedAlert:
    return NormalizedAlert(
        id="ALT-000000",
        timestamp=datetime.now(UTC),
        source=source,  # type: ignore[arg-type]
        severity="unknown",
        attack_type="unknown",
        src_ip="172.16.0.1",
        dest_ip="192.168.10.50",
        dest_port=80,
        protocol="TCP",
        signature="Flow to TCP/80 — very short exchange",
        features=features if features is not None else dict.fromkeys(FEATURE_COLUMNS, 0.0),
    )


# ---------------------------------------------------------------------------
# feature hygiene — the part that decides whether any of this means anything
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "column", ["Source IP", "Destination IP", "Flow ID", "Timestamp"]
)
def test_named_identifier_is_absent_from_the_trained_feature_set(column: str) -> None:
    """Named one by one so a failure says WHICH identifier leaked.

    CICIDS2017's topology is fixed — 172.16.0.1 runs DoS, DDoS and PortScan,
    205.174.165.73 is the botnet C2 — so an endpoint column is very close to a
    direct copy of the label. The GLF migration made the endpoints real, which
    makes this stricter, not looser.
    """
    assert column in EXCLUDED_IDENTIFIERS, f"{column} is not on the exclusion list"
    assert column not in FEATURE_COLUMNS, f"{column} reached the feature allowlist"


@needs_model
def test_committed_schema_names_the_same_exclusions(metrics: dict) -> None:
    schema = json.loads((MODEL_DIR / "feature_schema.json").read_text(encoding="utf-8"))
    assert schema["feature_columns"] == list(FEATURE_COLUMNS)
    assert schema["fingerprint"] == schema_fingerprint()
    for column in ("Source IP", "Destination IP", "Flow ID", "Timestamp"):
        assert column in schema["excluded_identifiers"]
        assert column not in schema["feature_columns"]


@needs_data
def test_no_metadata_column_can_reach_the_matrix() -> None:
    """build_matrix selects by allowlist, so extra columns are ignored, not admitted."""
    frame = pd.read_csv(SPLITS / "eval.csv", nrows=5, low_memory=False)
    assert "Source IP" in frame.columns, "the fixture must actually contain the identifier"
    assert build_matrix(frame).shape == (5, len(FEATURE_COLUMNS))


# ---------------------------------------------------------------------------
# train/serve parity — the classic silent skew failure
# ---------------------------------------------------------------------------


@needs_data
def test_train_and_serve_builders_produce_byte_identical_vectors() -> None:
    """PLAN §12 4b. Same row, both paths, identical bytes.

    The training script calls build_matrix on a frame; serving calls
    build_vector on one alert's feature dict. They are the same code, and this
    asserts that they stay the same code.
    """
    frame = pd.read_csv(SPLITS / "eval.csv", nrows=10, low_memory=False)
    training = build_matrix(frame)

    for position in range(len(frame)):
        row = frame.iloc[position]
        serving = build_vector({name: float(row[name]) for name in FEATURE_COLUMNS})
        assert serving.dtype == training.dtype == np.float32
        assert training[position].tobytes() == serving[0].tobytes(), (
            f"row {position}: training and serving vectors differ"
        )


# ---------------------------------------------------------------------------
# training guards
# ---------------------------------------------------------------------------


@needs_data
def test_trainer_refuses_a_non_train_partition() -> None:
    """The structural guard, in the same style as ReplayEngine's."""
    from scripts.train_classifier import PartitionError, load_partition

    with pytest.raises(PartitionError, match="outside the 'train' partition"):
        load_partition("train", splits_dir=_MislabelledSplits())


class _MislabelledSplits:
    """A splits dir whose train.csv is really the eval partition."""

    def __truediv__(self, name: str) -> Path:
        return SPLITS / ("eval.csv" if name == "train.csv" else name)


@needs_model
def test_training_used_only_train_partition_ids(metrics: dict) -> None:
    manifest = json.loads((SPLITS / "MANIFEST.json").read_text(encoding="utf-8"))
    assert metrics["train_partition"]["rows"] == manifest["partition_row_counts"]["train"]
    assert metrics["eval_partition"]["rows"] == manifest["partition_row_counts"]["eval"]


@needs_model
def test_classes_come_from_the_data(metrics: dict) -> None:
    trained = set(metrics["attack_type_head"]["classes"])
    assert trained == set(CANONICAL_CLASSES)
    assert set(metrics["severity_head"]["classes"]) == set(SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# calibration
# ---------------------------------------------------------------------------


@needs_model
@needs_data
def test_calibrated_probabilities_are_in_range(classifier: FastTierClassifier) -> None:
    frame = pd.read_csv(SPLITS / "eval.csv", nrows=60, low_memory=False)
    for position in range(len(frame)):
        row = frame.iloc[position]
        alert = _alert(features={name: float(row[name]) for name in FEATURE_COLUMNS})
        prediction = classifier.predict(alert)
        assert prediction.probability is not None
        assert 0.0 <= prediction.probability <= 1.0


@needs_model
def test_isotonic_calibration_is_monotonic(metrics: dict) -> None:
    """A calibrator that is not monotone is not a calibrator.

    Isotonic regression guarantees this by construction; the assertion is that
    the SERIALISED knots preserve it, since they are what serving replays.
    """
    for knots in metrics["attack_type_head"]["calibration"]["knots"]:
        x, y = knots["x"], knots["y"]
        assert x == sorted(x), "knot x values are not ascending"
        assert y == sorted(y), "calibration is not monotonically non-decreasing"
        assert 0.0 <= min(y) and max(y) <= 1.0

    for threshold in metrics["severity_head"]["thresholds"]:
        y = threshold["knots"]["y"]
        assert y == sorted(y)


# ---------------------------------------------------------------------------
# held-out metrics reproduce from the committed artifact
# ---------------------------------------------------------------------------


@needs_model
@needs_data
def test_held_out_accuracy_reproduces_from_the_committed_model(
    classifier: FastTierClassifier, metrics: dict
) -> None:
    """PLAN I17 — the committed artifact must produce the reported number.

    Recomputed through the SERVING path, not the training path, so this also
    catches a serving bug that the training report would never see.
    """
    frame = pd.read_csv(SPLITS / "eval.csv", low_memory=False)
    correct = 0
    for position in range(len(frame)):
        row = frame.iloc[position]
        alert = _alert(features={name: float(row[name]) for name in FEATURE_COLUMNS})
        if classifier.predict(alert).attack_type == row["canonical_class"]:
            correct += 1

    measured = correct / len(frame)
    reported = metrics["attack_type_head"]["held_out"]["accuracy"]
    assert measured == pytest.approx(reported, abs=0.002), (
        f"serving path scores {measured:.4f}, metrics.json reports {reported:.4f}"
    )


@needs_model
def test_leak_guard_state_is_recorded(metrics: dict) -> None:
    """The guard's verdict ships with the model, tripped or not.

    A guard whose result is only ever printed to a terminal is a guard nobody
    can audit later.
    """
    guard = metrics["leak_guard"]
    thresholds = guard["thresholds"]
    accuracy = metrics["attack_type_head"]["held_out"]["accuracy"]
    baseline = metrics["separability_diagnostics"]["nearest_neighbour_accuracy"]
    duplicates = metrics["separability_diagnostics"][
        "exact_feature_duplicates_eval_in_train"
    ]

    # PLAN §7.3a — the guard is RELATIVE now. The absolute ceiling survives only
    # as a backstop, raised to 0.995 because the old 0.98 sat below the
    # no-training 1-NN baseline for this configuration and could only ever fire.
    assert thresholds["attack_type_accuracy_ceiling"] == 0.995
    assert thresholds["relative_margin_over_1nn"] == 0.05
    assert thresholds["exact_feature_duplicates_maximum"] == 0

    # The superseded value is RETAINED, not deleted — a threshold that quietly
    # moved to make a number pass is indistinguishable from one that was
    # adjudicated, unless the old one is still on the record.
    assert guard["superseded_thresholds"]["attack_type_accuracy_ceiling"] == 0.98
    assert guard["superseded_thresholds"]["why"]

    expected_trip = (
        (accuracy > thresholds["relative_guard_applies_above"] and accuracy - baseline > 0.05)
        or duplicates > 0
        or accuracy > 0.995
        or accuracy == 1.0
    )
    assert bool(guard["tripped"]) == expected_trip

    assert duplicates == 0, (
        "an eval row whose feature vector is present in train is memorisation "
        "with the partition check passing"
    )


@needs_model
def test_one_nn_baseline_is_a_reported_baseline(metrics: dict) -> None:
    """PLAN §7.3 — 1-NN sits beside random and majority, not in a footnote.

    Random says what a coin does and majority says what the class prior does.
    Neither says what the FEATURE SPACE does, and on this problem that is the
    number that explains the score. An accuracy quoted without it is
    uninterpretable.
    """
    baselines = metrics["attack_type_head"]["held_out"]["baselines"]
    assert set(baselines) >= {"random", "majority", "nearest_neighbour_1nn"}
    assert (
        baselines["nearest_neighbour_1nn"]
        == metrics["separability_diagnostics"]["nearest_neighbour_accuracy"]
    )


# ---------------------------------------------------------------------------
# serving failure behaviour
# ---------------------------------------------------------------------------


@needs_model
def test_malformed_row_yields_unknown_and_stays_in_the_denominator(
    classifier: FastTierClassifier,
) -> None:
    """PLAN I13 — a failure is counted, never dropped and never defaulted."""
    prediction = classifier.predict(_alert(features={"Destination Port": 80.0}))

    assert prediction.attack_type == "unknown"
    assert prediction.severity == "unknown"
    assert prediction.probability is None
    assert prediction.scored is False
    assert prediction.trace["status"] == "failed"
    assert prediction.trace["provider"] == "lightgbm"
    assert prediction.trace["model"] == classifier.model_version


@needs_model
@pytest.mark.parametrize("source", ["suricata_sample", "live_demo"])
def test_eve_and_live_alerts_are_skipped_with_a_reason(
    classifier: FastTierClassifier, source: str
) -> None:
    """PLAN D25 — an explicit skip, never a silent bypass and never a zero vector."""
    assert source not in SCOREABLE_SOURCES
    prediction = classifier.predict(_alert(source=source))

    assert prediction.trace["status"] == "skipped"
    assert prediction.trace["source"] == source
    assert "no CICIDS flow features" in prediction.trace["reason"]
    assert prediction.attack_type == "unknown"
    assert prediction.probability is None


@needs_model
def test_every_prediction_is_attributed_to_the_tier(
    classifier: FastTierClassifier,
) -> None:
    """PLAN I5 — an analyst can always tell which tier produced a verdict."""
    for source in ("cicids_replay", "suricata_sample"):
        trace = classifier.predict(_alert(source=source)).trace
        assert trace["provider"] == "lightgbm"
        assert trace["model"] == classifier.model_version
        assert trace["stage"] == "classify"


@needs_model
@needs_data
def test_output_is_clamped_to_the_enums(classifier: FastTierClassifier) -> None:
    """The trained model gets no special trust — same clamp as LLM output."""
    frame = pd.read_csv(SPLITS / "eval.csv", nrows=40, low_memory=False)
    allowed_types = set(CANONICAL_CLASSES) | {"unknown"}
    allowed_severities = set(SEVERITY_ORDER) | {"unknown"}

    for position in range(len(frame)):
        row = frame.iloc[position]
        prediction = classifier.predict(
            _alert(features={name: float(row[name]) for name in FEATURE_COLUMNS})
        )
        assert prediction.attack_type in allowed_types
        assert prediction.severity in allowed_severities


def test_missing_model_fails_loudly(tmp_path: Path) -> None:
    """It does NOT fall through to an LLM and does NOT fall through to a default."""
    with pytest.raises(ModelLoadError, match="missing"):
        FastTierClassifier(tmp_path)


@needs_model
def test_corrupt_booster_fails_loudly(tmp_path: Path) -> None:
    for name in ("metrics.json", "attack_type.booster.txt"):
        (tmp_path / name).write_bytes((MODEL_DIR / name).read_bytes())
    for name in ("severity_gt_low", "severity_gt_medium", "severity_gt_high"):
        (tmp_path / f"{name}.booster.txt").write_bytes(
            (MODEL_DIR / f"{name}.booster.txt").read_bytes()
        )

    booster = tmp_path / "attack_type.booster.txt"
    booster.write_text(booster.read_text(encoding="utf-8") + "\ncorrupted\n", encoding="utf-8")

    with pytest.raises(ModelLoadError, match="does not match"):
        FastTierClassifier(tmp_path)


@needs_model
def test_schema_fingerprint_mismatch_fails_at_load(tmp_path: Path) -> None:
    """Wrong column ORDER fails as loudly as a missing column.

    The booster indexes by position, so a reordering silently changes what
    every tree splits on while leaving the column set identical.
    """
    for path in MODEL_DIR.glob("*"):
        if path.is_file():
            (tmp_path / path.name).write_bytes(path.read_bytes())

    metrics_path = tmp_path / "metrics.json"
    payload = json.loads(metrics_path.read_text(encoding="utf-8"))
    payload["feature_schema_fingerprint"] = "0" * 64
    metrics_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ModelLoadError, match="fingerprint mismatch"):
        FastTierClassifier(tmp_path)


@needs_model
def test_singleton_requires_explicit_load() -> None:
    reset_classifier()
    with pytest.raises(ModelLoadError, match="not loaded"):
        get_classifier()
    assert load_classifier(MODEL_DIR) is get_classifier()
