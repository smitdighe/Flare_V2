"""Train the fast-tier LightGBM classifier. PLAN §4.3 / D6 / E16 / I17.

This replaces the fabrication at the centre of the prior codebase's eval story:
its "fast path" was a hardcoded dict identical to its answer key, so bypassing
it was the only honest option. A model trained on a held-out split is a
legitimate subject of measurement, so it is measured.

TWO HEADS, TRAINED AND REPORTED SEPARATELY:

  attack type   multiclass over the classes the partitions actually contain
  severity      ORDINAL, via the Frank & Hall decomposition — K-1 binary
                models for P(y > k), differenced back into class
                probabilities. Multiclass would treat low-vs-critical and
                high-vs-critical as equally wrong; severity has a total order
                (PLAN D27) and the model should know it.

WHAT THE SEVERITY NUMBER IS AND IS NOT. In this dataset severity is a
deterministic function of the attack type (`CLASS_TO_SEVERITY`), not an
independent human judgement. The severity head is therefore an easier problem
than the attack-type head — `dos`, `botnet` and `web_attack` all collapse into
`high`, so confusing them costs nothing — and its accuracy is not independent
evidence. Reported anyway because PLAN §7.3 asks for it, and stated plainly in
the model card so the number cannot be read as more than it is.

FEATURE HYGIENE — the part that decides whether any of this means anything.
The allowlist lives in `app/ml/features.py` and is the SAME module the serving
path imports, so train/serve skew is designed out rather than tested for. The
migration to GeneratedLabelledFlows made this stricter, not looser: the
endpoints are now REAL, and CICIDS2017's topology is fixed — 172.16.0.1 runs
DoS, DDoS and PortScan, 205.174.165.73 is the botnet C2. A source-IP column
would be very close to a direct copy of the label and would score near
perfectly while learning nothing. Every identifier is excluded by allowlist,
which fails closed: a new identifier column appearing upstream is ignored
rather than silently admitted.

CALIBRATION. The router thresholds on the emitted probability, so an
uncalibrated score used as a confidence gate is a fake control. The booster is
fitted on 80% of the training partition and isotonic calibrators on the held-out
20%, which the booster never saw. Calibrators are serialised as their knot
arrays rather than pickled — a pickle is a version-fragile artifact and the
whole point of committing the model is that a cold clone works.

NOTHING HERE IS TUNED TOWARD A BAND. Model selection uses cross-validated
macro-F1 on the training partition only. The eval partition is read exactly
once, at the end, to report.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedKFold

from app.ingestion.labels import CLASS_TO_SEVERITY, SEVERITY_ORDER
from app.ml.features import (
    EXCLUDED_IDENTIFIERS,
    FEATURE_COLUMNS,
    build_matrix,
    schema_fingerprint,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SPLITS_DIR = REPO_ROOT / "data" / "splits"
MODEL_DIR = REPO_ROOT / "models" / "classifier"

SEED = 20260904
MODEL_VERSION = "1.0.0"

# PLAN §7.3 leak guard — see check_leak_guard for why these shapes.
#
# SUPERSEDED: a bare absolute ceiling at 0.98. It was set a priori, before
# anything measured how separable six coarse CICFlowMeter classes actually are,
# and it landed BELOW the no-training 1-NN baseline of 0.9844 — a threshold no
# working model could stay under. It is kept as ABSOLUTE_CEILING_SUPERSEDED so
# the revision is visible in metrics.json rather than quietly deleted.
ABSOLUTE_CEILING_SUPERSEDED = 0.98
RELATIVE_MARGIN_OVER_1NN = 0.05
RELATIVE_GUARD_APPLIES_ABOVE = 0.98
ABSOLUTE_ACCURACY_CEILING = 0.995
EXACT_DUPLICATE_MAXIMUM = 0
DEGENERATE_ACCURACY = 1.0
OFF_DIAGONAL_MINIMUM = 1

# Held out from the booster's fit so the calibrators see scores the booster did
# not train on. 20% of 5,400 is 1,080 rows — enough for isotonic to be stable
# without starving the fit.
CALIBRATION_FRACTION = 0.20

CV_FOLDS = 5

# Deliberately small. A large sweep on 5,400 rows overfits the CV estimate and
# invites tuning toward a number, which is the failure this rewrite exists to
# eliminate.
PARAM_GRID: tuple[dict[str, Any], ...] = (
    {"num_leaves": 15, "learning_rate": 0.10, "n_estimators": 200, "min_child_samples": 20},
    {"num_leaves": 31, "learning_rate": 0.05, "n_estimators": 300, "min_child_samples": 20},
    {"num_leaves": 31, "learning_rate": 0.10, "n_estimators": 200, "min_child_samples": 40},
    {"num_leaves": 63, "learning_rate": 0.05, "n_estimators": 300, "min_child_samples": 10},
)

BASE_PARAMS: dict[str, Any] = {
    "objective": "multiclass",
    "random_state": SEED,
    "deterministic": True,
    "force_row_wise": True,
    "verbose": -1,
    "n_jobs": 1,
}


class PartitionError(ValueError):
    """A row from outside the training partition reached the trainer."""


class LeakGuardTripped(RuntimeError):
    """PLAN §7.3 — a held-out score in memorization territory."""


# ---------------------------------------------------------------------------
# loading, with the structural guard
# ---------------------------------------------------------------------------


def load_partition(name: str, splits_dir: Path = SPLITS_DIR) -> pd.DataFrame:
    """Read one partition and REFUSE anything whose ids say it is another.

    The same guard style as `ReplayEngine.load_replay_rows` and
    `synthesize_signature`: the id is partition-stamped, so a mislabelled file
    is caught here rather than discovered in a suspiciously good metric.
    """
    path = splits_dir / f"{name}.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} missing. Run:\n"
            "  python -m scripts.fetch_dataset --glf-hf --attack-days-only\n"
            "  python -m scripts.build_partitions"
        )

    frame = pd.read_csv(path, low_memory=False)
    prefix = f"{name}-"
    stray = [rid for rid in frame["row_id"].astype(str) if not rid.startswith(prefix)]
    if stray:
        raise PartitionError(
            f"{path.name} contains {len(stray)} row id(s) outside the {name!r} "
            f"partition, first: {stray[0]!r}. Training on eval or replay rows "
            "makes every downstream number meaningless."
        )
    return frame


def assert_no_identifier_columns(frame: pd.DataFrame) -> None:
    """Belt to the allowlist's braces, and it names what it rejected.

    `build_matrix` already selects by allowlist, so an identifier cannot reach
    the model. This asserts the intent separately: if someone later adds
    "Source IP" to FEATURE_COLUMNS, the allowlist stops protecting anything and
    only this check fails.
    """
    admitted = [c for c in EXCLUDED_IDENTIFIERS if c in FEATURE_COLUMNS]
    if admitted:
        raise LeakGuardTripped(
            f"identifier columns are in the feature allowlist: {admitted}. "
            "CICIDS2017's topology is fixed — 172.16.0.1 runs DoS, DDoS and "
            "PortScan — so an endpoint column is close to a copy of the label."
        )
    present_but_unused = [c for c in EXCLUDED_IDENTIFIERS if c in frame.columns]
    print(
        f"  {len(FEATURE_COLUMNS)} features admitted; "
        f"{len(present_but_unused)} identifier column(s) present in the file and "
        f"excluded: {present_but_unused}"
    )


# ---------------------------------------------------------------------------
# calibration, serialised as knots rather than pickled
# ---------------------------------------------------------------------------


@dataclass
class IsotonicKnots:
    x: list[float]
    y: list[float]

    @classmethod
    def fit(cls, scores: np.ndarray, targets: np.ndarray) -> IsotonicKnots:
        model = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        model.fit(scores, targets)
        return cls(x=[float(v) for v in model.X_thresholds_],
                   y=[float(v) for v in model.y_thresholds_])

    def apply(self, scores: np.ndarray) -> np.ndarray:
        return np.interp(scores, self.x, self.y, left=self.y[0], right=self.y[-1])


def calibrate_multiclass(
    raw: np.ndarray, labels: np.ndarray, n_classes: int
) -> list[IsotonicKnots]:
    """One-vs-rest isotonic per class. Renormalised at apply time."""
    return [
        IsotonicKnots.fit(raw[:, index], (labels == index).astype(float))
        for index in range(n_classes)
    ]


def apply_multiclass_calibration(
    raw: np.ndarray, knots: list[IsotonicKnots]
) -> np.ndarray:
    calibrated = np.column_stack([k.apply(raw[:, i]) for i, k in enumerate(knots)])
    total = calibrated.sum(axis=1, keepdims=True)
    # A row where every one-vs-rest calibrator returned zero has no information
    # left to normalise; fall back to uniform rather than dividing by zero.
    uniform = np.full_like(calibrated, 1.0 / calibrated.shape[1])
    return np.where(total > 0, calibrated / np.where(total > 0, total, 1.0), uniform)


# ---------------------------------------------------------------------------
# model selection
# ---------------------------------------------------------------------------


def select_hyperparameters(
    matrix: np.ndarray, labels: np.ndarray, n_classes: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Stratified k-fold on the TRAINING partition only. Selection, not scoring."""
    folds = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=SEED)
    results: list[dict[str, Any]] = []

    for candidate in PARAM_GRID:
        scores: list[float] = []
        for fit_index, held_index in folds.split(matrix, labels):
            model = lgb.LGBMClassifier(
                **BASE_PARAMS, num_class=n_classes, **candidate
            )
            model.fit(matrix[fit_index], labels[fit_index])
            predicted = model.predict(matrix[held_index])
            scores.append(float(f1_score(labels[held_index], predicted, average="macro")))
        results.append(
            {
                "params": candidate,
                "cv_macro_f1_mean": float(np.mean(scores)),
                "cv_macro_f1_std": float(np.std(scores)),
                "cv_macro_f1_folds": [round(s, 6) for s in scores],
            }
        )
        print(
            f"  {candidate} -> macro-F1 {np.mean(scores):.4f} ± {np.std(scores):.4f}"
        )

    best = max(results, key=lambda r: r["cv_macro_f1_mean"])
    return dict(best["params"]), results


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------


def metric_block(
    truth: np.ndarray, predicted: np.ndarray, class_names: list[str]
) -> dict[str, Any]:
    indices = list(range(len(class_names)))
    precision, recall, f1, support = precision_recall_fscore_support(
        truth, predicted, labels=indices, zero_division=0
    )
    matrix = confusion_matrix(truth, predicted, labels=indices)
    return {
        "accuracy": float((truth == predicted).mean()),
        "macro_f1": float(f1_score(truth, predicted, average="macro", zero_division=0)),
        "per_class": {
            name: {
                "precision": round(float(precision[i]), 6),
                "recall": round(float(recall[i]), 6),
                "f1": round(float(f1[i]), 6),
                "support": int(support[i]),
            }
            for i, name in enumerate(class_names)
        },
        "confusion_matrix": {
            "labels": class_names,
            "rows_are_true": True,
            "matrix": matrix.tolist(),
        },
        "baselines": {
            "random": round(1.0 / len(class_names), 6),
            "majority": round(
                float(np.bincount(truth, minlength=len(class_names)).max() / len(truth)),
                6,
            ),
        },
    }


def binary_detection_block(
    truth: np.ndarray, predicted: np.ndarray, benign_index: int
) -> dict[str, Any]:
    """Attack vs benign, collapsed from the attack-type head. PLAN E13."""
    truth_attack = truth != benign_index
    predicted_attack = predicted != benign_index
    precision, recall, f1, _ = precision_recall_fscore_support(
        truth_attack, predicted_attack, average="binary", zero_division=0
    )
    return {
        "accuracy": float((truth_attack == predicted_attack).mean()),
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "f1": round(float(f1), 6),
        "baselines": {
            "random": 0.5,
            "majority": round(
                float(max(truth_attack.mean(), 1 - truth_attack.mean())), 6
            ),
        },
    }


def expected_calibration_error(
    probabilities: np.ndarray, truth: np.ndarray, bins: int = 10
) -> float:
    """Mean |confidence - accuracy| over equal-width confidence bins.

    Reported because "calibrated" is otherwise an assertion. The router gates
    on this probability, so its reliability is a measured property.
    """
    confidence = probabilities.max(axis=1)
    predicted = probabilities.argmax(axis=1)
    correct = (predicted == truth).astype(float)

    edges = np.linspace(0.0, 1.0, bins + 1)
    error = 0.0
    for low, high in itertools.pairwise(edges):
        mask = (confidence > low) & (confidence <= high)
        if not mask.any():
            continue
        error += mask.mean() * abs(correct[mask].mean() - confidence[mask].mean())
    return float(error)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# the two heads
# ---------------------------------------------------------------------------


def train_attack_type_head(
    train: pd.DataFrame, evaluation: pd.DataFrame, class_names: list[str], out_dir: Path
) -> dict[str, Any]:
    index_of = {name: i for i, name in enumerate(class_names)}
    x_train = build_matrix(train)
    y_train = train["canonical_class"].map(index_of).to_numpy(dtype=np.int64)
    x_eval = build_matrix(evaluation)
    y_eval = evaluation["canonical_class"].map(index_of).to_numpy(dtype=np.int64)

    print(f"\nAttack-type head — model selection (train partition, {CV_FOLDS}-fold CV)")
    best_params, cv_results = select_hyperparameters(x_train, y_train, len(class_names))
    print(f"  selected: {best_params}")

    fit_index, calib_index = stratified_holdout(y_train)
    model = lgb.LGBMClassifier(
        **BASE_PARAMS, num_class=len(class_names), **best_params
    )
    model.fit(x_train[fit_index], y_train[fit_index])

    knots = calibrate_multiclass(
        np.asarray(model.predict_proba(x_train[calib_index]), dtype=np.float64),
        y_train[calib_index],
        len(class_names),
    )

    raw_eval = np.asarray(model.predict_proba(x_eval), dtype=np.float64)
    calibrated = apply_multiclass_calibration(raw_eval, knots)
    predicted = calibrated.argmax(axis=1)

    booster_path = out_dir / "attack_type.booster.txt"
    model.booster_.save_model(str(booster_path))

    importance = dict(
        sorted(
            zip(
                FEATURE_COLUMNS,
                (int(v) for v in model.booster_.feature_importance("gain")),
                strict=True,
            ),
            key=lambda kv: kv[1],
            reverse=True,
        )
    )

    return {
        "classes": class_names,
        "hyperparameters": best_params,
        "cross_validation": cv_results,
        "fit_rows": len(fit_index),
        "calibration_rows": len(calib_index),
        "class_weighting": (
            "none — build_partitions.py caps every class at the same count, so "
            "the training partition is exactly balanced at 900 rows per class "
            "and reweighting would only add variance"
        ),
        "held_out": metric_block(y_eval, predicted, class_names),
        "binary_detection": binary_detection_block(y_eval, predicted, index_of["benign"]),
        "router_threshold": router_threshold_sweep(calibrated, y_eval),
        "calibration": {
            "method": "isotonic, one-vs-rest, fitted on a held-out 20% of train",
            "expected_calibration_error_raw": round(
                expected_calibration_error(raw_eval, y_eval), 6
            ),
            "expected_calibration_error_calibrated": round(
                expected_calibration_error(calibrated, y_eval), 6
            ),
            "knots": [{"x": k.x, "y": k.y} for k in knots],
        },
        "feature_importance_gain": importance,
        "booster_sha256": sha256_of(booster_path),
    }


def train_severity_head(
    train: pd.DataFrame, evaluation: pd.DataFrame, out_dir: Path
) -> dict[str, Any]:
    """Frank & Hall ordinal decomposition over `SEVERITY_ORDER`.

    K-1 binary models answer P(severity > k). Differencing them back gives class
    probabilities that respect the order by construction: the model cannot
    assign high probability to `low` and `critical` while starving `medium`.
    """
    order = list(SEVERITY_ORDER)
    rank_of = {name: i for i, name in enumerate(order)}

    x_train = build_matrix(train)
    y_train = (
        train["canonical_class"].map(CLASS_TO_SEVERITY).map(rank_of).to_numpy(np.int64)
    )
    x_eval = build_matrix(evaluation)
    y_eval = (
        evaluation["canonical_class"]
        .map(CLASS_TO_SEVERITY)
        .map(rank_of)
        .to_numpy(np.int64)
    )

    fit_index, calib_index = stratified_holdout(y_train)
    cutoffs = list(range(len(order) - 1))

    thresholds: list[dict[str, Any]] = []
    calibrated_columns: list[np.ndarray] = []

    for cutoff in cutoffs:
        binary_target = (y_train > cutoff).astype(np.int64)
        # Each cutoff splits the four severities unevenly — P(y > low) is 3:1
        # against, P(y > high) is 1:3 — so this head does need reweighting where
        # the attack-type head did not.
        model = lgb.LGBMClassifier(
            **{**BASE_PARAMS, "objective": "binary"},
            num_leaves=31,
            learning_rate=0.05,
            n_estimators=300,
            min_child_samples=20,
            class_weight="balanced",
        )
        model.fit(x_train[fit_index], binary_target[fit_index])

        knot = IsotonicKnots.fit(
            np.asarray(model.predict_proba(x_train[calib_index]), dtype=np.float64)[:, 1],
            binary_target[calib_index].astype(float),
        )
        calibrated_columns.append(
            knot.apply(np.asarray(model.predict_proba(x_eval), dtype=np.float64)[:, 1])
        )

        path = out_dir / f"severity_gt_{order[cutoff]}.booster.txt"
        model.booster_.save_model(str(path))
        thresholds.append(
            {
                "cutoff": f"P(severity > {order[cutoff]})",
                "booster": path.name,
                "booster_sha256": sha256_of(path),
                "knots": {"x": knot.x, "y": knot.y},
            }
        )

    probabilities = ordinal_probabilities(np.column_stack(calibrated_columns))
    predicted = probabilities.argmax(axis=1)

    return {
        "classes": order,
        "decomposition": "Frank & Hall — K-1 cumulative binary models, differenced",
        "class_weighting": (
            "balanced per cutoff — the class->severity map collapses dos, botnet "
            "and web_attack into `high`, so every cutoff is imbalanced even "
            "though the attack-type partition is not"
        ),
        "hyperparameters": {
            "num_leaves": 31,
            "learning_rate": 0.05,
            "n_estimators": 300,
            "min_child_samples": 20,
            "class_weight": "balanced",
        },
        "fit_rows": len(fit_index),
        "calibration_rows": len(calib_index),
        "held_out": metric_block(y_eval, predicted, order),
        "calibration": {
            "method": "isotonic per cutoff, fitted on a held-out 20% of train",
            "expected_calibration_error_calibrated": round(
                expected_calibration_error(probabilities, y_eval), 6
            ),
        },
        "thresholds": thresholds,
        "not_independent_evidence": (
            "Severity is a deterministic function of the attack type in this "
            "dataset (CLASS_TO_SEVERITY), not a separate human judgement. This "
            "head solves an easier problem than the attack-type head because "
            "confusing dos, botnet and web_attack costs nothing here. The "
            "number is real but it is not independent confirmation."
        ),
    }


def ordinal_probabilities(cumulative: np.ndarray) -> np.ndarray:
    """P(y > k) columns -> per-class probabilities.

    Isotonic calibration is monotone per cutoff but nothing forces monotonicity
    ACROSS cutoffs, so a difference can come out slightly negative. Clamped and
    renormalised rather than left to produce a negative probability.
    """
    n_rows, n_cuts = cumulative.shape
    columns = [1.0 - cumulative[:, 0]]
    for k in range(n_cuts - 1):
        columns.append(cumulative[:, k] - cumulative[:, k + 1])
    columns.append(cumulative[:, -1])

    probabilities = np.clip(np.column_stack(columns), 0.0, None)
    total = probabilities.sum(axis=1, keepdims=True)
    uniform = np.full((n_rows, n_cuts + 1), 1.0 / (n_cuts + 1))
    return np.where(total > 0, probabilities / np.where(total > 0, total, 1.0), uniform)


def stratified_holdout(labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Seeded stratified split of the training partition into fit / calibration."""
    folds = StratifiedKFold(
        n_splits=round(1 / CALIBRATION_FRACTION), shuffle=True, random_state=SEED
    )
    fit_index, calib_index = next(iter(folds.split(np.zeros(len(labels)), labels)))
    return fit_index, calib_index


# ---------------------------------------------------------------------------
# guard
# ---------------------------------------------------------------------------


def router_threshold_sweep(
    probabilities: np.ndarray, truth: np.ndarray
) -> dict[str, Any]:
    """What each escalation threshold would actually do. PLAN §22 item 6 / E17.

    The confidence gate is supposed to be set empirically here, not guessed in
    Phase 3. For each candidate this reports the fraction escalated and the
    accuracy on both sides of the gate — E17's question is whether escalation
    fires on the cases the model gets wrong, and only these two numbers answer
    it.
    """
    confidence = probabilities.max(axis=1)
    correct = probabilities.argmax(axis=1) == truth

    rows = []
    for threshold in (0.999, 0.99, 0.95, 0.90, 0.80, 0.50):
        escalated = confidence < threshold
        rows.append(
            {
                "threshold": threshold,
                "escalated_fraction": round(float(escalated.mean()), 6),
                "escalated_count": int(escalated.sum()),
                "accuracy_on_escalated": (
                    round(float(correct[escalated].mean()), 6) if escalated.any() else None
                ),
                "accuracy_on_kept": (
                    round(float(correct[~escalated].mean()), 6) if (~escalated).any() else None
                ),
            }
        )

    return {
        "confidence_distribution": {
            "min": round(float(confidence.min()), 6),
            "median": round(float(np.median(confidence)), 6),
            "mean": round(float(confidence.mean()), 6),
            "saturated_at_one_fraction": round(float((confidence >= 0.99999).mean()), 6),
        },
        "sweep": rows,
        "note": (
            "Isotonic on a well-separated problem pushes most confident "
            "predictions to exactly 1.0, so almost nothing falls below any "
            "threshold. The gate still discriminates — the few rows below it "
            "are where the errors are — but the LLM tier will be nearly idle "
            "on this data, and a demo that depends on visible escalation needs "
            "to know that."
        ),
    }


def separability_diagnostics(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    n_classes: int,
) -> dict[str, Any]:
    """Evidence for adjudicating a leak-guard trip, computed every run.

    A high held-out score has two possible causes and they need different
    responses: the model saw the answer, or the classes are simply far apart.
    Guessing between them is how a leak gets rationalised away, so the run
    produces the evidence itself.

    `nearest_neighbour_accuracy` is the load-bearing number. 1-NN does no
    training and cannot memorise a label it was not given — it only measures
    whether an eval row lands next to same-class train rows. If it is already
    near the booster's score, the geometry is doing the work and the booster is
    not cheating; if it is near chance while the booster is near perfect, the
    booster found something 1-NN cannot see, and that is when to worry.
    """
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.preprocessing import StandardScaler

    filled_train = np.nan_to_num(x_train)
    filled_eval = np.nan_to_num(x_eval)
    scaler = StandardScaler().fit(filled_train)
    neighbour = KNeighborsClassifier(n_neighbors=1).fit(
        scaler.transform(filled_train), y_train
    )

    digest = {hashlib.sha256(row.tobytes()).hexdigest() for row in x_train}
    duplicates = sum(
        1 for row in x_eval if hashlib.sha256(row.tobytes()).hexdigest() in digest
    )

    port_index = FEATURE_COLUMNS.index("Destination Port")
    without_port = lgb.LGBMClassifier(
        **BASE_PARAMS,
        num_class=n_classes,
        num_leaves=15,
        learning_rate=0.10,
        n_estimators=200,
        min_child_samples=20,
    ).fit(np.delete(x_train, port_index, axis=1), y_train)

    return {
        "exact_feature_duplicates_eval_in_train": duplicates,
        "nearest_neighbour_accuracy": round(
            float(neighbour.score(scaler.transform(filled_eval), y_eval)), 6
        ),
        "accuracy_without_destination_port": round(
            float(without_port.score(np.delete(x_eval, port_index, axis=1), y_eval)), 6
        ),
        "interpretation": (
            "1-NN does no training and is given no label at inference, so its "
            "accuracy measures class separation alone. A booster score close to "
            "it means the classes are far apart in CICFlowMeter feature space, "
            "not that the booster memorised anything. The port figure isolates "
            "the one feature that is partly label-correlated by construction."
        ),
    }


def check_leak_guard(
    block: dict[str, Any], diagnostics: dict[str, Any]
) -> list[str]:
    """PLAN §7.3 — is this score the geometry, or is it a leak?

    ADJUDICATED. The original guard was a bare absolute ceiling at 0.98 and it
    tripped on a score that turned out to be honest. The ceiling was a PROXY for
    "the model knows more than it was told"; measuring that directly is strictly
    better, so the proxy is demoted to a backstop and the real test is relative.

    Three signals, ordered by how much they actually prove:

    1. RELATIVE — the load-bearing one. 1-NN does no training and is given no
       label at inference, so its accuracy IS the intrinsic separability of the
       classes in this feature space. A booster sitting just on top of that
       number is reading geometry that was already there. A booster far ABOVE it
       found something the geometry does not contain, and that is what a leak
       looks like. Applied only in high-accuracy territory, because a 5-point
       margin over a 0.60 baseline is just a good model.
    2. EXACT OVERLAP — unconditional, at any accuracy. This is the check that
       caught the real defect: 62 eval rows whose 77-feature vector appeared
       verbatim in train, while id-level disjointness passed. A single shared
       vector means the partition contract is broken, and no accuracy number
       excuses it.
    3. ABSOLUTE — a backstop only. Raised from 0.98 to 0.995 for THIS
       configuration: six coarse classes, balanced at 900 rows each, on
       CICFlowMeter features whose no-training 1-NN baseline is already 0.9844.
       The old 0.98 sat BELOW that baseline, so it could only ever fire.
    """
    tripped: list[str] = []
    accuracy = block["accuracy"]
    baseline = diagnostics["nearest_neighbour_accuracy"]
    margin = accuracy - baseline

    if accuracy > RELATIVE_GUARD_APPLIES_ABOVE and margin > RELATIVE_MARGIN_OVER_1NN:
        tripped.append(
            f"attack-type accuracy {accuracy:.4f} is {margin:.4f} above the "
            f"no-training 1-NN baseline {baseline:.4f}, past the "
            f"{RELATIVE_MARGIN_OVER_1NN:.2f} margin. A model that far above the "
            "geometry it was given is reading something the features do not "
            "contain (PLAN §7.3)"
        )

    duplicates = diagnostics["exact_feature_duplicates_eval_in_train"]
    if duplicates > EXACT_DUPLICATE_MAXIMUM:
        tripped.append(
            f"{duplicates} eval rows have a feature vector that appears verbatim "
            "in train. The partition contract is broken at the feature level "
            "regardless of what the accuracy says (PLAN I15)"
        )

    if accuracy > ABSOLUTE_ACCURACY_CEILING:
        tripped.append(
            f"attack-type accuracy {accuracy:.4f} exceeds the "
            f"{ABSOLUTE_ACCURACY_CEILING} absolute backstop (PLAN §7.3)"
        )

    if accuracy == DEGENERATE_ACCURACY:
        tripped.append("attack-type accuracy is exactly 1.000 — degenerate by construction")

    matrix = np.array(block["confusion_matrix"]["matrix"])
    off_diagonal = int(matrix.sum() - np.trace(matrix))
    if off_diagonal < OFF_DIAGONAL_MINIMUM:
        tripped.append("confusion matrix is a perfect diagonal — no errors at all")

    return tripped


# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--splits-dir", type=Path, default=SPLITS_DIR)
    parser.add_argument("--out-dir", type=Path, default=MODEL_DIR)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    print("Loading partitions ...")
    train = load_partition("train", args.splits_dir)
    evaluation = load_partition("eval", args.splits_dir)
    print(f"  train {len(train):,} rows, eval {len(evaluation):,} rows")
    assert_no_identifier_columns(train)

    # The class list comes from the data, never from a constant that could
    # drift from it.
    class_names = sorted(set(train["canonical_class"]) & set(evaluation["canonical_class"]))
    print(f"  {len(class_names)} classes: {class_names}")

    attack_type = train_attack_type_head(train, evaluation, class_names, args.out_dir)
    severity = train_severity_head(train, evaluation, args.out_dir)

    index_of = {name: i for i, name in enumerate(class_names)}
    print("\nSeparability diagnostics ...")
    diagnostics = separability_diagnostics(
        build_matrix(train),
        train["canonical_class"].map(index_of).to_numpy(dtype=np.int64),
        build_matrix(evaluation),
        evaluation["canonical_class"].map(index_of).to_numpy(dtype=np.int64),
        len(class_names),
    )
    for key, value in diagnostics.items():
        if key != "interpretation":
            print(f"  {key}: {value}")

    # PLAN §7.3 — the 1-NN baseline is a REQUIRED reported metric, not a
    # diagnostic that only surfaces when something trips. Random says what a
    # coin does and majority says what the class prior does; neither says what
    # the FEATURE SPACE does, and on this problem that is the number that
    # explains the score. It lives beside the other two so no reader can quote
    # the accuracy without it.
    attack_type["held_out"]["baselines"]["nearest_neighbour_1nn"] = diagnostics[
        "nearest_neighbour_accuracy"
    ]

    schema_path = args.out_dir / "feature_schema.json"
    schema_path.write_text(
        json.dumps(
            {
                "feature_columns": list(FEATURE_COLUMNS),
                "feature_count": len(FEATURE_COLUMNS),
                "dtype": "float32",
                "fingerprint": schema_fingerprint(),
                "excluded_identifiers": list(EXCLUDED_IDENTIFIERS),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    tripped = check_leak_guard(attack_type["held_out"], diagnostics)

    report = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(UTC).isoformat(),
        "seed": SEED,
        "library": {
            "lightgbm": lgb.__version__,
            "numpy": np.__version__,
            "python": platform.python_version(),
        },
        "train_partition": {
            "rows": len(train),
            "class_counts": {
                str(k): int(v) for k, v in train["canonical_class"].value_counts().items()
            },
        },
        "eval_partition": {
            "rows": len(evaluation),
            "class_counts": {
                str(k): int(v)
                for k, v in evaluation["canonical_class"].value_counts().items()
            },
        },
        "feature_schema_fingerprint": schema_fingerprint(),
        "attack_type_head": attack_type,
        "severity_head": severity,
        "separability_diagnostics": diagnostics,
        "leak_guard": {
            "thresholds": {
                "relative_margin_over_1nn": RELATIVE_MARGIN_OVER_1NN,
                "relative_guard_applies_above": RELATIVE_GUARD_APPLIES_ABOVE,
                "exact_feature_duplicates_maximum": EXACT_DUPLICATE_MAXIMUM,
                "attack_type_accuracy_ceiling": ABSOLUTE_ACCURACY_CEILING,
                "degenerate_accuracy": DEGENERATE_ACCURACY,
                "off_diagonal_minimum": OFF_DIAGONAL_MINIMUM,
            },
            "superseded_thresholds": {
                "attack_type_accuracy_ceiling": ABSOLUTE_CEILING_SUPERSEDED,
                "why": (
                    "Set a priori, below the 0.9844 no-training 1-NN baseline "
                    "for this configuration, so it could only ever fire. "
                    "Replaced by a relative guard against that baseline plus an "
                    "unconditional exact-overlap check; the absolute ceiling "
                    "survives as a backstop at "
                    f"{ABSOLUTE_ACCURACY_CEILING}. PLAN §7.3."
                ),
            },
            "measured": {
                "attack_type_accuracy": attack_type["held_out"]["accuracy"],
                "nearest_neighbour_baseline": diagnostics[
                    "nearest_neighbour_accuracy"
                ],
                "margin_over_baseline": round(
                    attack_type["held_out"]["accuracy"]
                    - diagnostics["nearest_neighbour_accuracy"],
                    6,
                ),
                "exact_feature_duplicates_eval_in_train": diagnostics[
                    "exact_feature_duplicates_eval_in_train"
                ],
            },
            "tripped": tripped,
        },
    }

    metrics_path = args.out_dir / "metrics.json"
    metrics_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n" + "=" * 68)
    at = attack_type["held_out"]
    print(f"HELD-OUT (eval partition, {len(evaluation):,} rows, never seen in training)")
    print(f"  attack type ({len(class_names)} classes)  accuracy {at['accuracy']:.4f}  "
          f"macro-F1 {at['macro_f1']:.4f}  "
          f"(random {at['baselines']['random']:.4f}, "
          f"majority {at['baselines']['majority']:.4f}, "
          f"1-NN {at['baselines']['nearest_neighbour_1nn']:.4f})")
    bd = attack_type["binary_detection"]
    print(f"  binary detection                accuracy {bd['accuracy']:.4f}  "
          f"F1 {bd['f1']:.4f}  (random 0.5000, majority {bd['baselines']['majority']:.4f})")
    sv = severity["held_out"]
    print(f"  severity (4 classes, ordinal)   accuracy {sv['accuracy']:.4f}  "
          f"macro-F1 {sv['macro_f1']:.4f}  "
          f"(random {sv['baselines']['random']:.4f}, majority {sv['baselines']['majority']:.4f})")
    cal = attack_type["calibration"]
    print(f"  ECE raw {cal['expected_calibration_error_raw']:.4f} -> "
          f"calibrated {cal['expected_calibration_error_calibrated']:.4f}")
    print("=" * 68)

    if tripped:
        print("\nLEAK GUARD TRIPPED — PLAN §7.3. This is a bug report, not a result.")
        for line in tripped:
            print(f"  ! {line}")
        print(
            f"\n  Evidence: 1-NN scores "
            f"{diagnostics['nearest_neighbour_accuracy']:.4f} with no training, "
            f"{diagnostics['exact_feature_duplicates_eval_in_train']} exact "
            f"eval->train feature duplicates, "
            f"{diagnostics['accuracy_without_destination_port']:.4f} without "
            "Destination Port. See MODEL_CARD.md."
        )
        print(
            "\nArtifacts were still written so the evidence can be inspected. "
            "Nothing downstream should treat these numbers as a measurement "
            "until the trip has been adjudicated."
        )
        return 1

    print(f"\nWrote {metrics_path}")
    print(f"Wrote {schema_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
