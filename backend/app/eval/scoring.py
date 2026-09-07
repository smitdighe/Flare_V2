"""Metric computation. PLAN E7 / E10 / E12 / E13 / §11.

**THREE TASKS, THREE NUMBERS** (E13). Binary detection, severity and attack type
are genuinely different problems with genuinely different difficulty, and one
headline hides more than it shows. A model can be excellent at "is this an
attack" and mediocre at "which of six", and collapsing them reports neither.

**A FAILURE STAYS IN THE DENOMINATOR** (E7 / I13). A row the classifier could
not score is not dropped and is not a fifth class. It counts against accuracy
and it is reported separately as `unscored`, so a run with failures scores below
1.0 by construction — which is the honest result, not a bug to route around.

**BASELINES TRAVEL WITH EVERY ACCURACY** (E12). Random says what a coin does,
majority says what the class prior does. Neither says what the features do,
which is why the 1-NN baseline is carried alongside them for the attack-type
task (§7.3). An accuracy without its baselines is uninterpretable in either
direction, so the shape here makes it impossible to report one without them.

**AGGREGATES EXCLUDE NON-MEASUREMENTS** (§11). A stage that did not run has no
latency, and averaging a literal 0.0 in for it deflates the mean — the prior
codebase's headline classify latency was roughly half its real value for exactly
this reason. `mean_measured` drops `None` rather than coercing it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from app.ingestion.labels import CANONICAL_CLASSES, SEVERITY_ORDER

UNKNOWN = "unknown"

# CONTRACT ConfusionMatrix — exactly these four, in this order. `unknown` is
# never an axis: it is a failure state, not a class the model could be right
# about.
MATRIX_LABELS: tuple[str, ...] = ("critical", "high", "medium", "low")


def mean_measured(values: list[float | None]) -> float | None:
    """PLAN §11 — the mean of what was actually measured, or None."""
    measured = [v for v in values if v is not None]
    if not measured:
        return None
    return round(sum(measured) / len(measured), 3)


@dataclass
class Outcome:
    """One row's truth and one tier's answer for it."""

    row_id: str
    signature: str
    true_attack_type: str
    true_severity: str
    pred_attack_type: str
    pred_severity: str
    latency_ms: float | None = None
    escalated: bool = False
    failure: str | None = None

    @property
    def scored(self) -> bool:
        """False when the tier produced no verdict. Still in the denominator."""
        return self.pred_attack_type != UNKNOWN and self.pred_severity != UNKNOWN


def _accuracy(hits: int, total: int) -> float:
    return round(hits / total, 6) if total else 0.0


def _baselines(truths: list[str], classes: int) -> dict[str, float]:
    counts = Counter(truths)
    majority = max(counts.values()) / len(truths) if truths else 0.0
    return {
        "random": round(1.0 / classes, 6),
        "majority_class": round(majority, 6),
    }


def binary_block(outcomes: list[Outcome]) -> dict[str, Any]:
    """Attack vs benign. A failed row counts as wrong, never as benign.

    Treating an unscored row as `benign` would be the single most flattering
    bug available here — most traffic is benign, so a broken tier would score
    well by failing.
    """
    total = len(outcomes)
    hits = sum(
        1
        for o in outcomes
        if o.scored
        and (o.pred_attack_type != "benign") == (o.true_attack_type != "benign")
    )
    truths = ["attack" if o.true_attack_type != "benign" else "benign" for o in outcomes]

    tp = sum(
        1
        for o in outcomes
        if o.scored and o.pred_attack_type != "benign" and o.true_attack_type != "benign"
    )
    fp = sum(
        1
        for o in outcomes
        if o.scored and o.pred_attack_type != "benign" and o.true_attack_type == "benign"
    )
    fn = sum(
        1
        for o in outcomes
        if o.true_attack_type != "benign"
        and (not o.scored or o.pred_attack_type == "benign")
    )
    precision = round(tp / (tp + fp), 6) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 6) if (tp + fn) else 0.0
    f1 = (
        round(2 * precision * recall / (precision + recall), 6)
        if (precision + recall)
        else 0.0
    )
    return {
        "accuracy": _accuracy(hits, total),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "baselines": _baselines(truths, classes=2),
    }


def severity_block(outcomes: list[Outcome]) -> dict[str, Any]:
    total = len(outcomes)
    hits = sum(1 for o in outcomes if o.scored and o.pred_severity == o.true_severity)
    return {
        "accuracy": _accuracy(hits, total),
        "baselines": _baselines([o.true_severity for o in outcomes], len(SEVERITY_ORDER)),
    }


def attack_type_block(
    outcomes: list[Outcome], *, nearest_neighbour: float | None = None
) -> dict[str, Any]:
    total = len(outcomes)
    hits = sum(
        1 for o in outcomes if o.scored and o.pred_attack_type == o.true_attack_type
    )
    # PLAN §7.3 — 1-NN is a first-class baseline, not a diagnostic. It is what
    # makes a 0.99 interpretable rather than suspicious, so it travels in the
    # same dict as random and majority rather than off to one side.
    baselines: dict[str, float | None] = dict(
        _baselines([o.true_attack_type for o in outcomes], len(CANONICAL_CLASSES))
    )
    baselines["nearest_neighbour_1nn"] = nearest_neighbour
    return {"accuracy": _accuracy(hits, total), "baselines": baselines}


def high_severity_prf(outcomes: list[Outcome]) -> dict[str, float]:
    """Precision / recall / F1 for the `high` class, which the screen renders.

    `high` specifically, not "high and above": the three tiles are labelled HIGH
    and the confusion matrix carries `critical` as its own row. Folding
    `critical` in here would make the tiles describe a class the matrix says is
    a different one.
    """
    tp = sum(
        1
        for o in outcomes
        if o.scored and o.pred_severity == "high" and o.true_severity == "high"
    )
    fp = sum(
        1
        for o in outcomes
        if o.scored and o.pred_severity == "high" and o.true_severity != "high"
    )
    fn = sum(
        1
        for o in outcomes
        if o.true_severity == "high" and (not o.scored or o.pred_severity != "high")
    )
    precision = round(tp / (tp + fp), 6) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 6) if (tp + fn) else 0.0
    f1 = (
        round(2 * precision * recall / (precision + recall), 6)
        if (precision + recall)
        else 0.0
    )
    return {"precision": precision, "recall": recall, "f1": f1}


def confusion_matrix(outcomes: list[Outcome]) -> dict[str, Any]:
    """4x4, rows ACTUAL x cols PREDICTED. `unknown` is never an axis."""
    index = {label: i for i, label in enumerate(MATRIX_LABELS)}
    matrix = [[0] * len(MATRIX_LABELS) for _ in MATRIX_LABELS]
    for outcome in outcomes:
        if not outcome.scored:
            continue
        row = index.get(outcome.true_severity)
        col = index.get(outcome.pred_severity)
        if row is None or col is None:
            continue
        matrix[row][col] += 1
    return {"labels": list(MATRIX_LABELS), "matrix": matrix}


def attack_type_breakdown(outcomes: list[Outcome]) -> dict[str, dict[str, Any]]:
    """Per-class `{correct, true_count, accuracy}`. Denominator is TRUE count.

    An unscored row stays in its class's denominator, so a class the tier could
    not answer for reads below 1.0 rather than vanishing from the breakdown.
    """
    breakdown: dict[str, dict[str, Any]] = {}
    for outcome in outcomes:
        entry = breakdown.setdefault(
            outcome.true_attack_type, {"correct": 0, "true_count": 0, "accuracy": 0.0}
        )
        entry["true_count"] += 1
        if outcome.scored and outcome.pred_attack_type == outcome.true_attack_type:
            entry["correct"] += 1
    for entry in breakdown.values():
        entry["accuracy"] = _accuracy(entry["correct"], entry["true_count"])
    return dict(sorted(breakdown.items()))


def misclassified_rows(outcomes: list[Outcome]) -> list[dict[str, Any]]:
    """The rows the screen lists. UNSCORED ROWS ARE EXCLUDED (I13).

    The frontend recomputes the list client-side as
    `pred_severity !== true_severity || pred_attack_type !== true_attack_type`
    and reads the count from a separate field, so the two definitions have to
    agree exactly or the header and the list disagree on screen. Emitting an
    unscored row with `pred_severity: "unknown"` would satisfy that expression
    and put a failure in a list the contract says holds misclassifications.
    """
    return [
        {
            "signature": o.signature,
            "true_severity": o.true_severity,
            "pred_severity": o.pred_severity,
            "true_attack_type": o.true_attack_type,
            "pred_attack_type": o.pred_attack_type,
        }
        for o in outcomes
        if o.scored
        and (
            o.pred_severity != o.true_severity
            or o.pred_attack_type != o.true_attack_type
        )
    ]


@dataclass
class TierResult:
    """One tier scored on one row set. PLAN E13/E14."""

    name: str
    outcomes: list[Outcome] = field(default_factory=list)
    nearest_neighbour: float | None = None

    def block(self) -> dict[str, Any]:
        total = len(self.outcomes)
        unscored = sum(1 for o in self.outcomes if not o.scored)
        binary = binary_block(self.outcomes)
        severity = severity_block(self.outcomes)
        attack = attack_type_block(
            self.outcomes, nearest_neighbour=self.nearest_neighbour
        )
        return {
            "tier": self.name,
            "sample_size": total,
            "unscored_count": unscored,
            "binary_detection_accuracy": binary["accuracy"],
            "binary_detection": binary,
            "severity_accuracy": severity["accuracy"],
            "severity": severity,
            "attack_type_accuracy": attack["accuracy"],
            "attack_type": attack,
            "avg_latency_ms": mean_measured([o.latency_ms for o in self.outcomes]),
            "high_severity": high_severity_prf(self.outcomes),
            "failures": dict(
                sorted(Counter(o.failure for o in self.outcomes if o.failure).items())
            ),
        }
