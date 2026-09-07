"""Metric arithmetic. PLAN E7 / E10 / E12 / E13 / §11."""

from app.eval.scoring import (
    MATRIX_LABELS,
    Outcome,
    TierResult,
    attack_type_breakdown,
    binary_block,
    confusion_matrix,
    high_severity_prf,
    mean_measured,
    misclassified_rows,
    severity_block,
)


def outcome(
    true_type: str = "dos",
    pred_type: str | None = None,
    true_sev: str = "high",
    pred_sev: str | None = None,
    latency: float | None = 5.0,
    **kwargs,
) -> Outcome:
    """A correct row by default; pass a prediction to make it wrong.

    The prediction defaults to the truth rather than to a literal, so a test
    that varies only the true class does not accidentally build a wrong row and
    then assert about the wrong thing.
    """
    return Outcome(
        row_id=kwargs.pop("row_id", "eval-1"),
        signature=kwargs.pop("signature", "Flow to TCP/80 - nominal exchange"),
        true_attack_type=true_type,
        true_severity=true_sev,
        pred_attack_type=true_type if pred_type is None else pred_type,
        pred_severity=true_sev if pred_sev is None else pred_sev,
        latency_ms=latency,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# PLAN E7 / I13 — failures stay in the denominator
# ---------------------------------------------------------------------------


def test_a_failed_row_is_unscored_and_stays_in_the_denominator():
    outcomes = [
        outcome(),
        outcome(),
        outcome(pred_type="unknown", pred_sev="unknown", failure="empty_content"),
    ]
    result = TierResult("t", outcomes=outcomes).block()

    assert result["sample_size"] == 3
    assert result["unscored_count"] == 1
    # Two right out of THREE, not out of two.
    assert result["attack_type_accuracy"] == round(2 / 3, 6)
    assert result["severity_accuracy"] == round(2 / 3, 6)
    assert result["failures"] == {"empty_content": 1}


def test_an_unscored_row_is_not_in_the_misclassified_list():
    """CONTRACT §2.4 — the frontend recomputes this list from `rows`.

    An unscored row emitted with `pred_severity: "unknown"` would satisfy the
    client's filter expression and appear in a list the contract says holds
    misclassifications, while `misclassified_count` counted something else.
    """
    outcomes = [
        outcome(pred_type="ddos"),
        outcome(pred_type="unknown", pred_sev="unknown", failure="timeout"),
    ]
    rows = misclassified_rows(outcomes)

    assert len(rows) == 1
    assert rows[0]["pred_attack_type"] == "ddos"
    assert all(r["pred_severity"] != "unknown" for r in rows)


def test_an_unscored_row_stays_in_its_class_breakdown_denominator():
    outcomes = [
        outcome(true_type="botnet"),
        outcome(true_type="botnet", pred_type="unknown", pred_sev="unknown"),
    ]
    breakdown = attack_type_breakdown(outcomes)

    assert breakdown["botnet"] == {"correct": 1, "true_count": 2, "accuracy": 0.5}


def test_a_failed_row_is_never_counted_as_benign():
    """The most flattering bug available: most traffic is benign."""
    outcomes = [
        outcome(true_type="benign", pred_type="unknown", pred_sev="unknown"),
        outcome(true_type="dos", pred_type="unknown", pred_sev="unknown"),
    ]
    block = binary_block(outcomes)

    assert block["accuracy"] == 0.0
    assert block["recall"] == 0.0


# ---------------------------------------------------------------------------
# PLAN E12 — baselines travel with every accuracy
# ---------------------------------------------------------------------------


def test_every_accuracy_carries_its_baselines():
    outcomes = [outcome(true_type="dos")] * 3 + [outcome(true_type="benign")]
    block = TierResult("t", outcomes=outcomes, nearest_neighbour=0.91).block()

    assert block["attack_type"]["baselines"]["random"] == round(1 / 6, 6)
    assert block["attack_type"]["baselines"]["majority_class"] == 0.75
    assert block["attack_type"]["baselines"]["nearest_neighbour_1nn"] == 0.91
    assert block["binary_detection"]["baselines"]["random"] == 0.5
    assert block["severity"]["baselines"]["random"] == 0.25


def test_baselines_are_computed_from_the_rows_not_hardcoded():
    """A majority baseline that does not move with the class mix is a literal."""
    skewed = [outcome(true_type="dos")] * 9 + [outcome(true_type="benign")]
    balanced = [outcome(true_type="dos")] * 5 + [outcome(true_type="benign")] * 5

    assert (
        TierResult("t", outcomes=skewed).block()["attack_type"]["baselines"][
            "majority_class"
        ]
        == 0.9
    )
    assert (
        TierResult("t", outcomes=balanced).block()["attack_type"]["baselines"][
            "majority_class"
        ]
        == 0.5
    )


# ---------------------------------------------------------------------------
# PLAN E13 — three tasks, three numbers
# ---------------------------------------------------------------------------


def test_the_three_tasks_are_scored_separately_and_can_disagree():
    """`dos` called `botnet` is wrong for attack type and RIGHT for both others.

    Both map to `high`, and both are attacks. A single collapsed headline would
    hide exactly this, which is why PLAN E13 asks for three.
    """
    outcomes = [outcome(true_type="dos", pred_type="botnet")] * 4
    block = TierResult("t", outcomes=outcomes).block()

    assert block["attack_type_accuracy"] == 0.0
    assert block["severity_accuracy"] == 1.0
    assert block["binary_detection_accuracy"] == 1.0


# ---------------------------------------------------------------------------
# the matrix
# ---------------------------------------------------------------------------


def test_matrix_is_four_by_four_and_unknown_is_never_an_axis():
    outcomes = [
        outcome(true_sev="critical", pred_sev="critical"),
        outcome(true_sev="high", pred_sev="low"),
        outcome(true_sev="medium", pred_sev="unknown", pred_type="unknown"),
    ]
    matrix = confusion_matrix(outcomes)

    assert matrix["labels"] == list(MATRIX_LABELS) == ["critical", "high", "medium", "low"]
    assert len(matrix["matrix"]) == 4
    assert all(len(row) == 4 for row in matrix["matrix"])
    # The unscored row contributes to no cell.
    assert sum(sum(row) for row in matrix["matrix"]) == 2


def test_matrix_rows_are_actual_and_columns_are_predicted():
    outcomes = [outcome(true_sev="high", pred_sev="low")]
    matrix = confusion_matrix(outcomes)["matrix"]

    high_row = MATRIX_LABELS.index("high")
    low_col = MATRIX_LABELS.index("low")
    assert matrix[high_row][low_col] == 1
    assert matrix[MATRIX_LABELS.index("low")][MATRIX_LABELS.index("high")] == 0


# ---------------------------------------------------------------------------
# PLAN §11 — aggregates exclude non-measurements
# ---------------------------------------------------------------------------


def test_mean_excludes_non_measurements_rather_than_averaging_zeros():
    """The prior build's headline latency was deflated ~2x by exactly this."""
    assert mean_measured([10.0, 20.0, None]) == 15.0
    assert mean_measured([10.0, 20.0, 0.0]) == 10.0
    assert mean_measured([None, None]) is None


def test_high_severity_prf_counts_an_unscored_high_row_as_a_miss():
    outcomes = [
        outcome(true_sev="high", pred_sev="high"),
        outcome(true_sev="high", pred_sev="unknown", pred_type="unknown"),
    ]
    prf = high_severity_prf(outcomes)

    assert prf["precision"] == 1.0
    assert prf["recall"] == 0.5


def test_severity_block_denominator_is_the_whole_sample():
    outcomes = [outcome()] * 3 + [outcome(pred_sev="unknown", pred_type="unknown")]
    assert severity_block(outcomes)["accuracy"] == 0.75
