"""Guard bands. PLAN §7.3 / §7.3a.

Each band is exercised twice: once on a synthetic input built to trip it, and
once on the real measured run, which must not. A guard nobody has seen fire is
a guard nobody knows works.
"""

import json
import math
from pathlib import Path

import pytest

from app.eval import guards

METRICS = json.loads(
    (
        Path(__file__).resolve().parents[2] / "models" / "classifier" / "metrics.json"
    ).read_text(encoding="utf-8")
)

REAL_ACCURACY = float(METRICS["attack_type_head"]["held_out"]["accuracy"])
REAL_1NN = float(
    METRICS["separability_diagnostics"]["nearest_neighbour_accuracy"]
)
REAL_OVERLAP = int(
    METRICS["separability_diagnostics"]["exact_feature_duplicates_eval_in_train"]
)
FULL_PARTITION_ROWS = int(METRICS["eval_partition"]["rows"])


def names(findings: list[guards.Finding]) -> list[str]:
    return [f.guard for f in findings]


# ---------------------------------------------------------------------------
# the real run
# ---------------------------------------------------------------------------


def test_the_real_measured_run_trips_nothing():
    """The decisive evaluation: 1,800 rows, the numbers the model card quotes."""
    findings = guards.lightgbm_guards(
        label="full_partition",
        accuracy=REAL_ACCURACY,
        nearest_neighbour=REAL_1NN,
        exact_feature_duplicates=REAL_OVERLAP,
        sample_size=FULL_PARTITION_ROWS,
        reference_accuracy=None,
        apply_absolute_ceiling=True,
    )
    assert guards.tripped(findings) == [], [f.detail for f in findings]


def test_the_real_run_is_evaluated_where_the_ceiling_is_decisive():
    """PLAN 7.3g - 1,800 rows is where the 0.995 ceiling lives, and why.

    Two separate properties, and the second is the one 7.3g added. The
    threshold has to be EXPRESSIBLE (1/1800 = 0.00056 resolves finer than the
    0.005 the guard needs) and it has to DISCRIMINATE - the honest classifier
    must actually be expected to stay under it. At 0.9944 measured, the
    partition sits below 0.995, so a run that exceeds it is a real signal
    rather than an ordinary draw. The old constant asserted only the first.
    """
    assert 1 / FULL_PARTITION_ROWS < 1 - guards.ABSOLUTE_ACCURACY_CEILING
    assert REAL_ACCURACY < guards.ABSOLUTE_ACCURACY_CEILING


# ---------------------------------------------------------------------------
# PLAN §7.3 — the leak alarms
# ---------------------------------------------------------------------------


def test_llm_above_ninety_percent_trips_the_prompt_leak_alarm():
    findings = guards.llm_guards(accuracy=0.94, sample_size=80)
    assert "llm_prompt_leak" in names(guards.tripped(findings))


def test_llm_in_band_does_not_trip():
    findings = guards.llm_guards(accuracy=0.62, sample_size=80)
    assert guards.tripped(findings) == []


def test_llm_suspicion_band_warns_without_tripping():
    findings = guards.llm_guards(accuracy=0.85, sample_size=80)
    assert guards.tripped(findings) == []
    assert any(f.status == guards.WARNING for f in findings)


def test_llm_below_the_floor_trips():
    """PLAN §7.3d — the floor is now 0.18, just above the six-class random
    baseline of 0.1667. What it catches is a chance-level or worse LLM tier: a
    broken parser, a dead provider counted as `unknown`, a class-mapping bug."""
    findings = guards.llm_guards(accuracy=0.15, sample_size=300)
    assert "llm_floor" in names(guards.tripped(findings))


def test_the_measured_llm_accuracy_no_longer_trips_the_floor():
    """The adjudication, asserted rather than described.

    0.20 and 0.24 are the two measured LLM-alone attack-type accuracies (n=80
    and n=300). Both sat below the OLD 0.35 floor, and §7.3d ruled out all four
    of the hypotheses that floor exists to surface. The floor moved to 0.18;
    these numbers are above it and no longer trip.
    """
    for measured in (0.2000, 0.2250, 0.2400):
        findings = guards.llm_guards(accuracy=measured, sample_size=300)
        assert "llm_floor" not in names(guards.tripped(findings)), (
            f"{measured} is a measured value that §7.3d adjudicated as a "
            "finding rather than a bug"
        )


def test_the_floor_still_catches_chance_level_output():
    """The job the floor is left with. 1/6 is what guessing looks like."""
    findings = guards.llm_guards(accuracy=1 / 6, sample_size=300)
    assert "llm_floor" in names(guards.tripped(findings))

    findings = guards.llm_guards(accuracy=0.0, sample_size=300)
    assert "llm_floor" in names(guards.tripped(findings))


def test_the_superseded_floor_travels_with_its_reason():
    """PLAN §7.3a's precedent — a guard band that changed leaves a record.

    Without it, a threshold that moved is indistinguishable from a threshold
    tuned to make a number pass.
    """
    record = guards.superseded_thresholds()["llm_floor"]

    assert record["was"] == 0.35
    assert record["now"] == guards.LLM_FLOOR == 0.18
    assert record["superseded_on"] == "2026-09-06"
    assert record["random_baseline_six_classes"] == pytest.approx(1 / 6, abs=1e-6)
    assert guards.LLM_FLOOR > record["random_baseline_six_classes"], (
        "the floor must sit ABOVE chance or it can never fire"
    )
    # The reason names the EVIDENCE, not just the change.
    why = record["why"]
    assert "0.2000" in why and "0.2250" in why
    assert "PROMPT_FEATURES" in why
    assert "Nothing in the prompt, the feature list or the sample was changed" in why


def test_relative_guard_trips_when_the_model_is_far_above_the_geometry():
    """§7.3a — the load-bearing check. Above 0.98 AND 5+ points over 1-NN."""
    findings = guards.lightgbm_guards(
        label="synthetic",
        accuracy=0.99,
        nearest_neighbour=0.60,
        exact_feature_duplicates=0,
        sample_size=1800,
        reference_accuracy=None,
        apply_absolute_ceiling=True,
    )
    assert "lightgbm_relative:synthetic" in names(guards.tripped(findings))


def test_relative_guard_does_not_trip_on_a_wide_margin_at_ordinary_accuracy():
    """A 5-point margin over a 0.60 baseline is just a good model."""
    findings = guards.lightgbm_guards(
        label="synthetic",
        accuracy=0.80,
        nearest_neighbour=0.60,
        exact_feature_duplicates=0,
        sample_size=1800,
        reference_accuracy=None,
        apply_absolute_ceiling=True,
    )
    assert guards.tripped(findings) == []


def test_feature_overlap_trips_unconditionally_at_any_accuracy():
    """The check that caught the one real defect: 62 shared rows, ids disjoint."""
    for accuracy in (0.55, 0.85, 0.99):
        findings = guards.lightgbm_guards(
            label="synthetic",
            accuracy=accuracy,
            nearest_neighbour=accuracy - 0.01,
            exact_feature_duplicates=1,
            sample_size=1800,
            reference_accuracy=None,
            apply_absolute_ceiling=True,
        )
        assert "feature_overlap:synthetic" in names(guards.tripped(findings))


def test_absolute_backstop_trips_above_the_ceiling_on_a_decisive_sample():
    findings = guards.lightgbm_guards(
        label="full_partition",
        accuracy=0.9985,
        nearest_neighbour=0.9844,
        exact_feature_duplicates=0,
        sample_size=1800,
        reference_accuracy=None,
        apply_absolute_ceiling=True,
    )
    assert "lightgbm_absolute:full_partition" in names(guards.tripped(findings))


def test_the_absolute_ceiling_never_runs_on_a_capped_sample():
    """PLAN 7.3g - the ceiling is a full-partition check and nothing else.

    0.9967 on 300 rows is 299/300, a single error where the measured classifier
    predicts 1.67. It used to trip `lightgbm_absolute:sample`. It must not now,
    and the reason must be that the guard is not evaluated there at all rather
    than that a threshold was loosened.
    """
    findings = guards.lightgbm_guards(
        label="sample",
        accuracy=299 / 300,
        nearest_neighbour=0.986667,
        exact_feature_duplicates=0,
        sample_size=300,
        reference_accuracy=REAL_ACCURACY,
        apply_absolute_ceiling=False,
    )
    assert not [f for f in findings if f.guard.startswith("lightgbm_absolute")]
    assert guards.tripped(findings) == [], [f.detail for f in findings]


def test_the_ceiling_value_itself_did_not_move():
    """The adjudication changed WHERE the check runs, not WHAT it asserts."""
    assert guards.ABSOLUTE_ACCURACY_CEILING == 0.995


# ---------------------------------------------------------------------------
# PLAN 7.3g - the sample-level consistency test that replaced the ceiling
# ---------------------------------------------------------------------------


def test_the_n300_run_is_consistent_with_the_measured_partition():
    """The run that triggered the adjudication. One error, 1.67 expected."""
    finding = guards.consistency_check(
        label="sample",
        accuracy=299 / 300,
        sample_size=300,
        reference_accuracy=REAL_ACCURACY,
    )
    assert finding is None, finding.detail if finding else ""


def test_an_implausibly_clean_sample_trips_the_low_tail():
    """The memorisation signal the ceiling was standing in for.

    A sample large enough that a perfect result is NOT an ordinary draw - the
    low tail is decisive from n=951 at this error rate - scoring perfectly.
    """
    finding = guards.consistency_check(
        label="sample",
        accuracy=1.0,
        sample_size=1200,
        reference_accuracy=REAL_ACCURACY,
    )
    assert finding is not None
    assert finding.status == guards.TRIPPED
    assert finding.guard == "lightgbm_consistency:sample"


def test_a_sample_far_worse_than_the_measurement_trips_the_high_tail():
    """Skew, a stale artifact, or a sampler drawing from the wrong partition."""
    finding = guards.consistency_check(
        label="sample",
        accuracy=0.95,
        sample_size=300,
        reference_accuracy=REAL_ACCURACY,
    )
    assert finding is not None
    assert finding.status == guards.TRIPPED
    assert "above it" in finding.detail


def test_a_perfect_sample_the_low_tail_cannot_judge_is_a_warning_not_a_trip():
    """PLAN 7.3g's own example: zero errors in 300 where 1.67 are expected.

    Worth flagging and NOT worth failing a build over - P(0 errors) is 0.188,
    an ordinary draw. The finding has to carry both the probability and the n
    at which the tail becomes decisive, or the reader cannot check the claim.
    """
    finding = guards.consistency_check(
        label="sample",
        accuracy=1.0,
        sample_size=300,
        reference_accuracy=REAL_ACCURACY,
    )
    assert finding is not None
    assert finding.status == guards.WARNING
    assert "0.188" in finding.detail
    # The n at which the low tail becomes decisive is DERIVED from the measured
    # error rate, not chosen. Recomputed here so the test checks the derivation
    # rather than transcribing its output.
    decisive_n = math.ceil(math.log(0.005) / math.log(REAL_ACCURACY))
    assert decisive_n == 952
    assert f"n >= {decisive_n}" in finding.detail


def test_one_error_where_one_point_seven_are_expected_never_trips():
    """The exact case that was adjudicated. Asserted, not described."""
    findings = guards.lightgbm_guards(
        label="sample",
        accuracy=299 / 300,
        nearest_neighbour=0.986667,
        exact_feature_duplicates=0,
        sample_size=300,
        reference_accuracy=REAL_ACCURACY,
        apply_absolute_ceiling=False,
    )
    assert guards.tripped(findings) == []


def test_the_consistency_interval_is_exact_and_two_sided():
    """The acceptance interval is derived, so it can be recomputed by hand."""
    low, high = guards._binomial_tail_bounds(300, 1 - REAL_ACCURACY, 0.99)
    assert low == 0, "a perfect 300-row sample is an ordinary draw at this rate"
    assert 1 <= high <= 300
    assert guards._at_most_probability(300, 1 - REAL_ACCURACY, 0) == pytest.approx(
        0.188, abs=0.005
    )


def test_the_superseded_ceiling_sample_size_travels_with_its_reason():
    """PLAN 7.3a's precedent again - a design that changed leaves its record."""
    record = guards.superseded_thresholds()["ceiling_decisive_sample_size"]

    assert record["was"] == 201 == guards.CEILING_DECISIVE_SAMPLE_SIZE_SUPERSEDED
    assert record["now"] is None
    assert record["superseded_on"] == "2026-09-06"
    assert record["absolute_ceiling_still_applies_to"] == "full_partition"
    assert record["consistency_confidence"] == guards.CONSISTENCY_CONFIDENCE

    why = record["why"]
    assert "299/300" in why and "1.67 expected errors" in why
    assert "P(<=1 error) ~ 0.50" in why
    assert "0.995 ceiling itself is UNCHANGED" in why


def test_lightgbm_below_the_floor_trips():
    findings = guards.lightgbm_guards(
        label="synthetic",
        accuracy=0.60,
        nearest_neighbour=0.55,
        exact_feature_duplicates=0,
        sample_size=1800,
        reference_accuracy=None,
        apply_absolute_ceiling=True,
    )
    assert "lightgbm_floor:synthetic" in names(guards.tripped(findings))


# ---------------------------------------------------------------------------
# PLAN §7.3 — degenerate
# ---------------------------------------------------------------------------


def test_a_pinned_one_point_zero_on_a_large_sample_trips():
    """HIS's failure mode: 1.000 on 1,800 rows is not sampling."""
    finding = guards.degenerate_check(
        label="full_partition",
        accuracy=1.0,
        sample_size=1800,
        reference_accuracy=REAL_ACCURACY,
    )
    assert finding is not None and finding.status == guards.TRIPPED


def test_one_point_zero_with_no_reference_accuracy_trips():
    finding = guards.degenerate_check(
        label="llm", accuracy=1.0, sample_size=80, reference_accuracy=None
    )
    assert finding is not None and finding.status == guards.TRIPPED


def test_one_point_zero_on_a_small_sample_is_inconclusive_with_its_probability():
    finding = guards.degenerate_check(
        label="sample",
        accuracy=1.0,
        sample_size=80,
        reference_accuracy=REAL_ACCURACY,
    )
    assert finding is not None
    assert finding.status == guards.INCONCLUSIVE
    # 0.9944^80 is about 0.64 — the detail has to carry the number, or the
    # reader has no way to check the claim.
    assert "0.64" in finding.detail


@pytest.mark.parametrize("accuracy", [0.0, 0.5, 0.9944, 0.999])
def test_anything_short_of_one_point_zero_is_not_degenerate(accuracy: float):
    assert (
        guards.degenerate_check(
            label="x", accuracy=accuracy, sample_size=80, reference_accuracy=0.99
        )
        is None
    )


# ---------------------------------------------------------------------------
# PLAN §7.3 / E17 — the router
# ---------------------------------------------------------------------------


def test_router_regression_trips_when_the_system_is_worse_than_the_model():
    findings = guards.router_guard(system_accuracy=0.90, lightgbm_accuracy=0.95)
    assert "router_regression" in names(guards.tripped(findings))


def test_equality_is_the_expected_result_and_does_not_trip():
    """§7.3 Band 3 — the gate fires ~3 times in 1,000, so equality is predicted."""
    assert guards.router_guard(system_accuracy=0.95, lightgbm_accuracy=0.95) == []


def test_the_system_being_better_does_not_trip():
    assert guards.router_guard(system_accuracy=0.97, lightgbm_accuracy=0.95) == []
