"""Guard bands. PLAN §7.3.

A guard here is not a quality gate. It asks one question — *is this number
measuring what it claims to measure* — and it is allowed to stop a run. Nothing
downstream may respond to a trip by moving a threshold; §7.3a records the one
time a threshold did move, what evidence moved it, and the fact that the score
was byte-identical either side.

**THE DEGENERATE CHECK NEEDS A SAMPLE IT CAN CONCLUDE ON, AND THIS IS THE ONE
PLACE THAT SUBTLETY MATTERS.** "Exactly 1.000 is a build failure" was written
against a classifier whose answer key WAS its lookup table: pinned at 1.000
every run, at every sample size, forever. A trained model at 0.9944 scored on 80
sampled rows returns a perfect sample about 64% of the time — 0.9944^80 — so on
a capped sample the bare equality test fires on an honest run more often than
not, and a guard that fires on honest runs teaches people to ignore guards.

The fix is not a softer threshold. It is to run the check where it can conclude:
the LightGBM tier is additionally scored on the FULL 1,800-row eval partition,
where a genuinely pinned 1.000 is impossible to miss (0.9944^1800 is
effectively zero) and where this guard is therefore decisive. On the capped
sample the same check still runs and still reports, but a perfect result that
the reference accuracy fully explains is recorded as INCONCLUSIVE with its
probability, not as a pass and not as a trip. Nothing is tuned; the check is
evaluated where the evidence exists.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

# PLAN §7.3 guard bands. Every one of these is a threshold from the plan, not a
# value chosen here.
LLM_ATTACK_TYPE_CEILING = 0.90
RELATIVE_MARGIN_OVER_1NN = 0.05
RELATIVE_GUARD_APPLIES_ABOVE = 0.98
ABSOLUTE_ACCURACY_CEILING = 0.995
EXACT_DUPLICATE_MAXIMUM = 0
DEGENERATE_ACCURACY = 1.0
LIGHTGBM_FLOOR = 0.75

# PLAN §7.3d — ADJUDICATED 2026-09-06. The floor was wrong and the measurement
# was right.
#
# SUPERSEDED: 0.35. It sat inside Band 2's original 55-75% estimate, so it was
# an assertion that the estimate was correct. The estimate was written before
# anyone had measured a balanced-sampled CICIDS flow with zero cross-flow
# context, and measurement disproved it: 0.2000 and 0.2250 across two runs on
# the same held-out rows, with `unscored_count` 0, no failures, 80/80 calls
# succeeded, every response parsed and clamped, and all fifteen PROMPT_FEATURES
# present in every prompt. All four of the floor's own stated hypotheses —
# under-fed prompt, broken parser, class-mapping bug, silent provider failures —
# were ruled out with evidence (§7.3d). The model is coherently wrong, not
# broken: one flow drawn from a DISTRIBUTED attack carries no evidence of the
# distribution, so a five-packet no-reply DDoS flow reads as benign.
#
# This is the same class of error as the 0.98 ceiling in §7.3a: a number chosen
# a priori as a proxy, calibrated for a different problem than the one built.
# The 0.35 is kept here, and travels on every payload under
# `superseded_thresholds`, so the revision is auditable and cannot be read as a
# threshold quietly moved to make a number pass.
#
# The floor now sits just above the random baseline for six classes (1/6 =
# 0.1667). Its remaining job is the one it can actually do: catch an LLM tier
# producing chance-level or worse output — a broken parser, a dead provider
# counted as `unknown`, a class-mapping bug. NOTHING in the prompt, the feature
# list or the sample was changed; changing any of them after seeing the score
# would be tuning toward an eval number.
LLM_FLOOR_SUPERSEDED = 0.35
LLM_FLOOR_SUPERSEDED_ON = "2026-09-06"
LLM_RANDOM_BASELINE_SIX_CLASSES = 1 / 6
LLM_FLOOR = 0.18

LLM_SUSPICION_BAND = (0.80, 0.90)

# Above this, a perfect sample is an ordinary outcome for a model at the
# reference accuracy and the degenerate check cannot distinguish it from a
# pinned one.
DEGENERATE_INCONCLUSIVE_ABOVE = 0.05

# PLAN §7.3g — ADJUDICATED 2026-09-06. The sample-level ceiling design was
# wrong; the arithmetic that exposed it was right.
#
# SUPERSEDED: CEILING_DECISIVE_SAMPLE_SIZE = 201, and with it the whole idea of
# applying the 0.995 absolute ceiling to a capped sample. The constant was
# derived from EXPRESSIBILITY: accuracy on n rows moves in steps of 1/n, so
# 1/n < 1 - 0.995 requires n > 200 and 201 is the smallest sample on which the
# threshold can be represented at all. Expressible is not DISCRIMINATING. At
# n=300 the only expressible values around the threshold are 299/300 = 0.9967
# and 300/300 = 1.0000, and 299/300 is the single most likely outcome for an
# honest model measured at 0.9944 on the full partition: 300 x 0.005556 = 1.67
# expected errors, and P(<=1 error) ~ 0.50. The guard fired on the n=300 run at
# 0.9967 and about half of all honest 300-row draws from this partition land at
# or above that. A guard that fires on half of correct runs is noise, which is
# the same position the degenerate check was in before §7.3a moved it to a
# sample it could conclude on. Every other signal on that run agreed it was
# clean: relative margin 0.0100 against a 0.05 limit, feature overlap 0,
# degenerate clean, full partition 0.9944 below the ceiling.
#
# THE ABSOLUTE CEILING IS NOT SOFTENED AND IS NOT DELETED. It still applies,
# unchanged at 0.995, to the FULL 1,800-row partition measurement where n makes
# it meaningful. What the sample gets instead is a statistical consistency test
# against that full-partition measurement (`binomial_consistency_check`), which
# asks the question the ceiling was standing in for — is this sample's error
# count consistent with the model we actually measured — and can answer it.
CEILING_DECISIVE_SAMPLE_SIZE_SUPERSEDED = 201
CEILING_SUPERSEDED_ON = "2026-09-06"

# The sample-level consistency test. Two-sided, on the ERROR COUNT, against the
# full-partition error rate. Stated here rather than buried in the function so
# the confidence level is a declared threshold like every other number in this
# module.
CONSISTENCY_CONFIDENCE = 0.99

TRIPPED = "tripped"
INCONCLUSIVE = "inconclusive"
WARNING = "warning"


@dataclass(frozen=True)
class Finding:
    guard: str
    status: str
    detail: str

    def as_payload(self) -> dict[str, str]:
        return {"guard": self.guard, "status": self.status, "detail": self.detail}


def _perfect_sample_probability(reference_accuracy: float, n: int) -> float:
    if n <= 0:
        return 1.0
    return float(reference_accuracy) ** n


def _binomial_tail_bounds(n: int, p_error: float, confidence: float) -> tuple[int, int]:
    """Smallest two-sided acceptance interval on the error COUNT.

    Returns `(low, high)` such that P(k < low) <= alpha/2 and P(k > high) <=
    alpha/2 for k ~ Binomial(n, p_error). Exact, by summation — n here is a few
    hundred to a few thousand, so there is no reason to approximate and every
    reason not to: a normal approximation at n=300 with p=0.0056 is exactly the
    regime where it is worst.

    `low` is 0 whenever even a PERFECT sample is an ordinary draw at this rate,
    which is the honest answer at small n and is reported as such rather than
    hidden behind a bound that cannot fire.
    """
    alpha = (1.0 - confidence) / 2.0
    if n <= 0 or p_error <= 0.0:
        return (0, 0)
    if p_error >= 1.0:
        return (n, n)

    # pmf by the stable recurrence, not math.comb on big factorials.
    pmf = [0.0] * (n + 1)
    pmf[0] = (1.0 - p_error) ** n
    ratio = p_error / (1.0 - p_error)
    for k in range(1, n + 1):
        pmf[k] = pmf[k - 1] * ratio * (n - k + 1) / k

    low = 0
    cumulative = 0.0
    for k in range(0, n + 1):
        if cumulative + pmf[k] > alpha:
            low = k
            break
        cumulative += pmf[k]
    else:  # pragma: no cover - only reachable if the pmf sums under alpha
        low = n

    high = n
    cumulative = 0.0
    for k in range(n, -1, -1):
        if cumulative + pmf[k] > alpha:
            high = k
            break
        cumulative += pmf[k]
    else:  # pragma: no cover
        high = 0

    return (low, high)


def _at_most_probability(n: int, p_error: float, k: int) -> float:
    if n <= 0:
        return 1.0
    if p_error <= 0.0:
        return 1.0
    pmf = (1.0 - p_error) ** n
    total = pmf
    ratio = p_error / (1.0 - p_error)
    for i in range(1, k + 1):
        pmf = pmf * ratio * (n - i + 1) / i
        total += pmf
    return min(total, 1.0)


def consistency_check(
    *,
    label: str,
    accuracy: float,
    sample_size: int,
    reference_accuracy: float,
    confidence: float = CONSISTENCY_CONFIDENCE,
) -> Finding | None:
    """PLAN §7.3g — is this sample's error count consistent with the model we measured?

    This REPLACES the absolute ceiling at the sample level. The ceiling asked
    "is the number high" and answered by comparing a quantity that moves in
    steps of 1/n against a threshold with three decimal places. This asks the
    question the ceiling was standing in for — *does this sample look like it
    came from the classifier we measured on 1,800 rows* — and answers it on the
    error count, where the sampling distribution is exactly known.

    Both tails are findings and they mean different things. Too FEW errors is
    the memorisation signal the ceiling existed to catch. Too MANY is skew, a
    stale artifact, or a sampler that is not drawing from the partition it
    claims. Neither is softened; the interval is exact and the confidence level
    is declared.

    Where the low tail cannot fire at this n — because a perfect sample is
    itself an ordinary draw — the check says so, and a perfect sample is
    reported as a WARNING with its probability rather than passed in silence.
    The n at which the low tail becomes decisive is derived and reported with
    it, which is the number `CEILING_DECISIVE_SAMPLE_SIZE` was reaching for and
    got wrong (§7.3g).
    """
    if sample_size <= 0:
        return None

    p_error = max(0.0, 1.0 - float(reference_accuracy))
    observed_errors = round((1.0 - float(accuracy)) * sample_size)
    expected_errors = p_error * sample_size
    low, high = _binomial_tail_bounds(sample_size, p_error, confidence)

    # The smallest n at which a PERFECT sample is itself outside the interval,
    # i.e. at which the low tail can conclude anything. Derived, not chosen.
    alpha = (1.0 - confidence) / 2.0
    if 0.0 < p_error < 1.0:
        decisive_n = math.ceil(math.log(alpha) / math.log(1.0 - p_error))
    else:  # pragma: no cover - a reference of exactly 1.0 has no error rate
        decisive_n = 0

    context = (
        f"{observed_errors} error(s) on {sample_size} rows against "
        f"{expected_errors:.2f} expected at the full-partition accuracy "
        f"{reference_accuracy:.4f}. The two-sided {confidence:.0%} acceptance "
        f"interval on the error count is [{low}, {high}]"
    )

    if observed_errors < low:
        return Finding(
            f"lightgbm_consistency:{label}",
            TRIPPED,
            f"{context}, and {observed_errors} is below it. The sample is "
            "better than the measured classifier can account for by sampling — "
            "the signature of scoring rows the model has seen (PLAN §7.3g).",
        )
    if observed_errors > high:
        return Finding(
            f"lightgbm_consistency:{label}",
            TRIPPED,
            f"{context}, and {observed_errors} is above it. The sample is worse "
            "than the measured classifier accounts for: a stale artifact, "
            "train/serve skew, or a sampler not drawing from the partition it "
            "names (PLAN §7.3g).",
        )

    if low == 0 and observed_errors == 0 and expected_errors >= 1.0:
        probability = _at_most_probability(sample_size, p_error, 0)
        return Finding(
            f"lightgbm_consistency:{label}",
            WARNING,
            f"{context}. A perfect sample where {expected_errors:.2f} errors "
            f"are expected happens with probability {probability:.3f}, so it is "
            "inside the interval and the low tail cannot trip at this n. Worth "
            f"reading: the low tail becomes decisive at n >= {decisive_n} rows. "
            "The full-partition measurement is the decisive check until then "
            "(PLAN §7.3g).",
        )
    return None


def degenerate_check(
    *,
    label: str,
    accuracy: float,
    sample_size: int,
    reference_accuracy: float | None,
) -> Finding | None:
    """PLAN §7.3 — exactly 1.000 is a build failure, where that can be said.

    With no reference accuracy there is nothing to explain a perfect run with,
    so 1.000 trips outright. That is the right default: the LLM tier has no
    prior claim to perfection and a zero-shot 1.000 is a leak by any reading.
    """
    if accuracy != DEGENERATE_ACCURACY:
        return None

    if reference_accuracy is None:
        return Finding(
            f"degenerate:{label}",
            TRIPPED,
            f"{label} accuracy is exactly 1.000 over {sample_size} rows and "
            "there is no measured reference accuracy that would explain a "
            "perfect run. A pinned 1.000 is the failure mode PLAN §7.1 records.",
        )

    probability = _perfect_sample_probability(reference_accuracy, sample_size)
    if probability > DEGENERATE_INCONCLUSIVE_ABOVE:
        return Finding(
            f"degenerate:{label}",
            INCONCLUSIVE,
            f"{label} accuracy is exactly 1.000 over {sample_size} sampled rows. "
            f"A model at its measured held-out accuracy of {reference_accuracy:.4f} "
            f"returns a perfect sample of this size with probability "
            f"{probability:.3f}, so this result is an ordinary sampling outcome "
            "and the check cannot distinguish it from a pinned one. The same "
            "check on the full 1,800-row partition IS decisive and is reported "
            "separately.",
        )
    return Finding(
        f"degenerate:{label}",
        TRIPPED,
        f"{label} accuracy is exactly 1.000 over {sample_size} rows. A model at "
        f"{reference_accuracy:.4f} would do that with probability "
        f"{probability:.2e} — too unlikely to be sampling. Treat as a build "
        "failure, not a result (PLAN §7.3).",
    )


def lightgbm_guards(
    *,
    label: str,
    accuracy: float,
    nearest_neighbour: float | None,
    exact_feature_duplicates: int,
    sample_size: int,
    reference_accuracy: float | None,
    apply_absolute_ceiling: bool,
) -> list[Finding]:
    """PLAN §7.3 / §7.3a / §7.3g — relative first, overlap unconditional, ceiling on the partition.

    Two of these hold at ANY sample size and one does not, and the difference is
    arithmetic rather than judgement. The exact-overlap check and the floor are
    exact statements about the data: one shared feature vector is one shared
    feature vector on eighty rows or eighteen hundred. The 0.995 absolute
    ceiling is a statement about a quantity that moves in steps of 1/n, and
    §7.3g adjudicated that no capped sample can carry it — not because 0.995 is
    inexpressible below n=201, which was the old and wrong reason, but because
    the values it can express either side of the threshold are BOTH ordinary
    outcomes for the classifier that was actually measured. So the ceiling
    applies where n makes it decisive, on the full 1,800-row partition, and the
    sample is checked for CONSISTENCY with that measurement instead.

    `apply_absolute_ceiling` is explicit at both call sites rather than derived
    from the label, because which check runs where is the whole substance of
    §7.3g and it should not be inferable only by reading a string.
    """
    findings: list[Finding] = []

    if nearest_neighbour is not None:
        margin = accuracy - nearest_neighbour
        if (
            accuracy > RELATIVE_GUARD_APPLIES_ABOVE
            and margin > RELATIVE_MARGIN_OVER_1NN
        ):
            findings.append(
                Finding(
                    f"lightgbm_relative:{label}",
                    TRIPPED,
                    f"attack-type accuracy {accuracy:.4f} is {margin:.4f} above the "
                    f"no-training 1-NN baseline {nearest_neighbour:.4f}, past the "
                    f"{RELATIVE_MARGIN_OVER_1NN:.2f} margin. A model that far above "
                    "the geometry it was handed is reading something the features "
                    "do not contain (PLAN §7.3).",
                )
            )

    # Unconditional, at any accuracy. This is the check that caught the one real
    # defect: 62 shared rows while id-level disjointness passed.
    if exact_feature_duplicates > EXACT_DUPLICATE_MAXIMUM:
        findings.append(
            Finding(
                f"feature_overlap:{label}",
                TRIPPED,
                f"{exact_feature_duplicates} eval rows carry a feature vector that "
                "appears verbatim in train. The partition contract is broken at "
                "the feature level and no accuracy number excuses it (PLAN I15).",
            )
        )

    if apply_absolute_ceiling and accuracy > ABSOLUTE_ACCURACY_CEILING:
        findings.append(
            Finding(
                f"lightgbm_absolute:{label}",
                TRIPPED,
                f"attack-type accuracy {accuracy:.4f} exceeds the "
                f"{ABSOLUTE_ACCURACY_CEILING} absolute backstop over "
                f"{sample_size} rows (PLAN §7.3).",
            )
        )

    if not apply_absolute_ceiling and reference_accuracy is not None:
        # §7.3g — what the sample gets INSTEAD of the ceiling. Not a softer
        # version of it: a different and answerable question.
        consistency = consistency_check(
            label=label,
            accuracy=accuracy,
            sample_size=sample_size,
            reference_accuracy=reference_accuracy,
        )
        if consistency is not None:
            findings.append(consistency)

    if accuracy < LIGHTGBM_FLOOR:
        findings.append(
            Finding(
                f"lightgbm_floor:{label}",
                TRIPPED,
                f"attack-type accuracy {accuracy:.4f} is below the {LIGHTGBM_FLOOR} "
                "floor. Something is wrong with training, features or class "
                "balance — investigate before accepting (PLAN §7.3).",
            )
        )

    degenerate = degenerate_check(
        label=label,
        accuracy=accuracy,
        sample_size=sample_size,
        reference_accuracy=reference_accuracy,
    )
    if degenerate is not None:
        findings.append(degenerate)
    return findings


def llm_guards(*, accuracy: float, sample_size: int) -> list[Finding]:
    """PLAN §7.3 — zero-shot does not reach trained-classifier territory."""
    findings: list[Finding] = []

    if accuracy > LLM_ATTACK_TYPE_CEILING:
        findings.append(
            Finding(
                "llm_prompt_leak",
                TRIPPED,
                f"LLM-alone attack-type accuracy {accuracy:.4f} exceeds "
                f"{LLM_ATTACK_TYPE_CEILING}. Zero-shot classification of six "
                "classes from flow statistics does not reach trained-classifier "
                "territory. Dump the constructed prompts and grep them for label "
                "strings and class names — this is I4, and it is how a prior "
                "build put the answer in 450 of 450 prompts.",
            )
        )
    elif LLM_SUSPICION_BAND[0] <= accuracy <= LLM_SUSPICION_BAND[1]:
        findings.append(
            Finding(
                "llm_suspicion_band",
                WARNING,
                f"LLM-alone attack-type accuracy {accuracy:.4f} is in the "
                f"{LLM_SUSPICION_BAND[0]}-{LLM_SUSPICION_BAND[1]} suspicion band. "
                "Read ten constructed prompts end to end before accepting it.",
            )
        )

    if accuracy < LLM_FLOOR:
        findings.append(
            Finding(
                "llm_floor",
                TRIPPED,
                f"LLM-alone attack-type accuracy {accuracy:.4f} is below the "
                f"{LLM_FLOOR} floor. Likely an under-fed prompt, a broken parser, "
                "a class-mapping bug, or silent provider failures being counted "
                "as `unknown` (PLAN §7.3).",
            )
        )

    degenerate = degenerate_check(
        label="llm",
        accuracy=accuracy,
        sample_size=sample_size,
        reference_accuracy=None,
    )
    if degenerate is not None:
        findings.append(degenerate)
    return findings


def router_guard(*, system_accuracy: float, lightgbm_accuracy: float) -> list[Finding]:
    """PLAN §7.3 — the system must not be worse than the tier it routes from.

    Equality is the EXPECTED result on this data (§7.3, Band 3): the gate fires
    on roughly three alerts in a thousand, and three in a thousand cannot move a
    headline. Only a strict regression is a finding.
    """
    if system_accuracy < lightgbm_accuracy:
        return [
            Finding(
                "router_regression",
                TRIPPED,
                f"as-shipped system attack-type accuracy {system_accuracy:.4f} is "
                f"below LightGBM-alone {lightgbm_accuracy:.4f}. Escalation is "
                "sending the model cases it was getting right; the confidence "
                "threshold is wrong (PLAN §7.3, E17).",
            )
        ]
    return []


def superseded_thresholds() -> dict[str, Any]:
    """Thresholds this module used to hold, with why they moved.

    Mirrors `leak_guard.superseded_thresholds` in `metrics.json` (§7.3a). A
    guard band that changes without leaving a record is indistinguishable from a
    guard band tuned to make a number pass, so the old value ships beside the
    new one on every payload rather than being deleted from the source.
    """
    return {
        "llm_floor": {
            "was": LLM_FLOOR_SUPERSEDED,
            "now": LLM_FLOOR,
            "superseded_on": LLM_FLOOR_SUPERSEDED_ON,
            "why": (
                "Set inside Band 2's original 55-75% estimate, which was written "
                "before anything measured a balanced-sampled CICIDS flow with zero "
                "cross-flow context. Measurement disproved the estimate: 0.2000 and "
                "0.2250 across two runs on the same held-out rows, with zero unscored "
                "rows, zero failures, 80/80 provider calls succeeded, every response "
                "parsed and enum-clamped, and all fifteen PROMPT_FEATURES present in "
                "every prompt. All four hypotheses the floor exists to surface were "
                "ruled out with evidence (PLAN §7.3d). The floor now sits just above "
                "the 0.1667 six-class random baseline so it still catches a "
                "chance-level or broken LLM tier. Nothing in the prompt, the feature "
                "list or the sample was changed to raise the score."
            ),
            "random_baseline_six_classes": round(
                LLM_RANDOM_BASELINE_SIX_CLASSES, 6
            ),
        },
        "ceiling_decisive_sample_size": {
            "was": CEILING_DECISIVE_SAMPLE_SIZE_SUPERSEDED,
            "now": None,
            "superseded_on": CEILING_SUPERSEDED_ON,
            "replaced_by": "lightgbm_consistency (binomial, two-sided)",
            "why": (
                "The constant conflated EXPRESSIBLE with DISCRIMINATING. It was "
                "derived from 1/n < 1 - 0.995, which makes 201 the smallest sample "
                "on which a 0.995 threshold can be represented at all — and "
                "representable is not the same as able to separate the two "
                "hypotheses the guard exists to separate. At n=300 the expressible "
                "values around the threshold are 299/300 = 0.9967 and 300/300 = "
                "1.0000, and 299/300 is the MOST LIKELY single outcome for a "
                "classifier measured at 0.9944 on the full partition: 300 x 0.005556 "
                "= 1.67 expected errors, P(<=1 error) ~ 0.50. The guard fired on the "
                "n=300 run at 0.9967 while the relative margin (0.0100 against a 0.05 "
                "limit), the unconditional feature-overlap check (0 shared vectors), "
                "the degenerate check and the full-partition ceiling (0.9944 < 0.995) "
                "all reported clean. A guard that fires on about half of honest runs "
                "is noise. The 0.995 ceiling itself is UNCHANGED and still applies to "
                "the full 1,800-row partition, where n makes it decisive; the sample "
                "is now checked with a two-sided exact binomial consistency test on "
                "the error count against that full-partition measurement, at "
                f"{CONSISTENCY_CONFIDENCE:.0%} confidence. Nothing about the model, "
                "the sample, the features or the 0.995 value was changed in response "
                "to the trip (PLAN §7.3g)."
            ),
            "consistency_confidence": CONSISTENCY_CONFIDENCE,
            "absolute_ceiling_still_applies_to": "full_partition",
        },
    }


def tripped(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.status == TRIPPED]


def as_payload(findings: list[Finding]) -> list[dict[str, Any]]:
    return [f.as_payload() for f in findings]
