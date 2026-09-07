"""The eval. PLAN §7 / E1-E17.

**WHAT THIS FILE HAS TO AVOID.** Two prior implementations of this screen were
broken in different ways and both looked fine from the outside. One made its
answer key byte-identical to its classifier's lookup table, so every metric
returned 1.000 at 0.0 ms with zero model calls, deterministically. The other
pasted the ground-truth label into the signature and then put the signature into
the prompt, so 450 of 450 eval prompts contained the answer in plain text —
worse, because it looked rigorous. Neither held anything out.

**THE FOUR STRUCTURAL DEFENCES, in the order they matter:**

1. The ground truth is a partition-stamped file the model has never seen, and
   disjointness is verified at the FEATURE VECTOR, not the row id (§7.3b).
2. `ground_truth_class` is not a field of `PipelineState`. It cannot reach a
   prompt because there is no path from here to there — `initial_state` does not
   copy it and the model would have to be edited to make it possible (I4).
3. The system tier calls `run_pipeline`, the exact function the replay loop
   calls, with the same arguments (E3). Not a shortcut past three of four
   stages.
4. Every tier's denominator is the full sample. A row that failed to classify
   stays in it as `unknown` and drags the number down (E7 / I13), because a
   metric that silently drops its failures is measuring a different population
   than the one it names.

**THE FAST TIER IS MEASURED, NOT BYPASSED** (E8), and that inverts the old rule
deliberately: bypassing was the only honest option when the fast tier was a
hardcoded dict identical to the answer key. A trained model on a held-out
partition is a legitimate subject of measurement. What IS bypassed is the intel
cache, so no verdict is scored as fresh when it was served from a lookup.

**THREE TIERS, SCORED SEPARATELY, ON THE SAME ROWS** (E14/E15). LightGBM alone,
the LLM alone, and the as-shipped system with real routing. The system number is
the headline because it is the only one describing what a user actually gets;
the other two explain it. The system number is EXPECTED to equal LightGBM-alone
to within sampling noise, because the classification gate fires on roughly three
alerts per thousand (§7.3, Band 3) — that is the predicted result, and reporting
it as a win over LightGBM-alone would be the dishonest move.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.eval import guards
from app.eval.dataset import (
    EvalRow,
    exact_feature_overlap,
    load_partition_rows,
    nearest_neighbour_baseline,
    stratified_sample,
    to_eval_rows,
)
from app.eval.pricing import (
    SKIPPED,
    SUCCESS,
    CallRecord,
    aggregate,
    categorize,
)
from app.eval.scoring import (
    Outcome,
    TierResult,
    attack_type_breakdown,
    confusion_matrix,
    high_severity_prf,
    mean_measured,
    misclassified_rows,
)

logger = logging.getLogger("flare.eval")

MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "classifier"

UNKNOWN = "unknown"


class EvalDataError(RuntimeError):
    """The eval cannot run because its inputs are missing or inconsistent."""


@dataclass
class EvalConfig:
    # PLAN E6 / §7.3f — 300, not 80. Set by what the guards need to be able
    # to conclude: 1/80 = 0.0125 cannot express the 0.995 ceiling threshold,
    # so `lightgbm_absolute` and `degenerate:sample` could only ever report
    # INCONCLUSIVE. 1/300 = 0.0033 expresses every threshold in §7.3.
    sample_size: int = 300
    seed: int = 20260904
    # Sequential pacing between LLM-tier calls. Groq's free tier for the
    # classify model is ~30 RPM; 2s keeps an 80-row run inside it without
    # relying on key rotation to absorb a burst.
    llm_pace_seconds: float = 2.0
    score_full_partition: bool = True

    @classmethod
    def from_settings(cls, settings: Settings) -> EvalConfig:
        return cls(
            sample_size=settings.eval_sample_size,
            seed=settings.eval_seed,
            llm_pace_seconds=settings.eval_llm_pace_seconds,
            score_full_partition=settings.eval_score_full_partition,
        )


@dataclass
class EvalHarness:
    settings: Settings
    config: EvalConfig = field(default_factory=EvalConfig)

    # Every prompt the LLM tier constructed, kept so a test can scan them for
    # label strings. This is the direct check on I4: the assertion is not that
    # the code looks careful, it is that the bytes that went to the provider do
    # not contain the answer.
    prompts: list[str] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)

    # -- reference numbers -------------------------------------------------

    def reference_metrics(self) -> dict[str, Any]:
        path = MODEL_DIR / "metrics.json"
        if not path.exists():
            raise EvalDataError(
                f"{path} missing. The committed classifier and its metrics are "
                "evidence, not build artifacts — run `python -m "
                "scripts.train_classifier` to rebuild them."
            )
        return json.loads(path.read_text(encoding="utf-8"))

    # -- the run -----------------------------------------------------------

    async def run(self) -> dict[str, Any]:
        started = time.perf_counter()
        reference = self.reference_metrics()

        eval_partition = load_partition_rows("eval")
        train_partition = load_partition_rows("train")
        sampled = stratified_sample(
            eval_partition, cap=self.config.sample_size, seed=self.config.seed
        )
        rows = to_eval_rows(sampled)

        # PLAN §7.3b / I15 — verified on THESE rows, at the feature level,
        # before anything is scored. An overlap here means the number below is
        # meaningless regardless of what it says.
        overlap = exact_feature_overlap(sampled, train_partition)
        nn_sample = nearest_neighbour_baseline(sampled, train_partition)

        lightgbm = self._score_lightgbm(rows, nearest_neighbour=nn_sample)
        llm = await self._score_llm(rows)
        system, escalation = await self._score_system(rows, nearest_neighbour=nn_sample)

        full_block: dict[str, Any] | None = None
        full_overlap: int | None = None
        if self.config.score_full_partition:
            full_rows = to_eval_rows(eval_partition)
            full_nn = float(
                reference["separability_diagnostics"]["nearest_neighbour_accuracy"]
            )
            full_overlap = int(
                reference["separability_diagnostics"][
                    "exact_feature_duplicates_eval_in_train"
                ]
            )
            full_block = self._score_lightgbm(
                full_rows, nearest_neighbour=full_nn
            ).block()

        findings = self._check_guards(
            lightgbm=lightgbm,
            llm=llm,
            system=system,
            overlap=overlap,
            nn_sample=nn_sample,
            reference=reference,
            full_block=full_block,
            full_overlap=full_overlap,
        )

        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        return self._payload(
            lightgbm=lightgbm,
            llm=llm,
            system=system,
            escalation=escalation,
            findings=findings,
            overlap=overlap,
            nn_sample=nn_sample,
            reference=reference,
            full_block=full_block,
            duration_ms=duration_ms,
        )

    # -- tier 1: the trained model ----------------------------------------

    def _score_lightgbm(
        self, rows: list[EvalRow], *, nearest_neighbour: float | None
    ) -> TierResult:
        """PLAN E8 — measured, not bypassed. No provider, no cache, no network."""
        from app.ml.classifier import get_classifier

        classifier = get_classifier()
        result = TierResult("lightgbm", nearest_neighbour=nearest_neighbour)
        for row in rows:
            started = time.perf_counter()
            prediction = classifier.predict(row.alert)
            elapsed = round((time.perf_counter() - started) * 1000, 3)
            result.outcomes.append(
                Outcome(
                    row_id=row.alert.row_id or row.alert.id,
                    signature=row.alert.signature,
                    true_attack_type=row.true_attack_type,
                    true_severity=row.true_severity,
                    pred_attack_type=prediction.attack_type,
                    pred_severity=prediction.severity,
                    latency_ms=elapsed,
                    failure=None if prediction.scored else "not_scored",
                )
            )
        # PLAN E7 — the denominator is the sample, always.
        assert len(result.outcomes) == len(rows)
        return result

    # -- tier 2: the LLM alone --------------------------------------------

    async def _score_llm(self, rows: list[EvalRow]) -> TierResult:
        """The same model, prompt and parser the escalation path uses.

        Scored on its own so the two tiers can be compared on identical rows
        (E14). This is the tier the leak alarm watches: zero-shot classification
        of six classes from flow statistics does not reach trained-classifier
        territory, so a high number here means the answer reached the prompt.
        """
        from app.agent.graph import initial_state
        from app.agent.prompts import CLASSIFY_SYSTEM, build_classify_prompt
        from app.ingestion.labels import CANONICAL_CLASSES, SEVERITY_ORDER
        from app.providers.base import ProviderError, parse_json_content
        from app.providers.keypool import AllKeysCoolingError, EmptyPoolError
        from app.providers.registry import call_with_rotation, get_registry
        from app.security.sanitize import clamp_enum

        registry = get_registry()
        result = TierResult("llm")

        for index, row in enumerate(rows):
            state = initial_state(row.alert, self.settings)
            prompt = build_classify_prompt(state)
            self.prompts.append(prompt)

            if registry.offline_mode:
                # PLAN E9 — declared, never a silent substitute. The row stays
                # in the denominator as unscored.
                self.calls.append(
                    CallRecord(provider="offline", model=None, outcome=SKIPPED)
                )
                result.outcomes.append(
                    self._outcome(row, UNKNOWN, UNKNOWN, None, failure="offline_mode")
                )
                continue

            if index and self.config.llm_pace_seconds > 0:
                await asyncio.sleep(self.config.llm_pace_seconds)

            started = time.perf_counter()
            try:
                # Bound explicitly: `call_with_rotation` re-invokes this on a
                # 429, and a late-binding closure over the loop variable would
                # retry the NEXT row's prompt while scoring it against this
                # row's answer.
                def issue(text: str = prompt) -> Any:
                    return registry.groq.complete(
                        CLASSIFY_SYSTEM, text, max_tokens=400
                    )

                call = await call_with_rotation(registry.groq_pool, issue)
                parsed = parse_json_content(
                    "groq", call.model, call.content, required=("attack_type", "severity")
                )
            except (ProviderError, AllKeysCoolingError, EmptyPoolError) as exc:
                elapsed = round((time.perf_counter() - started) * 1000, 3)
                category = categorize(exc)
                self.calls.append(
                    CallRecord(
                        provider="groq",
                        model=registry.groq.model,
                        outcome=category,
                        duration_ms=elapsed,
                    )
                )
                # PLAN I13/E7 — a failed call is `unknown` in the denominator,
                # never a dropped row and never a silent default.
                result.outcomes.append(
                    self._outcome(row, UNKNOWN, UNKNOWN, elapsed, failure=category)
                )
                continue

            elapsed = round((time.perf_counter() - started) * 1000, 3)
            self.calls.append(
                CallRecord(
                    provider="groq",
                    model=call.model,
                    outcome=SUCCESS,
                    prompt_tokens=call.prompt_tokens,
                    completion_tokens=call.completion_tokens,
                    duration_ms=call.duration_ms,
                )
            )
            result.outcomes.append(
                self._outcome(
                    row,
                    clamp_enum(parsed.get("attack_type"), CANONICAL_CLASSES, UNKNOWN),
                    clamp_enum(parsed.get("severity"), SEVERITY_ORDER, UNKNOWN),
                    elapsed,
                )
            )

        assert len(result.outcomes) == len(rows)
        return result

    # -- tier 3: the as-shipped system ------------------------------------

    async def _score_system(
        self, rows: list[EvalRow], *, nearest_neighbour: float | None
    ) -> tuple[TierResult, dict[str, Any]]:
        """PLAN E3/E15 — `run_pipeline`, the production entry point, unchanged.

        The intel cache is cleared first (E8). A cached reputation served to the
        enrich node would make an escalation decision on a lookup that did not
        happen during this run, and the run would be scoring a mixture of fresh
        and remembered evidence while reporting it as one number.
        """
        from app.agent.graph import run_pipeline
        from app.intel.aggregator import get_aggregator

        get_aggregator().clear_cache()

        result = TierResult("system", nearest_neighbour=nearest_neighbour)
        escalated_outcomes: list[Outcome] = []
        kept_outcomes: list[Outcome] = []

        for row in rows:
            started = time.perf_counter()
            state = await run_pipeline(row.alert, self.settings)
            elapsed = round((time.perf_counter() - started) * 1000, 3)

            outcome = self._outcome(
                row,
                state.attack_type,
                state.severity,
                elapsed,
                escalated=state.classification_escalated,
            )
            result.outcomes.append(outcome)
            (escalated_outcomes if outcome.escalated else kept_outcomes).append(outcome)

            for entry in state.trace:
                record = self._call_from_trace(entry)
                if record is not None:
                    self.calls.append(record)

        assert len(result.outcomes) == len(rows)

        def accuracy(subset: list[Outcome]) -> float | None:
            if not subset:
                return None
            hits = sum(
                1
                for o in subset
                if o.scored and o.pred_attack_type == o.true_attack_type
            )
            return round(hits / len(subset), 6)

        escalation = {
            "rate": round(len(escalated_outcomes) / len(rows), 6) if rows else 0.0,
            "escalated_count": len(escalated_outcomes),
            "kept_count": len(kept_outcomes),
            "accuracy_escalated": accuracy(escalated_outcomes),
            "accuracy_kept": accuracy(kept_outcomes),
            "threshold": self.settings.escalation_confidence_threshold,
            "note": (
                "PLAN §7.3 Band 3 predicted this. The classification gate fires "
                "on roughly three alerts per thousand because isotonic "
                "calibration on a well-separated problem pushes 99.7% of "
                "confident predictions to exactly 1.0, so on a sample this size "
                "it is expected to fire rarely or not at all. That is the gate "
                "being confident, not the gate being broken — and the reasoning "
                "tier is a SEPARATE gate that is not rare."
            ),
        }
        return result, escalation

    # -- helpers -----------------------------------------------------------

    def _outcome(
        self,
        row: EvalRow,
        attack_type: str,
        severity: str,
        latency_ms: float | None,
        *,
        escalated: bool = False,
        failure: str | None = None,
    ) -> Outcome:
        return Outcome(
            row_id=row.alert.row_id or row.alert.id,
            signature=row.alert.signature,
            true_attack_type=row.true_attack_type,
            true_severity=row.true_severity,
            pred_attack_type=attack_type,
            pred_severity=severity,
            latency_ms=latency_ms,
            escalated=escalated,
            failure=failure,
        )

    def _call_from_trace(self, entry: Any) -> CallRecord | None:
        """A trace entry -> a countable provider call, or None.

        Only entries naming a real provider become records. `lightgbm`,
        `offline`, `pipeline` and the local retriever are work this process did,
        not calls it made — counting them would inflate the success rate with
        things that cannot fail the way a network call fails, and would list
        `finalize` and `0 rules` as models nobody has a price for.
        """
        provider = entry.provider or "unknown"
        if provider not in {"groq", "gemini", "abuseipdb", "virustotal"}:
            return None

        status = str(entry.status)
        if status == "ok":
            outcome = SUCCESS
        elif status == "skipped":
            outcome = SKIPPED
        else:
            outcome = self._category_from_note(entry.note)

        tokens = entry.tokens
        return CallRecord(
            provider=provider,
            model=entry.model,
            outcome=outcome,
            prompt_tokens=tokens.prompt if tokens else 0,
            completion_tokens=tokens.completion if tokens else 0,
            duration_ms=entry.duration_ms,
        )

    @staticmethod
    def _category_from_note(note: str | None) -> str:
        """Recover the failure category the node recorded in its trace note.

        The nodes embed `type(exc).__name__` in the note, so the category is
        recoverable rather than guessed. It is matched explicitly here — an
        unrecognised failure becomes `other_error` and stays visible as a
        failure, never quietly folded into success.
        """
        from app.eval.pricing import (
            EMPTY_CONTENT,
            HTTP_4XX,
            HTTP_5XX,
            OTHER_ERROR,
            POOL_EXHAUSTED,
            RATE_LIMITED,
            TIMEOUT,
        )

        text = note or ""
        if "EmptyContentError" in text:
            return EMPTY_CONTENT
        if "RateLimited" in text:
            return RATE_LIMITED
        if "AllKeysCoolingError" in text or "EmptyPoolError" in text:
            return POOL_EXHAUSTED
        if "ProviderTimeout" in text or "TimeoutError" in text:
            return TIMEOUT
        if "ProviderHTTPError" in text:
            # `ProviderHTTPError` formats itself as "HTTP {code}: {body}", so the
            # status is recoverable rather than guessed. Collapsing 5xx into 4xx
            # would report a provider outage as a malformed request — which is
            # exactly the distinction D36 makes the fallback decision on.
            match = re.search(r"HTTP (\d{3})", text)
            if match:
                return HTTP_4XX if 400 <= int(match.group(1)) < 500 else HTTP_5XX
            return OTHER_ERROR
        return OTHER_ERROR

    # -- guards ------------------------------------------------------------

    def _check_guards(
        self,
        *,
        lightgbm: TierResult,
        llm: TierResult,
        system: TierResult,
        overlap: int,
        nn_sample: float,
        reference: dict[str, Any],
        full_block: dict[str, Any] | None,
        full_overlap: int | None,
    ) -> list[guards.Finding]:
        reference_accuracy = float(
            reference["attack_type_head"]["held_out"]["accuracy"]
        )
        lightgbm_block = lightgbm.block()
        llm_block = llm.block()
        system_block = system.block()

        findings = guards.lightgbm_guards(
            label="sample",
            accuracy=lightgbm_block["attack_type_accuracy"],
            nearest_neighbour=nn_sample,
            exact_feature_duplicates=overlap,
            sample_size=lightgbm_block["sample_size"],
            reference_accuracy=reference_accuracy,
            # §7.3g — the ceiling does not apply to a capped sample. The
            # consistency test against the full-partition measurement does.
            apply_absolute_ceiling=False,
        )

        if full_block is not None and full_overlap is not None:
            # The decisive evaluation. On 1,800 rows a pinned 1.000 cannot hide
            # behind sampling, so the degenerate check concludes here.
            findings += guards.lightgbm_guards(
                label="full_partition",
                accuracy=full_block["attack_type_accuracy"],
                nearest_neighbour=float(
                    reference["separability_diagnostics"]["nearest_neighbour_accuracy"]
                ),
                exact_feature_duplicates=full_overlap,
                sample_size=full_block["sample_size"],
                reference_accuracy=None,
                # The decisive n. The 0.995 ceiling is unchanged and lives here.
                apply_absolute_ceiling=True,
            )

        # An offline run made no provider calls, so the LLM tier scored nothing
        # and its guards would judge a number that describes the absence of a
        # measurement rather than a measurement.
        if llm_block["unscored_count"] < llm_block["sample_size"]:
            findings += guards.llm_guards(
                accuracy=llm_block["attack_type_accuracy"],
                sample_size=llm_block["sample_size"],
            )
            findings += guards.router_guard(
                system_accuracy=system_block["attack_type_accuracy"],
                lightgbm_accuracy=lightgbm_block["attack_type_accuracy"],
            )
        else:
            findings += guards.router_guard(
                system_accuracy=system_block["attack_type_accuracy"],
                lightgbm_accuracy=lightgbm_block["attack_type_accuracy"],
            )
        return findings

    # -- payload -----------------------------------------------------------

    def _payload(
        self,
        *,
        lightgbm: TierResult,
        llm: TierResult,
        system: TierResult,
        escalation: dict[str, Any],
        findings: list[guards.Finding],
        overlap: int,
        nn_sample: float,
        reference: dict[str, Any],
        full_block: dict[str, Any] | None,
        duration_ms: float,
    ) -> dict[str, Any]:
        """CONTRACT EvalPayload. The six scalars are the SYSTEM numbers (Q2)."""
        outcomes = system.outcomes
        system_block = system.block()
        lightgbm_block = lightgbm.block()
        llm_block = llm.block()
        high = high_severity_prf(outcomes)
        rows = misclassified_rows(outcomes)

        offline = bool(self.settings.offline_mode)
        payload: dict[str, Any] = {
            # -- what the frozen screen renders ---------------------------
            "sample_size": len(outcomes),
            "severity_accuracy": system_block["severity_accuracy"],
            "attack_type_accuracy": system_block["attack_type_accuracy"],
            "avg_latency_ms": mean_measured([o.latency_ms for o in outcomes]) or 0.0,
            "high_severity_precision": high["precision"],
            "high_severity_recall": high["recall"],
            "high_severity_f1": high["f1"],
            "confusion_matrix": confusion_matrix(outcomes),
            "attack_type_breakdown": attack_type_breakdown(outcomes),
            "rows": rows,
            "misclassified_count": len(rows),
            "unscored_count": system_block["unscored_count"],
            # -- additive: the API and the README read these --------------
            "baselines": {
                "random": system_block["attack_type"]["baselines"]["random"],
                "majority_class": system_block["attack_type"]["baselines"][
                    "majority_class"
                ],
                "nearest_neighbour_1nn": nn_sample,
            },
            "tiers": {
                "lightgbm": lightgbm_block,
                "llm": llm_block,
                "system": system_block,
            },
            "escalation": escalation,
            "guards": guards.as_payload(findings),
            "guards_tripped": [f.guard for f in guards.tripped(findings)],
            # PLAN §7.3a / §7.3d — a guard band that changed travels with its
            # old value and the reason, so a revision is auditable rather than
            # indistinguishable from a threshold quietly moved to pass.
            "superseded_thresholds": guards.superseded_thresholds(),
            "partition": {
                "eval_rows_available": 1800,
                "sampled": len(outcomes),
                "seed": self.config.seed,
                "exact_feature_overlap_with_train": overlap,
                "disjointness": (
                    "verified on the 77-feature vector, not the row id "
                    "(PLAN §7.3b / I15 as amended)"
                ),
            },
            "usage": aggregate(self.calls),
            "model_version": reference.get("model_version"),
            "offline": offline,
            "duration_ms": duration_ms,
            "generated_at": datetime.now(UTC).isoformat(),
            "run_notice": self._notice(
                offline=offline,
                lightgbm_block=lightgbm_block,
                llm_block=llm_block,
                system_block=system_block,
                escalation=escalation,
                findings=findings,
            ),
        }
        if full_block is not None:
            payload["tiers"]["lightgbm_full_partition"] = full_block
        return payload

    def _notice(
        self,
        *,
        offline: bool,
        lightgbm_block: dict[str, Any],
        llm_block: dict[str, Any],
        system_block: dict[str, Any],
        escalation: dict[str, Any],
        findings: list[guards.Finding],
    ) -> str:
        """PLAN E5/E9 — the seed, what is still non-deterministic, and warnings."""
        parts = [
            f"Seed {self.config.seed}. Sampling and shuffling are deterministic; "
            "the LLM tier is not — provider temperature and server-side variance "
            "mean two runs on the same rows can disagree, so a difference of a "
            "point or two between runs is the provider, not the harness.",
            "Ground truth is data/splits/eval.csv, held out from both training "
            "and replay, verified disjoint at the feature vector.",
            "The six headline tiles are the AS-SHIPPED SYSTEM numbers: real "
            "routing, real escalation, the same run_pipeline the replay loop "
            "calls.",
        ]

        system_attack = system_block["attack_type_accuracy"]
        lightgbm_attack = lightgbm_block["attack_type_accuracy"]
        if abs(system_attack - lightgbm_attack) < 1e-9:
            parts.append(
                f"The system and LightGBM-alone attack-type numbers are identical "
                f"({system_attack:.4f}) and the classification gate fired "
                f"{escalation['escalated_count']} time(s) on {system_block['sample_size']} "
                "rows. PLAN §7.3 Band 3 predicted exactly this: the gate fires on "
                "roughly three alerts per thousand, and three in a thousand cannot "
                "move a headline. It is recorded as equality, not as a win."
            )

        if offline:
            parts.append(
                "WARNING: OFFLINE MODE produced these numbers. No provider was "
                "called, so the LLM tier scored nothing and every row it was "
                "given counts as unscored in its denominator. The system tier "
                "still ran the real graph, but every stage that needed a "
                "provider was skipped and marked degraded. Do not quote the LLM "
                "or system figures from an offline run as measurements of the "
                "shipped system."
            )

        if llm_block["unscored_count"]:
            parts.append(
                f"{llm_block['unscored_count']} of {llm_block['sample_size']} LLM-tier "
                "rows produced no verdict and remain in the denominator as "
                f"unknown (PLAN I13): {llm_block['failures']}."
            )

        for finding in findings:
            if finding.status != guards.TRIPPED:
                parts.append(f"{finding.status.upper()}: {finding.detail}")
        tripped = guards.tripped(findings)
        if tripped:
            parts.append(
                "GUARD BAND TRIPPED — these numbers are not to be quoted until "
                "the finding is adjudicated: "
                + "; ".join(f.detail for f in tripped)
            )
        return " ".join(parts)


async def run_eval(
    settings: Settings | None = None, config: EvalConfig | None = None
) -> dict[str, Any]:
    harness = EvalHarness(settings or get_settings(), config or EvalConfig())
    return await harness.run()
