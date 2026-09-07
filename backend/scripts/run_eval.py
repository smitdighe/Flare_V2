"""Run the held-out eval and cache the result. PLAN §19 step 8.

    python -m scripts.run_eval                 # 80 rows, cached to data/eval
    python -m scripts.run_eval --sample-size 40
    python -m scripts.run_eval --no-full-partition   # skip the 1,800-row block

The demo runbook pre-executes this so the Evaluation panel is never waiting on a
live provider under judging pressure. It is also the honest place to see a guard
band trip: the exit code is non-zero when one does, so a tripped guard is a
failed command rather than a line of output somebody has to notice.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from app.config import Settings, get_settings
from app.eval import cache
from app.eval.harness import EvalConfig, EvalHarness


def bootstrap(settings: Settings) -> None:
    """Load what the app lifespan loads, because this runs outside it.

    The singletons deliberately refuse to self-load on first use — reaching
    inference without an explicit load means startup was bypassed, and the app
    should say so rather than paper over it. A script that wants them has to ask
    for them the same way `app.main` does.
    """
    from app.agent.budget import reset_reason_budget
    from app.intel.aggregator import load_aggregator
    from app.ml.classifier import load_classifier
    from app.providers.registry import load_registry
    from app.rag.retriever import load_retriever

    load_classifier()
    load_retriever()
    load_registry(settings)
    load_aggregator(settings)
    reset_reason_budget(settings.reason_calls_per_minute)


def _line(label: str, block: dict[str, Any]) -> str:
    baselines = block["attack_type"]["baselines"]
    one_nn = baselines.get("nearest_neighbour_1nn")
    floor = f" / 1-NN {one_nn:.4f}" if isinstance(one_nn, int | float) else ""
    return (
        f"  {label:<24} binary {block['binary_detection_accuracy']:.4f}"
        f"  severity {block['severity_accuracy']:.4f}"
        f"  attack-type {block['attack_type_accuracy']:.4f}"
        f"   [random {baselines['random']:.4f}"
        f" / majority {baselines['majority_class']:.4f}{floor}]"
    )


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-size", type=int, default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument(
        "--llm-pace-seconds",
        type=float,
        default=None,
        help="Delay between LLM-tier calls. Groq's free tier is ~30 RPM.",
    )
    parser.add_argument(
        "--no-full-partition",
        action="store_true",
        help="Skip the 1,800-row LightGBM block (the degenerate guard needs it "
        "to be decisive; skipping leaves that check inconclusive).",
    )
    parser.add_argument("--no-cache", action="store_true", help="Do not write the cache.")
    args = parser.parse_args()

    settings = get_settings()
    config = EvalConfig.from_settings(settings)
    if args.sample_size is not None:
        config.sample_size = args.sample_size
    if args.seed is not None:
        config.seed = args.seed
    if args.llm_pace_seconds is not None:
        config.llm_pace_seconds = args.llm_pace_seconds
    if args.no_full_partition:
        config.score_full_partition = False

    print(
        f"eval: {config.sample_size} rows, seed {config.seed}, "
        f"offline={settings.offline_mode}"
    )
    bootstrap(settings)
    harness = EvalHarness(settings, config)
    payload = await harness.run()

    tiers = payload["tiers"]
    print(f"\nsample_size {payload['sample_size']}   "
          f"unscored {payload['unscored_count']}")
    for name in ("lightgbm", "llm", "system", "lightgbm_full_partition"):
        if name in tiers:
            print(_line(name, tiers[name]))

    escalation = payload["escalation"]
    routed = escalation["escalated_count"] + escalation["kept_count"]
    print(
        f"\n  escalation rate {escalation['rate']:.4f} "
        f"({escalation['escalated_count']}/{routed})"
        f"  accuracy escalated={escalation['accuracy_escalated']} "
        f"kept={escalation['accuracy_kept']}"
    )

    usage = payload["usage"]
    print(
        f"\n  provider calls {usage['calls_succeeded']}/{usage['calls_attempted']} "
        f"succeeded  success_rate {usage['success_rate']}"
    )
    print(f"  tokens {usage['prompt_tokens']} in / {usage['completion_tokens']} out")
    if "cost_usd" in usage:
        print(f"  modelled list-price cost ${usage['cost_usd']:.6f} (free tier: $0 spent)")
    else:
        print("  cost: ABSENT — no priced model was called")
    if usage.get("unpriced_models"):
        print(f"  unpriced models: {usage['unpriced_models']}")

    for finding in payload["guards"]:
        print(f"\n  [{finding['status'].upper()}] {finding['guard']}: {finding['detail']}")

    tripped = payload["guards_tripped"]
    if not args.no_cache:
        cache.write(payload)
        print(f"\ncached -> {cache.CACHE_PATH}")

    if tripped:
        print(f"\nGUARD BAND TRIPPED: {tripped}", file=sys.stderr)
        return 1
    print("\nno guard band tripped")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
