"""Run the CI checks. PLAN §13.2.

    python -m scripts.ci.run                    # every check
    python -m scripts.ci.run disjointness       # one of them
    python -m scripts.ci.run --json             # machine-readable

Exit code is the number of failing checks, capped at 1 so it reads as a boolean
to a shell — a non-zero exit is a failed build.

**RUNNABLE LOCALLY, IDENTICALLY.** The GitHub Actions workflow calls exactly
this module, so a check cannot pass on a workstation and fail in CI for reasons
that live in the workflow file rather than in the code.
"""

from __future__ import annotations

import argparse
import json
import sys

from scripts.ci.checks import ALL_CHECKS, run_named


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "checks",
        nargs="*",
        default=None,
        help=f"which checks to run (default: all). Known: {', '.join(ALL_CHECKS)}",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    names = args.checks or list(ALL_CHECKS)
    results = run_named(names)

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "name": r.name,
                        "ok": r.ok,
                        "detail": r.detail,
                        "evidence": r.evidence,
                        "artifact": str(r.artifact) if r.artifact else None,
                    }
                    for r in results
                ],
                indent=2,
            )
        )
    else:
        for result in results:
            print(result.line())
            if result.artifact is not None:
                print(f"       artifact: {result.artifact}")

    failed = [r for r in results if not r.ok]
    if failed:
        print(
            f"\n{len(failed)} of {len(results)} check(s) FAILED: "
            + ", ".join(r.name for r in failed),
            file=sys.stderr,
        )
        return 1
    print(f"\nall {len(results)} check(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
