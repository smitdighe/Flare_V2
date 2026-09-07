"""Score retrieval against the committed labelled set. PLAN §4.4.

"Retrieval works" is an assertion until something measures it. This reports
recall@k over `data/retrieval_labels.json` and writes the result next to the
index, so the number ships with the artifact it describes.

recall@k here is: for each labelled alert, did ANY acceptable technique appear
in the top k? Several techniques are legitimately correct for one alert —
a SYN sweep is both T1046 and T1595.001 — so scoring against a single arbitrary
answer would measure agreement with that arbitrary choice rather than retrieval.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.rag.loader import technique_ids
from app.rag.retriever import INDEX_DIR, Retriever, build_query

LABELS_PATH = Path(__file__).resolve().parents[1] / "data" / "retrieval_labels.json"
REPORT_NAME = "RETRIEVAL_REPORT.json"

K_VALUES = (1, 3, 5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, default=LABELS_PATH)
    parser.add_argument("--index-dir", type=Path, default=INDEX_DIR)
    args = parser.parse_args()

    labels: dict[str, Any] = json.loads(args.labels.read_text(encoding="utf-8"))
    pairs: list[dict[str, Any]] = labels["pairs"]

    # A label naming a technique the corpus does not contain is unscoreable and
    # would silently deflate recall. Caught here rather than absorbed.
    available = technique_ids()
    for pair in pairs:
        missing = [t for t in pair["expected"] if t not in available]
        if missing:
            raise SystemExit(
                f"{pair['id']}: expected techniques not in the corpus: {missing}"
            )

    retriever = Retriever(args.index_dir)
    largest = max(K_VALUES)

    rows: list[dict[str, Any]] = []
    for pair in pairs:
        query = build_query(pair["attack_type"], pair["signature"], pair["dest_port"])
        hits = retriever.search(query, top_k=largest)
        ranked = [h.technique_id for h in hits]
        expected = set(pair["expected"])
        first = next((i + 1 for i, t in enumerate(ranked) if t in expected), None)
        rows.append(
            {
                "id": pair["id"],
                "expected": pair["expected"],
                "retrieved": ranked,
                "top_scores": [h.score for h in hits],
                "first_hit_rank": first,
                **{f"hit@{k}": bool(first is not None and first <= k) for k in K_VALUES},
            }
        )

    recall = {
        f"recall@{k}": round(sum(r[f"hit@{k}"] for r in rows) / len(rows), 6)
        for k in K_VALUES
    }
    ranks = [r["first_hit_rank"] for r in rows if r["first_hit_rank"]]
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "attack_version": labels["attack_version"],
        "pairs": len(rows),
        "corpus_techniques": len(available),
        "index_chunks": retriever.chunk_count,
        **recall,
        "mean_reciprocal_rank": round(sum(1 / r for r in ranks) / len(rows), 6),
        "misses_at_5": [r["id"] for r in rows if not r["hit@5"]],
        "results": rows,
    }

    (args.index_dir / REPORT_NAME).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"{len(rows)} labelled alerts over {len(available)} techniques, "
          f"{retriever.chunk_count} chunks")
    for k in K_VALUES:
        print(f"  recall@{k}  {recall[f'recall@{k}']:.4f}")
    print(f"  MRR        {report['mean_reciprocal_rank']:.4f}")
    if report["misses_at_5"]:
        print(f"  misses@5: {report['misses_at_5']}")
    for row in rows:
        mark = "ok " if row["hit@5"] else "MISS"
        print(f"  {mark} {row['id']:<26} rank={row['first_hit_rank']} {row['retrieved'][:3]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
