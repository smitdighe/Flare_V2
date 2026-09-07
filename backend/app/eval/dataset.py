"""The eval partition, sampled. PLAN E1 / E4 / E5 / E12 / §7.3b.

**THE GROUND TRUTH IS A FILE, AND IT IS NOT THE CLASSIFIER.** One prior repo's
answer key was byte-identical to its classifier's lookup table, so every metric
returned 1.000 at 0.0 ms with zero model calls, by construction. The answer key
here is `data/splits/eval.csv` — 1,800 rows the model never saw, partition-
stamped, and read through the same guard style the replay engine uses: a row id
that does not start with `eval-` stops the run.

**DISJOINTNESS IS CHECKED AT THE FEATURE VECTOR, NOT THE ID** (§7.3b, I15 as
amended). Ids hash Flow ID and the endpoints, so two flows with byte-identical
statistics get different ids and would pass an id-level check while being the
same row to a classifier that sees neither. That is not hypothetical: it is the
defect the Phase 2a guard caught, 62 rows deep.

**THE 1-NN BASELINE IS COMPUTED HERE, NOT COPIED.** `metrics.json` records one
for the full partition; a sample needs its own, because a baseline quoted
against a different row set explains nothing about this run. 1-NN fits nothing
and is given no label at inference, so its accuracy is the intrinsic
separability of the classes in the feature space the model was handed — the
number that says whether a high score is the geometry or a leak.
"""

from __future__ import annotations

import csv
import hashlib
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np

from app.ingestion.labels import CANONICAL_CLASSES
from app.ingestion.normalize import NormalizedAlert, parse_cicids_row
from app.ml.features import FEATURE_COLUMNS

REPO_ROOT = Path(__file__).resolve().parents[2]
SPLITS_DIR = REPO_ROOT / "data" / "splits"


class PartitionError(ValueError):
    """A non-eval partition was handed to the eval harness (PLAN I15)."""


class ClassDroppedError(ValueError):
    """PLAN E4 — a class fell out of the sample. Fail loudly, never silently."""


def load_partition_rows(name: str, splits_dir: Path = SPLITS_DIR) -> list[dict[str, Any]]:
    """Read one partition and REFUSE anything whose ids say it is another."""
    path = splits_dir / f"{name}.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} missing. Run:\n"
            "  python -m scripts.fetch_dataset --glf-hf --attack-days-only\n"
            "  python -m scripts.build_partitions"
        )
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    prefix = f"{name}-"
    for row in rows:
        row_id = str(row.get("row_id", ""))
        if not row_id.startswith(prefix):
            raise PartitionError(
                f"{path.name} contains a row id outside the {name!r} partition: "
                f"{row_id!r}. Scoring against the wrong partition makes every "
                "number below it meaningless."
            )
    return rows


def stratified_sample(
    rows: list[dict[str, Any]], *, cap: int, seed: int
) -> list[dict[str, Any]]:
    """PLAN E4 / E5 — every class gets a slot, then proportional, seeded.

    A plain random sample of 80 rows from six classes will usually contain all
    six, and "usually" is not a property worth relying on: a run that silently
    scored five classes would report a per-class breakdown with a hole in it and
    an accuracy computed over a population that is not the one described. Each
    class is given one slot first, the remainder is allocated proportionally,
    and a class that still ends up empty stops the run.
    """
    by_class: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_class.setdefault(str(row.get("canonical_class") or ""), []).append(row)

    present = [c for c in CANONICAL_CLASSES if by_class.get(c)]
    missing = [c for c in CANONICAL_CLASSES if not by_class.get(c)]
    if missing:
        raise ClassDroppedError(
            f"the eval partition contains no rows for {missing}. The partition "
            "does not describe the class list the model was trained on."
        )
    if cap < len(present):
        raise ValueError(
            f"cap={cap} cannot give all {len(present)} classes a slot (PLAN E4)"
        )

    # S311: a seeded PRNG is the POINT here (PLAN E5). A cryptographic source
    # would make the sample unreproducible, which is the property being bought.
    rng = random.Random(seed)  # noqa: S311
    quotas = dict.fromkeys(present, 1)
    remaining = cap - len(present)
    total = sum(len(by_class[c]) for c in present)
    for name in present:
        quotas[name] += int(remaining * len(by_class[name]) / total)

    # Integer division leaves a few slots unallocated; hand them out in a
    # deterministic order so the same seed produces the same sample.
    leftover = cap - sum(quotas.values())
    for index in range(leftover):
        quotas[present[index % len(present)]] += 1

    sample: list[dict[str, Any]] = []
    for name in present:
        pool = sorted(by_class[name], key=lambda r: str(r.get("row_id", "")))
        take = min(quotas[name], len(pool))
        if take <= 0:
            raise ClassDroppedError(
                f"class {name!r} received no slot in the sample (PLAN E4)"
            )
        sample.extend(rng.sample(pool, take))

    sampled_classes = {str(r.get("canonical_class")) for r in sample}
    dropped = [c for c in present if c not in sampled_classes]
    if dropped:
        raise ClassDroppedError(
            f"classes {dropped} dropped out of the sample despite having rows "
            "(PLAN E4). The sampler is wrong, not the data."
        )

    rng.shuffle(sample)
    return sample


@dataclass(frozen=True)
class EvalRow:
    """One scored row: the alert the pipeline sees, and the answer it does not.

    `alert` carries `ground_truth_class`, and that field is never copied into
    `PipelineState` — `initial_state` does not read it and it is not a field of
    that model at all (PLAN I4). The truth lives here, beside the prediction,
    and reaches the model through no path.
    """

    alert: NormalizedAlert
    true_attack_type: str
    true_severity: str
    features: np.ndarray


#: PLAN I15 as extended by D24 — the ONLY source an eval may score.
#:
#: `suricata_sample` and `live_demo` carry no ground truth by construction, so
#: a scored set containing either is scoring a row against a label that does
#: not exist. Before Phase 4a this was enforced only by the partition files
#: happening to be clean; the live path made unlabelled alerts a real thing in
#: the running system, so it is enforced HERE, on the path that builds scored
#: rows, and asserted by an invariant test.
SCORABLE_SOURCES: frozenset[str] = frozenset({"cicids_replay"})


class UnscorableSourceError(RuntimeError):
    """A partition row named a source that carries no ground truth."""


def to_eval_rows(rows: list[dict[str, Any]]) -> list[EvalRow]:
    """Partition rows -> alerts, through the SAME parser production uses.

    `parse_cicids_row` synthesizes the signature from flow features and takes no
    label parameter (I4), so the signature an eval prompt carries is built the
    same way a replayed alert's is. A separate eval-only parser is how the two
    quietly diverge and the eval stops measuring the thing that ships.
    """
    from app.ingestion.labels import severity_for

    base = datetime.now(UTC)
    out: list[EvalRow] = []
    for index, row in enumerate(rows):
        canonical = str(row.get("canonical_class") or "")
        declared = str(row.get("source") or "cicids_replay")
        if declared not in SCORABLE_SOURCES:
            # I15 / D24. Loud, and at the boundary: a row that reached here
            # from the live path would otherwise be scored against a label it
            # does not have, which is the failure this invariant names.
            raise UnscorableSourceError(
                f"row {row.get('row_id')!r} declares source {declared!r}, which "
                f"carries no ground truth. Only {sorted(SCORABLE_SOURCES)} may "
                "enter a scored set (PLAN I15, extended by D24)."
            )
        alert = parse_cicids_row(
            row,
            # Arrival time. Spaced so two rows never share a timestamp, which
            # keeps any ordering stable without implying a real cadence.
            timestamp=base + timedelta(milliseconds=index),
            source="cicids_replay",
        )
        out.append(
            EvalRow(
                alert=alert,
                true_attack_type=canonical,
                true_severity=severity_for(canonical),
                features=np.array(
                    [float(row.get(name, 0.0) or 0.0) for name in FEATURE_COLUMNS],
                    dtype=np.float64,
                ),
            )
        )
    return out


def feature_matrix(rows: list[dict[str, Any]]) -> np.ndarray:
    return np.array(
        [[float(r.get(name, 0.0) or 0.0) for name in FEATURE_COLUMNS] for r in rows],
        dtype=np.float64,
    )


def exact_feature_overlap(
    eval_rows: list[dict[str, Any]], train_rows: list[dict[str, Any]]
) -> int:
    """How many eval feature vectors appear VERBATIM in train (I15, §7.3b).

    Hashed rather than compared pairwise: 80 x 5,400 exact comparisons on 77
    float columns is slow and, worse, invites a tolerance. There is no tolerance
    here — a vector either is the same bytes or it is not.
    """
    digest = {
        hashlib.sha256(row.tobytes()).hexdigest() for row in feature_matrix(train_rows)
    }
    return sum(
        1
        for row in feature_matrix(eval_rows)
        if hashlib.sha256(row.tobytes()).hexdigest() in digest
    )


def nearest_neighbour_baseline(
    eval_rows: list[dict[str, Any]], train_rows: list[dict[str, Any]]
) -> float:
    """PLAN §7.3 — the no-training baseline, computed on THESE rows.

    Standardised first, because 1-NN on raw CICFlowMeter columns is dominated by
    whichever feature happens to have the largest units. Fitted on train only:
    fitting the scaler on the eval rows would leak their distribution into the
    baseline the eval is judged against.
    """
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.preprocessing import StandardScaler

    x_train = np.nan_to_num(feature_matrix(train_rows))
    x_eval = np.nan_to_num(feature_matrix(eval_rows))
    y_train = [str(r.get("canonical_class") or "") for r in train_rows]
    y_eval = [str(r.get("canonical_class") or "") for r in eval_rows]

    scaler = StandardScaler().fit(x_train)
    model = KNeighborsClassifier(n_neighbors=1).fit(scaler.transform(x_train), y_train)
    return round(float(model.score(scaler.transform(x_eval), y_eval)), 6)
