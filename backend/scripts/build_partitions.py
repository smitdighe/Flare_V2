"""Build the three-way disjoint train / eval / replay partitions.

PLAN D20 / §6.2 / I15 — the single most important data rule in the project.
There are two independent leak mechanisms and one partition scheme has to
defeat both:

  * prompt-copy    — the label reaching an LLM prompt
  * memorization   — the classifier being scored on rows it trained on

  train   feeds LightGBM fitting only        never eval, never replay
  eval    feeds the eval harness only        never train, never replay
  replay  feeds the live demo feed only      never train, never eval

Replay must also be disjoint: if the demo plays rows the model trained on, the
live feed is a memorization demo, and a judge who notices the classifier is
flawless on screen but middling in the eval has found the discrepancy for you.

Everything here is seeded and reproducible. The partition assignment is written
to disk and committed — it is never recomputed at runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from app.ingestion.labels import (
    CANONICAL_CLASSES,
    CLASS_TO_SEVERITY,
    EXCLUDED_CLASSES,
    canonical_class,
)
from app.ml.features import FEATURE_COLUMNS
from scripts.fetch_dataset import METADATA_COLUMNS

REPO_ROOT = Path(__file__).resolve().parents[1]
CLEAN_DIR = REPO_ROOT / "data" / "datasets" / "clean"
SPLITS_DIR = REPO_ROOT / "data" / "splits"

SEED = 20260904

# Attack-heavy days. Monday is pure BENIGN and Tuesday/Thursday-afternoon carry
# only FTP/SSH brute force and Infiltration, which this build does not model —
# see JUSTIFICATION below, reproduced into the report.
SOURCE_FILES: tuple[str, ...] = (
    "Wednesday-workingHours.clean.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.clean.csv",
    "Friday-WorkingHours-Morning.clean.csv",
    "Friday-WorkingHours-Afternoon-PortScan.clean.csv",
    "Friday-WorkingHours-Afternoon-DDos.clean.csv",
)

JUSTIFICATION = (
    "Wednesday supplies every DoS variant (Hulk, GoldenEye, slowloris, "
    "Slowhttptest). Thursday morning supplies the web attacks (Brute Force, "
    "XSS, SQL Injection). Friday supplies Botnet in the morning and PortScan "
    "and DDoS in the afternoon. Together these five files cover all six "
    "canonical attack classes plus a large BENIGN population. Monday is "
    "entirely BENIGN and adds no class coverage; Tuesday (FTP/SSH brute force) "
    "and Thursday afternoon (Infiltration) carry classes this build does not "
    "model, so including them would add rows without adding coverage."
)

# Per class, per partition. A class that cannot reach this in all three
# partitions fails the build rather than being quietly under-represented.
MIN_ROWS_PER_PARTITION = 60

# Cap per class so BENIGN does not swamp the sample. Real imbalance is
# preserved below the cap; it is not resampled away.
MAX_ROWS_PER_CLASS = 1500

SPLIT_FRACTIONS = {"train": 0.60, "eval": 0.20, "replay": 0.20}


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_and_label(clean_dir: Path) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for name in SOURCE_FILES:
        path = clean_dir / name
        if not path.exists():
            raise FileNotFoundError(
                f"{path} missing. Run: python -m scripts.fetch_dataset --glf-hf --attack-days-only"
            )
        frame = pd.read_csv(path, low_memory=False)
        frame["source_file"] = name
        frames.append(frame)

    combined = pd.concat(frames, ignore_index=True)

    # Zero unmapped, enforced here and by tests/unit/test_labels.py.
    unique_raw = sorted(combined["Label"].astype(str).str.strip().unique())
    mapping = {raw: canonical_class(raw) for raw in unique_raw}
    combined["canonical_class"] = combined["Label"].astype(str).str.strip().map(mapping)

    return combined


def deduplicate_feature_vectors(frame: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """One row per distinct 77-feature vector, BEFORE the split.

    Id-level disjointness is not enough, and the GLF migration is what exposed
    it. The row id now hashes Flow ID and the endpoints, so two flows with
    byte-identical statistics but different endpoints get different ids and land
    in different partitions while being, to the classifier, the same row. The
    first trained model scored 0.9983 on held-out data and 3.44% of eval rows
    had a feature vector present verbatim in train — 16.3% of the `dos` rows,
    because DoS Hulk emits enormous numbers of stereotyped flows.

    That is memorization with the partition check passing, which is precisely
    the failure I15 exists to prevent. So disjointness is now enforced on what
    the model actually sees. Deduplication happens on the full population before
    sampling, so the survivor is chosen without reference to any partition.

    Rounded to 9 decimal places first: these values survived a CSV round-trip,
    and two flows differing only in float-repr noise are not two flows.
    """
    fingerprint = pd.util.hash_pandas_object(
        frame[list(FEATURE_COLUMNS)].astype("float64").round(9), index=False
    )
    keep = ~fingerprint.duplicated()
    return frame.loc[keep.to_numpy()].reset_index(drop=True), int((~keep).sum())


def stratified_sample(frame: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    kept: list[pd.DataFrame] = []
    for canonical in CANONICAL_CLASSES:
        subset = frame.loc[frame["canonical_class"] == canonical]
        take = min(len(subset), MAX_ROWS_PER_CLASS)
        if take < len(subset):
            positions = rng.choice(len(subset), size=take, replace=False)
            subset = subset.iloc[np.sort(positions)]
        kept.append(subset)
    return pd.concat(kept, ignore_index=True)


def assign_partitions(frame: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    """Stratified three-way split. Each class is split independently so every
    partition sees every class in roughly the sampled proportion."""
    frame = frame.copy()
    frame["partition"] = ""

    for canonical in CANONICAL_CLASSES:
        index = np.array(frame.index[frame["canonical_class"] == canonical])
        rng.shuffle(index)

        total = len(index)
        n_train = round(total * SPLIT_FRACTIONS["train"])
        n_eval = round(total * SPLIT_FRACTIONS["eval"])

        frame.loc[index[:n_train], "partition"] = "train"
        frame.loc[index[n_train : n_train + n_eval], "partition"] = "eval"
        frame.loc[index[n_train + n_eval :], "partition"] = "replay"

    return frame


def stamp_ids(frame: pd.DataFrame) -> pd.DataFrame:
    """A stable, partition-stamped id per row.

    PLAN §6.2: the id carries its partition, so an overlap is visible in the id
    itself and not only in a set comparison. The hash is over every column that
    describes the flow — the 77 features plus the GLF metadata (Flow ID,
    endpoints, capture timestamp) — so the same row always gets the same id and
    the assignment is reproducible from the file rather than recomputed at
    runtime.

    The metadata is in the hash deliberately. Hashing features alone collided:
    the MachineLearningCSV build produced 5,234 distinct ids for 5,400 train
    rows, because two flows with identical statistics are indistinguishable
    without their endpoints. Flow ID makes each row unique, which is what an
    id has to be for the disjointness check to mean anything.
    """
    identity_columns = [
        c
        for c in frame.columns
        if c not in ("Label", "canonical_class", "partition", "source_file")
    ]

    def row_id(row: pd.Series) -> str:
        payload = "|".join(f"{c}={row[c]}" for c in identity_columns)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
        return f"{row['partition']}-{digest}"

    frame = frame.copy()
    frame["row_id"] = frame.apply(row_id, axis=1)
    return frame


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean-dir", type=Path, default=CLEAN_DIR)
    parser.add_argument("--out-dir", type=Path, default=SPLITS_DIR)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)

    print("Loading cleaned CSVs ...")
    combined = load_and_label(args.clean_dir)
    raw_counts = Counter(combined["canonical_class"])
    print(f"  {len(combined):,} rows, {len(raw_counts)} canonical classes")

    excluded_counts = {
        name: int(raw_counts.get(name, 0)) for name in EXCLUDED_CLASSES
    }
    for name, count in excluded_counts.items():
        if count:
            print(f"  excluding {name}: {count} rows — {EXCLUDED_CLASSES[name]}")

    combined, duplicates_removed = deduplicate_feature_vectors(combined)
    print(f"  dropped {duplicates_removed:,} duplicate feature vectors (I15, feature level)")
    deduped_counts = Counter(combined["canonical_class"])

    sampled = stratified_sample(combined, rng)
    print(f"Sampled {len(sampled):,} rows")

    partitioned = assign_partitions(sampled, rng)
    partitioned = stamp_ids(partitioned)

    # Fail loudly if any class is too thin in any partition.
    problems: list[str] = []
    for canonical in CANONICAL_CLASSES:
        for partition in SPLIT_FRACTIONS:
            count = int(
                (
                    (partitioned["canonical_class"] == canonical)
                    & (partitioned["partition"] == partition)
                ).sum()
            )
            if count < MIN_ROWS_PER_PARTITION:
                problems.append(
                    f"{canonical}/{partition}: {count} rows "
                    f"(minimum {MIN_ROWS_PER_PARTITION})"
                )
    if problems:
        print("\nFAILED — a class would be under-represented:", flush=True)
        for problem in problems:
            print(f"  {problem}")
        return 1

    # PLAN I15 — the assertion the whole scheme exists for.
    id_sets = {
        partition: set(partitioned.loc[partitioned["partition"] == partition, "row_id"])
        for partition in SPLIT_FRACTIONS
    }
    for left in SPLIT_FRACTIONS:
        for right in SPLIT_FRACTIONS:
            if left < right:
                overlap = id_sets[left] & id_sets[right]
                if overlap:
                    print(
                        f"FAILED — {left} and {right} share {len(overlap)} row ids",
                        flush=True,
                    )
                    return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    checksums: dict[str, str] = {}
    per_partition: dict[str, dict[str, int]] = {}

    for partition in SPLIT_FRACTIONS:
        subset = partitioned.loc[partitioned["partition"] == partition].drop(
            columns=["partition"]
        )
        # Interleave the classes. stratified_sample concatenates class by class,
        # so without this the replay feed would show 300 consecutive BENIGN rows
        # before the first attack. Seeded, so ordering stays reproducible —
        # PLAN §6.4 requires deterministic ordering, not unshuffled ordering.
        subset = subset.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
        out_path = args.out_dir / f"{partition}.csv"
        subset.to_csv(out_path, index=False)
        checksums[out_path.name] = sha256_of(out_path)
        per_partition[partition] = {
            str(k): int(v) for k, v in Counter(subset["canonical_class"]).items()
        }
        print(f"  wrote {out_path.name}: {len(subset):,} rows")

    unique_ids = {p: len(ids) for p, ids in id_sets.items()}
    duplicate_ids = {
        p: int((partitioned["partition"] == p).sum()) - unique_ids[p]
        for p in SPLIT_FRACTIONS
    }
    if any(duplicate_ids.values()):
        print(f"FAILED — duplicate row ids within a partition: {duplicate_ids}")
        return 1

    manifest = {
        "seed": args.seed,
        "distribution": "GeneratedLabelledFlows (85 columns, real endpoints and timestamps)",
        "source_files": list(SOURCE_FILES),
        "metadata_columns": list(METADATA_COLUMNS),
        "day_selection_justification": JUSTIFICATION,
        "canonical_classes": list(CANONICAL_CLASSES),
        "class_to_severity": CLASS_TO_SEVERITY,
        "severity_order": ["low", "medium", "high", "critical"],
        "severity_note": (
            "PLAN D27 — `unknown` is outside the order, satisfies no threshold, "
            "and is never a ground-truth label."
        ),
        "excluded_classes": {
            name: {"reason": EXCLUDED_CLASSES[name], "rows_available": count}
            for name, count in excluded_counts.items()
        },
        "max_rows_per_class": MAX_ROWS_PER_CLASS,
        "min_rows_per_partition": MIN_ROWS_PER_PARTITION,
        "split_fractions": SPLIT_FRACTIONS,
        "population_class_counts": {str(k): int(v) for k, v in raw_counts.items()},
        "distinct_feature_vector_counts": {
            str(k): int(v) for k, v in deduped_counts.items()
        },
        "duplicate_feature_vectors_removed": duplicates_removed,
        "disjointness_note": (
            "Disjointness is enforced on the 77-feature vector, not only on the "
            "row id. Ids hash Flow ID and the endpoints, so two flows with "
            "identical statistics get different ids and would otherwise be split "
            "across partitions while being the same row to the classifier."
        ),
        "partition_row_counts": {
            partition: int((partitioned["partition"] == partition).sum())
            for partition in SPLIT_FRACTIONS
        },
        "partition_class_counts": per_partition,
        "row_ids": {partition: sorted(ids) for partition, ids in id_sets.items()},
        "checksums_sha256": checksums,
        "disjoint_verified": True,
    }

    manifest_path = args.out_dir / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nWrote {manifest_path}")
    print("Partitions are pairwise disjoint (I15 verified).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
