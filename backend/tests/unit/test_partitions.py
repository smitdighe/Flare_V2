"""Partition, label and leak invariants.

These are the three PLAN calls out as mattering most: I15 (three-way
disjointness), I4 (no label leak) and the zero-unmapped label rule.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from app.ingestion.labels import (
    CANONICAL_CLASSES,
    CLASS_TO_SEVERITY,
    RAW_TO_CANONICAL,
    SEVERITY_ORDER,
    UnmappedLabelError,
    canonical_class,
    meets_threshold,
    normalize_label,
    severity_rank,
)

SPLITS = Path(__file__).resolve().parents[2] / "data" / "splits"
PARTITIONS = ("train", "eval", "replay")

pytestmark = pytest.mark.skipif(
    not (SPLITS / "MANIFEST.json").exists(),
    reason="partitions not built — run scripts.fetch_dataset then scripts.build_partitions",
)


def _row_ids(partition: str) -> set[str]:
    with (SPLITS / f"{partition}.csv").open(encoding="utf-8", newline="") as handle:
        return {row["row_id"] for row in csv.DictReader(handle)}


def test_partition_id_sets_are_pairwise_disjoint() -> None:
    """PLAN I15 — the assertion the whole partition scheme exists for."""
    ids = {partition: _row_ids(partition) for partition in PARTITIONS}

    for left in PARTITIONS:
        for right in PARTITIONS:
            if left < right:
                overlap = ids[left] & ids[right]
                assert not overlap, (
                    f"{left} and {right} share {len(overlap)} rows: "
                    f"{sorted(overlap)[:3]}"
                )

    assert all(ids[p] for p in PARTITIONS), "no partition may be empty"


def test_row_ids_are_partition_stamped() -> None:
    """A train row reaching the demo feed is visible in the id itself."""
    for partition in PARTITIONS:
        for row_id in _row_ids(partition):
            assert row_id.startswith(f"{partition}-"), (
                f"{row_id!r} is in {partition}.csv but not stamped for it"
            )


def test_every_class_survives_in_every_partition() -> None:
    manifest = json.loads((SPLITS / "MANIFEST.json").read_text(encoding="utf-8"))
    minimum = manifest["min_rows_per_partition"]

    for partition in PARTITIONS:
        counts = manifest["partition_class_counts"][partition]
        for canonical in CANONICAL_CLASSES:
            assert counts.get(canonical, 0) >= minimum, (
                f"{canonical} has {counts.get(canonical, 0)} rows in {partition}, "
                f"minimum is {minimum}"
            )


def test_manifest_records_the_seed_and_checksums() -> None:
    manifest = json.loads((SPLITS / "MANIFEST.json").read_text(encoding="utf-8"))
    assert isinstance(manifest["seed"], int)
    assert manifest["disjoint_verified"] is True
    assert "GeneratedLabelledFlows" in manifest["distribution"], (
        "MachineLearningCSV has no endpoints; a partition built from it would "
        "put the synthesis question back"
    )
    for partition in PARTITIONS:
        digest = manifest["checksums_sha256"][f"{partition}.csv"]
        assert len(digest) == 64, "sha256 per output file"


def test_row_ids_are_unique_within_a_partition() -> None:
    """Hashing features alone collided — 5,400 rows, 5,234 ids.

    Two flows with identical statistics are indistinguishable without their
    endpoints, so the id now covers the GLF identity columns too. A duplicate
    id would silently weaken the disjointness check above.
    """
    for partition in PARTITIONS:
        ids = list(_row_ids(partition))
        assert len(ids) == len(set(ids)), (
            f"{partition}: {len(ids) - len(set(ids))} duplicate row ids"
        )


def test_no_label_column_leaks_into_the_partition_row_ids() -> None:
    """The id hashes identity and feature columns, never the label."""
    for partition in PARTITIONS:
        for row_id in list(_row_ids(partition))[:50]:
            suffix = row_id.split("-", 1)[1]
            for canonical in CANONICAL_CLASSES:
                assert canonical not in suffix


# ---------------------------------------------------------------------------
# label mapping
# ---------------------------------------------------------------------------


def test_every_spelling_in_the_data_maps() -> None:
    """PLAN §6.3 — zero unmapped, enforced against the real cleaned files."""
    clean = SPLITS.parent / "datasets" / "clean" / "FETCH_REPORT.json"
    if not clean.exists():
        pytest.skip("fetch report not present")

    report = json.loads(clean.read_text(encoding="utf-8"))
    seen: set[str] = set()
    for file_report in report["files"]:
        seen.update(file_report["label_counts"])

    assert seen, "the fetch report recorded no labels"
    for spelling in seen:
        canonical_class(spelling)  # raises UnmappedLabelError if unmapped


def test_unmapped_spelling_fails_loudly() -> None:
    with pytest.raises(UnmappedLabelError, match="Unmapped label spelling"):
        canonical_class("Some Brand New Attack")


def test_no_silent_default_in_the_map() -> None:
    """A fallthrough to 'other' is how a class quietly disappears from an eval."""
    assert "other" not in RAW_TO_CANONICAL.values()


@pytest.mark.parametrize(
    "spelling",
    [
        "Web Attack – Brute Force",  # true CP-1252 en dash
        "Web Attack � Brute Force",  # UTF-8 conversion artefact
        "Web Attack ï¿½ Brute Force",  # double-decode mojibake
        "Web Attack - Brute Force",  # plain hyphen
    ],
)
def test_encoding_variants_all_normalize(spelling: str) -> None:
    assert canonical_class(spelling) == "web_attack"
    assert normalize_label(spelling) == "Web Attack - Brute Force"


def test_normalize_never_inserts_hyphens_everywhere() -> None:
    """Guards against an empty string reaching the separator list."""
    assert normalize_label("BENIGN") == "BENIGN"
    assert normalize_label("DoS Hulk") == "DoS Hulk"


# ---------------------------------------------------------------------------
# severity
# ---------------------------------------------------------------------------


def test_every_scored_class_has_a_severity() -> None:
    for canonical in CANONICAL_CLASSES:
        assert CLASS_TO_SEVERITY[canonical] in SEVERITY_ORDER


def test_severity_total_order() -> None:
    """PLAN D27 — low < medium < high < critical."""
    assert severity_rank("low") < severity_rank("medium")
    assert severity_rank("medium") < severity_rank("high")
    assert severity_rank("high") < severity_rank("critical")


def test_unknown_is_outside_the_order_and_fails_closed() -> None:
    """PLAN D27 — a failed classification must never trip a threshold.

    Treating `unknown` as "at least high" would fire playbooks and emails on
    the pipeline's own failures.
    """
    assert severity_rank("unknown") == -1
    assert meets_threshold("unknown", "low") is False
    assert meets_threshold("unknown", "critical") is False
    # No threshold set means everything passes, including unknown.
    assert meets_threshold("unknown", None) is True


def test_threshold_comparison_is_inclusive() -> None:
    assert meets_threshold("high", "high") is True
    assert meets_threshold("critical", "high") is True
    assert meets_threshold("medium", "high") is False
