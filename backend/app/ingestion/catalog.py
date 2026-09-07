"""What the data actually contains, read from the committed manifest.

FE-11. The frozen frontend hardcoded six vector-filter options
(`FilterStrip.jsx:40-45`) of which four match nothing and which omit four
classes every alert can carry. Serving a second hardcoded list from the backend
would move the defect rather than fix it: a canonical tuple in Python can drift
from the partitions exactly as the JSX did.

So the list is read from `data/splits/MANIFEST.json`, which `build_partitions.py`
writes from the classes it actually wrote to disk. If a class disappears from
the data, it disappears from the filter, with no code change and no way to
forget.

`CANONICAL_CLASSES` in `labels.py` is still the modelling contract — it is what
the classifier's heads are built over. This module answers a different
question: which of those survived into the built partitions. They agree today,
and `test_catalog.py` asserts they agree, so a divergence is a loud failure
rather than a silent one.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "data" / "splits" / "MANIFEST.json"


class CatalogUnavailableError(RuntimeError):
    """The partition manifest is missing or unreadable."""


def _label_for(value: str) -> str:
    return value.replace("_", " ").upper()


@lru_cache(maxsize=1)
def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    if not path.exists():
        raise CatalogUnavailableError(
            f"{path} missing. Run:\n"
            "  python -m scripts.fetch_dataset --glf-hf --attack-days-only\n"
            "  python -m scripts.build_partitions"
        )
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def attack_types(path: Path = MANIFEST_PATH) -> list[dict[str, str]]:
    """The classes present in every partition, in manifest order.

    Presence is checked per partition rather than against the top-level class
    list: a class recorded as canonical but absent from `eval` would be
    unscoreable, and offering it as a filter option would promise a view the
    data cannot fill.
    """
    manifest = load_manifest(path)
    per_partition: dict[str, dict[str, int]] = manifest["partition_class_counts"]
    severities: dict[str, str] = manifest["class_to_severity"]

    present = set.intersection(*(set(counts) for counts in per_partition.values()))

    return [
        {
            "value": name,
            "label": _label_for(name),
            "severity": severities[name],
        }
        for name in manifest["canonical_classes"]
        if name in present
    ]


def excluded_classes(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    excluded: dict[str, Any] = load_manifest(path).get("excluded_classes", {})
    return excluded
