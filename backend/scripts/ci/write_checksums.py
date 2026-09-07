"""(Re)write the committed artifact checksums. PLAN D21 / §13.2 check 5.

    python -m scripts.ci.write_checksums

**RUN THIS ONLY WHEN THE ARTIFACT LEGITIMATELY CHANGED** — after
`scripts.train_classifier` or `scripts.build_index`. Running it to make a failing
integrity check pass is the same move as moving a guard band to make a score
pass, and it defeats the entire point of committing the checksums: they exist so
that a model file which changed WITHOUT a retraining run is caught.

The embedding weights already ship `models/embeddings/CHECKSUMS.json`, written by
the fetch script. This adds the same treatment to the two artifacts that had
none: the classifier boosters and its feature schema, and the retrieval index.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.ci.checks import CLASSIFIER_DIR, INDEX_DIR, sha256_of

CLASSIFIER_FILES: tuple[str, ...] = (
    "attack_type.booster.txt",
    "severity_gt_low.booster.txt",
    "severity_gt_medium.booster.txt",
    "severity_gt_high.booster.txt",
    "feature_schema.json",
)

INDEX_FILES: tuple[str, ...] = (
    "corpus_embeddings.npy",
    "chunk_manifest.json",
)


def write(directory: Path, filenames: tuple[str, ...]) -> Path:
    checksums = {
        name: sha256_of(directory / name)
        for name in filenames
        if (directory / name).exists()
    }
    missing = [name for name in filenames if not (directory / name).exists()]
    if missing:
        raise SystemExit(
            f"refusing to write a partial manifest for {directory.name}: "
            f"{missing} not on disk. Rebuild the artifact first."
        )
    path = directory / "CHECKSUMS.json"
    path.write_text(json.dumps(checksums, indent=2, sort_keys=True), encoding="utf-8")
    return path


def main() -> int:
    for directory, filenames in (
        (CLASSIFIER_DIR, CLASSIFIER_FILES),
        (INDEX_DIR, INDEX_FILES),
    ):
        path = write(directory, filenames)
        print(f"wrote {path.relative_to(path.parents[2])}")
        for name, digest in json.loads(path.read_text(encoding="utf-8")).items():
            print(f"  {digest}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
