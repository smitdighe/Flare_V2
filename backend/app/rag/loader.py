"""The MITRE corpus on disk: schema, validation, loading.

PLAN §4.4 / D5. One JSON file per technique, Pydantic-validated at load. A
corpus file that has drifted out of shape is a loud failure here rather than a
retrieval that silently returns nothing.

The corpus is COMMITTED. It is not fetched at runtime and not rebuilt lazily —
`scripts/build_mitre_corpus.py` regenerates it from the ATT&CK STIX bundle when
the ATT&CK version is bumped, and that is a deliberate act.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
MANIFEST_NAME = "_corpus.json"


class CorpusError(RuntimeError):
    """The committed corpus is missing, empty or malformed."""


class Technique(BaseModel):
    """One ATT&CK technique, reduced to the fields retrieval and the drawer use."""

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    tactics: list[str] = Field(min_length=1)
    platforms: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    detection: str = ""
    is_subtechnique: bool = False
    parent_id: str | None = None
    url: str
    attack_version: str

    @field_validator("description", "detection")
    @classmethod
    def _collapse_whitespace(cls, value: str) -> str:
        return " ".join(value.split())


class CorpusManifest(BaseModel):
    attack_version: str
    attack_spec: str
    source: str
    technique_count: int
    corpus_sha256: str
    built_at: str


def corpus_hash(directory: Path = CORPUS_DIR) -> str:
    """A digest over every technique file, order-independent.

    `build_index.py` keys on this: the index is rebuilt when the corpus changes
    and skipped when it has not, so the build is idempotent without a timestamp
    comparison that a checkout can scramble.
    """
    digest = hashlib.sha256()
    for path in sorted(directory.glob("T*.json")):
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


@lru_cache(maxsize=1)
def load_corpus(directory: Path = CORPUS_DIR) -> tuple[Technique, ...]:
    paths = sorted(directory.glob("T*.json"))
    if not paths:
        raise CorpusError(
            f"no technique files in {directory}. The corpus is committed — run "
            "`python -m scripts.build_mitre_corpus` to regenerate it."
        )

    techniques: list[Technique] = []
    for path in paths:
        try:
            techniques.append(
                Technique.model_validate_json(path.read_text(encoding="utf-8"))
            )
        except Exception as exc:
            raise CorpusError(f"{path.name} failed validation: {exc}") from exc

    ids = [t.technique_id for t in techniques]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise CorpusError(f"duplicate technique ids in the corpus: {sorted(duplicates)}")

    return tuple(techniques)


def load_manifest(directory: Path = CORPUS_DIR) -> CorpusManifest:
    path = directory / MANIFEST_NAME
    if not path.exists():
        raise CorpusError(f"{path} missing — run `python -m scripts.build_mitre_corpus`")
    return CorpusManifest.model_validate(json.loads(path.read_text(encoding="utf-8")))


def technique_ids(directory: Path = CORPUS_DIR) -> frozenset[str]:
    """The grounding set. A technique id outside this is dropped from model output."""
    return frozenset(t.technique_id for t in load_corpus(directory))
