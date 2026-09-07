"""Section chunking. PLAN §4.4.

A technique's description runs to several hundred words and covers distinct
things — what the adversary does, the variants, the observable effect. Embedding
all of it as one vector averages those into a centroid that matches everything
weakly and nothing well.

So each technique becomes several chunks, each carrying its identity. Every
chunk is PREFIXED with the technique name and tactics: a bare paragraph of
description embedded alone loses the fact that it is about network denial of
service, and an alert signature says "SYN-heavy, minimal payload" rather than
quoting ATT&CK prose. The prefix is what bridges the two vocabularies.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.rag.loader import Technique

# Below this a paragraph is a fragment — a heading, a cross-reference — and
# embeds to noise. Merged into the previous chunk instead of standing alone.
MIN_CHUNK_CHARS = 120

# MiniLM truncates at 256 word-pieces. Splitting near that keeps a chunk from
# silently losing its tail to truncation.
MAX_CHUNK_CHARS = 900


@dataclass(frozen=True)
class Chunk:
    technique_id: str
    section: str
    text: str

    @property
    def key(self) -> str:
        return f"{self.technique_id}::{self.section}"


def _split_paragraphs(text: str) -> list[str]:
    parts = [p.strip() for p in text.split("\n") if p.strip()]
    if not parts:
        return []

    merged: list[str] = []
    for part in parts:
        if merged and len(part) < MIN_CHUNK_CHARS:
            merged[-1] = f"{merged[-1]} {part}"
        else:
            merged.append(part)

    bounded: list[str] = []
    for part in merged:
        while len(part) > MAX_CHUNK_CHARS:
            cut = part.rfind(". ", 0, MAX_CHUNK_CHARS)
            if cut <= 0:
                cut = MAX_CHUNK_CHARS
            bounded.append(part[: cut + 1].strip())
            part = part[cut + 1 :].strip()
        if part:
            bounded.append(part)
    return bounded


def chunk_technique(technique: Technique) -> list[Chunk]:
    prefix = f"{technique.technique_id} {technique.name} ({', '.join(technique.tactics)})"
    chunks = [Chunk(technique.technique_id, "summary", f"{prefix}. {technique.name}.")]

    for index, paragraph in enumerate(_split_paragraphs(technique.description)):
        chunks.append(
            Chunk(technique.technique_id, f"description-{index}", f"{prefix}. {paragraph}")
        )

    if technique.detection:
        for index, paragraph in enumerate(_split_paragraphs(technique.detection)):
            chunks.append(
                Chunk(technique.technique_id, f"detection-{index}", f"{prefix}. {paragraph}")
            )

    if technique.mitigations:
        chunks.append(
            Chunk(
                technique.technique_id,
                "mitigations",
                f"{prefix}. Mitigations: {'; '.join(technique.mitigations)}.",
            )
        )

    return chunks


def chunk_corpus(techniques: tuple[Technique, ...]) -> list[Chunk]:
    return [chunk for technique in techniques for chunk in chunk_technique(technique)]
