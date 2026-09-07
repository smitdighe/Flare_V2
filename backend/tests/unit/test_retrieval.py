"""MiniLM embeddings, the committed index, and measured retrieval. PLAN §4.4 / D3 / D21."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from app.rag.chunker import chunk_corpus, chunk_technique
from app.rag.embedder import (
    CHECKSUM_NAME,
    EMBEDDING_DIM,
    EMBEDDING_DIR,
    EmbedderError,
    get_embedder,
    sha256_of,
    verify_checksums,
)
from app.rag.loader import CORPUS_DIR, corpus_hash, load_corpus, load_manifest, technique_ids
from app.rag.retriever import INDEX_DIR, Retriever, build_query

BACKEND = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND.parent
LABELS = BACKEND / "data" / "retrieval_labels.json"

needs_index = pytest.mark.skipif(
    not (INDEX_DIR / "corpus_embeddings.npy").exists(),
    reason="index not built — run scripts.build_index",
)


@pytest.fixture(scope="module")
def retriever() -> Retriever:
    return Retriever(INDEX_DIR)


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------


def test_corpus_loads_and_validates() -> None:
    corpus = load_corpus()
    assert len(corpus) >= 40, "a corpus this small cannot make retrieval discriminate"
    for technique in corpus:
        assert technique.tactics, f"{technique.technique_id} has no tactic"
        assert technique.description


def test_corpus_manifest_records_the_attack_version() -> None:
    manifest = load_manifest()
    assert manifest.attack_version != "unknown"
    assert manifest.technique_count == len(load_corpus())
    assert manifest.corpus_sha256 == corpus_hash()


def test_corpus_covers_every_canonical_class() -> None:
    """Each class must have somewhere to land, or grounding drops everything."""
    required = {
        "dos": {"T1499"},
        "ddos": {"T1498"},
        "port_scan": {"T1046", "T1595"},
        "botnet": {"T1071"},
        "web_attack": {"T1190", "T1110"},
    }
    available = technique_ids()
    for canonical, techniques in required.items():
        assert techniques <= available, f"{canonical} has no technique in the corpus"


def test_chunker_prefixes_every_chunk_with_its_identity() -> None:
    """A bare description paragraph embeds without its subject and matches noise."""
    technique = next(t for t in load_corpus() if t.technique_id == "T1498")
    chunks = chunk_technique(technique)
    assert len(chunks) > 1, "a single chunk per technique averages its sections away"
    for chunk in chunks:
        assert chunk.technique_id == "T1498"
        assert chunk.text.startswith("T1498 ")


# ---------------------------------------------------------------------------
# weights and checksums
# ---------------------------------------------------------------------------


def test_committed_weights_verify() -> None:
    digests = verify_checksums()
    assert "model_quantized.onnx" in digests
    assert "tokenizer.json" in digests


def test_tampered_weights_fail_loudly(tmp_path: Path) -> None:
    manifest = json.loads((EMBEDDING_DIR / CHECKSUM_NAME).read_text(encoding="utf-8"))
    for name in manifest:
        (tmp_path / name).write_bytes((EMBEDDING_DIR / name).read_bytes())

    tampered = tmp_path / "tokenizer.json"
    tampered.write_bytes(tampered.read_bytes() + b" ")
    manifest_path = tmp_path / CHECKSUM_NAME
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(EmbedderError, match="does not match"):
        verify_checksums(tmp_path)


def test_embeddings_are_unit_length_and_384_dim() -> None:
    """`matrix @ query` is only cosine if every vector is normalised."""
    vectors = get_embedder().encode(["network denial of service", "port scanning"])
    assert vectors.shape == (2, EMBEDDING_DIM)
    assert vectors.dtype == np.float32
    assert np.allclose(np.linalg.norm(vectors, axis=1), 1.0, atol=1e-4)


def test_embedding_is_deterministic() -> None:
    first = get_embedder().encode_one("SYN flood against a web server")
    second = get_embedder().encode_one("SYN flood against a web server")
    assert np.array_equal(first, second)


# ---------------------------------------------------------------------------
# index
# ---------------------------------------------------------------------------


@needs_index
def test_index_dimensions_match_the_manifest(retriever: Retriever) -> None:
    manifest = json.loads((INDEX_DIR / "chunk_manifest.json").read_text(encoding="utf-8"))
    matrix = np.load(INDEX_DIR / "corpus_embeddings.npy")

    assert matrix.shape == (manifest["chunk_count"], manifest["dimensions"])
    assert matrix.dtype == np.float32
    assert retriever.chunk_count == manifest["chunk_count"]
    assert retriever.dimensions == EMBEDDING_DIM
    assert manifest["chunk_count"] == len(chunk_corpus(load_corpus()))


@needs_index
def test_index_is_keyed_on_the_corpus_hash() -> None:
    manifest = json.loads((INDEX_DIR / "chunk_manifest.json").read_text(encoding="utf-8"))
    assert manifest["corpus_sha256"] == corpus_hash(CORPUS_DIR)


@needs_index
def test_stale_index_fails_loudly(tmp_path: Path) -> None:
    """A stale index answers confidently about documents that are gone."""
    manifest = json.loads((INDEX_DIR / "chunk_manifest.json").read_text(encoding="utf-8"))
    manifest["corpus_sha256"] = "0" * 64
    (tmp_path / "chunk_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "corpus_embeddings.npy").write_bytes(
        (INDEX_DIR / "corpus_embeddings.npy").read_bytes()
    )

    from app.rag.retriever import IndexError_

    with pytest.raises(IndexError_, match="Rebuild"):
        Retriever(tmp_path)


@needs_index
def test_missing_index_fails_loudly(tmp_path: Path) -> None:
    from app.rag.retriever import IndexError_

    with pytest.raises(IndexError_, match="missing"):
        Retriever(tmp_path)


# ---------------------------------------------------------------------------
# retrieval quality — measured, not asserted
# ---------------------------------------------------------------------------


@needs_index
def test_search_returns_distinct_techniques(retriever: Retriever) -> None:
    """Without the dedupe one technique's chunks fill the whole result set."""
    hits = retriever.search(build_query("ddos", "Flow to TCP/80 — high packet volume", 80), 5)
    assert len(hits) == 5
    assert len({h.technique_id for h in hits}) == 5
    assert all(-1.0 <= h.score <= 1.0 for h in hits)
    assert [h.score for h in hits] == sorted((h.score for h in hits), reverse=True)


@needs_index
def test_recall_at_k_on_the_committed_labelled_set(retriever: Retriever) -> None:
    """PLAN §4.4 — retrieval quality is measured.

    The floor is deliberately below the measured value (recall@5 = 0.944 at the
    time of writing). This asserts the retriever has not REGRESSED; it is not a
    target, and moving the floor up to whatever today's number happens to be
    would make it one.
    """
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    pairs = labels["pairs"]
    available = technique_ids()

    hits_at_5 = 0
    for pair in pairs:
        assert set(pair["expected"]) <= available, (
            f"{pair['id']} expects a technique the corpus does not contain"
        )
        query = build_query(pair["attack_type"], pair["signature"], pair["dest_port"])
        retrieved = {h.technique_id for h in retriever.search(query, 5)}
        if retrieved & set(pair["expected"]):
            hits_at_5 += 1

    recall = hits_at_5 / len(pairs)
    assert recall >= 0.80, f"recall@5 regressed to {recall:.4f}"


@needs_index
def test_grounding_drops_unretrieved_techniques(retriever: Retriever) -> None:
    """PLAN §4.4 — the half MINE never had."""
    hits = retriever.search(build_query("ddos", "high packet volume", 80), 5)
    retrieved = [h.technique_id for h in hits]

    grounded = retriever.ground([retrieved[0], "T9999", "T1078"], hits)
    assert retrieved[0] in grounded
    assert "T9999" not in grounded, "a technique the retriever never returned survived"


@needs_index
def test_query_builder_expands_the_class_enum() -> None:
    """The enum is not English; MiniLM needs the vocabulary the corpus uses."""
    query = build_query("port_scan", "Flow to TCP/443", 443)
    assert "port_scan" not in query
    assert "scanning" in query
    assert "Flow to TCP/443" in query


def test_embedding_weights_are_committed_not_gitignored() -> None:
    """PLAN D21 — a cold clone with no network is the case this design serves.

    The repository keeps ONE `.gitignore`, at the root, so this reads that file
    rather than a per-package one. Comment lines are dropped per line: the file
    documents the `models/` exception in prose, and a substring search over the
    raw text would match the explanation instead of a rule.
    """
    ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    patterns = [
        line.strip()
        for line in ignore.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert patterns, "the root .gitignore has no active patterns — wrong file?"
    offending = [p for p in patterns if "models" in p and not p.startswith("!")]
    assert not offending, f"the committed model artifacts are gitignored by {offending}"
    assert (EMBEDDING_DIR / "model_quantized.onnx").exists()
    assert sha256_of(EMBEDDING_DIR / "model_quantized.onnx")
