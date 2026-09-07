"""Embed the corpus once and commit the result. PLAN §4.4 / D5 / D21.

NEVER LAZY, NEVER AT FIRST QUERY. Building an index on first use means the first
query is slow, the failure surfaces mid-demo, and a cold clone needs whatever
the build needed. This script runs deliberately; the output is committed.

IDEMPOTENT, keyed on the corpus hash. Rerunning with an unchanged corpus is a
no-op — not because of a timestamp comparison, which a checkout scrambles, but
because the content digest says so.

It also writes `models/embeddings/CHECKSUMS.json`, the digests the embedder
verifies at startup, so the weights that answer a query are provably the
weights the index was built from.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from app.rag.chunker import chunk_corpus
from app.rag.embedder import (
    CHECKSUM_NAME,
    EMBEDDING_DIM,
    EMBEDDING_DIR,
    Embedder,
    sha256_of,
)
from app.rag.loader import corpus_hash, load_corpus, load_manifest
from app.rag.retriever import INDEX_DIR, MANIFEST_NAME, MATRIX_NAME

# Everything the embedder needs at runtime. Listed rather than globbed so a
# stray file in the directory cannot quietly become part of the contract.
WEIGHT_FILES: tuple[str, ...] = (
    "model_quantized.onnx",
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "config.json",
)

BATCH = 32


def write_checksums(directory: Path = EMBEDDING_DIR) -> dict[str, str]:
    digests = {name: sha256_of(directory / name) for name in WEIGHT_FILES}
    (directory / CHECKSUM_NAME).write_text(json.dumps(digests, indent=2), encoding="utf-8")
    return digests


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-dir", type=Path, default=INDEX_DIR)
    parser.add_argument("--embedding-dir", type=Path, default=EMBEDDING_DIR)
    parser.add_argument(
        "--force", action="store_true", help="rebuild even if the corpus hash matches"
    )
    args = parser.parse_args()

    args.index_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.index_dir / MANIFEST_NAME
    digest = corpus_hash()

    if manifest_path.exists() and not args.force:
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        if existing.get("corpus_sha256") == digest:
            print(f"Index is current for corpus {digest[:16]}… — nothing to do.")
            return 0

    print("Verifying and checksumming the committed weights ...")
    digests = write_checksums(args.embedding_dir)
    for name, value in digests.items():
        print(f"  {value[:16]}…  {name}")

    corpus = load_corpus()
    corpus_manifest = load_manifest()
    chunks = chunk_corpus(corpus)
    print(
        f"\n{len(corpus)} techniques (ATT&CK {corpus_manifest.attack_version}) "
        f"-> {len(chunks)} chunks"
    )

    embedder = Embedder(args.embedding_dir)
    vectors: list[np.ndarray] = []
    for start in range(0, len(chunks), BATCH):
        batch = chunks[start : start + BATCH]
        vectors.append(embedder.encode([c.text for c in batch]))
        print(f"  embedded {min(start + BATCH, len(chunks))}/{len(chunks)}", flush=True)

    matrix = np.vstack(vectors).astype(np.float32)
    if matrix.shape != (len(chunks), EMBEDDING_DIM):
        raise RuntimeError(f"embedded {matrix.shape}, expected ({len(chunks)}, {EMBEDDING_DIM})")

    # The retriever treats `matrix @ query` as cosine, which is only true if
    # every row is unit length. Asserted rather than assumed.
    norms = np.linalg.norm(matrix, axis=1)
    if not np.allclose(norms, 1.0, atol=1e-4):
        raise RuntimeError(f"rows are not L2-normalised: min {norms.min()}, max {norms.max()}")

    np.save(args.index_dir / MATRIX_NAME, matrix)
    manifest_path.write_text(
        json.dumps(
            {
                "corpus_sha256": digest,
                "attack_version": corpus_manifest.attack_version,
                "model": "all-MiniLM-L6-v2 int8 ONNX",
                "dimensions": EMBEDDING_DIM,
                "chunk_count": len(chunks),
                "built_at": datetime.now(UTC).isoformat(),
                "weight_checksums": digests,
                "chunks": [
                    {"technique_id": c.technique_id, "section": c.section, "text": c.text}
                    for c in chunks
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"\nWrote {args.index_dir / MATRIX_NAME}  {matrix.shape} float32")
    print(f"Wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
