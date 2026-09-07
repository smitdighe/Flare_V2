"""MiniLM through onnxruntime. PLAN D4 / §4.4.

`all-MiniLM-L6-v2`, 6-layer BERT, 384-dim, int8-quantized ONNX. A real
transformer, and the ONNX route avoids dragging in ~800MB of PyTorch for a
model that is 23MB.

NO PyTorch, NO sentence-transformers, NO chromadb. The weights and the
tokenizer are COMMITTED with checksums (D21) and verified at load — a cold
clone with no network is the case this design exists to serve, because a lazy
download is exactly what fails on demo day.

The session is built once and cached. Pooling is mean-over-tokens masked by
attention, then L2 normalisation, which is what all-MiniLM-L6-v2 was trained
with — max-pooling or CLS would produce vectors the model's training never
optimised and quietly worse retrieval.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

EMBEDDING_DIR = Path(__file__).resolve().parents[2] / "models" / "embeddings"
CHECKSUM_NAME = "CHECKSUMS.json"

MODEL_FILE = "model_quantized.onnx"
TOKENIZER_FILE = "tokenizer.json"

EMBEDDING_DIM = 384
MAX_TOKENS = 256


class EmbedderError(RuntimeError):
    """The committed weights are missing or do not match their checksum."""


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_checksums(directory: Path = EMBEDDING_DIR) -> dict[str, str]:
    """PLAN D21 — a mismatch fails loudly, at startup, not at first query."""
    manifest_path = directory / CHECKSUM_NAME
    if not manifest_path.exists():
        raise EmbedderError(
            f"{manifest_path} missing. The weights are committed, not downloaded — "
            "run `python -m scripts.build_index` to regenerate the manifest."
        )

    expected: dict[str, str] = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, digest in expected.items():
        path = directory / name
        if not path.exists():
            raise EmbedderError(f"{path} missing — the committed model is incomplete")
        actual = sha256_of(path)
        if actual != digest:
            raise EmbedderError(
                f"{name} sha256 {actual[:16]}… does not match the committed "
                f"{digest[:16]}…. The weights on disk are not the weights the "
                "index was built from, so every retrieval would be wrong."
            )
    return expected


class Embedder:
    def __init__(self, directory: Path = EMBEDDING_DIR) -> None:
        verify_checksums(directory)

        self._session = ort.InferenceSession(
            str(directory / MODEL_FILE), providers=["CPUExecutionProvider"]
        )
        self._input_names = {i.name for i in self._session.get_inputs()}

        self._tokenizer = Tokenizer.from_file(str(directory / TOKENIZER_FILE))
        self._tokenizer.enable_truncation(max_length=MAX_TOKENS)
        self._tokenizer.enable_padding(length=None)

    def encode(self, texts: list[str]) -> np.ndarray:
        """-> (n, 384) float32, L2-normalised so a dot product IS cosine."""
        if not texts:
            return np.zeros((0, EMBEDDING_DIM), dtype=np.float32)

        encoded = self._tokenizer.encode_batch(texts)
        ids = np.array([e.ids for e in encoded], dtype=np.int64)
        mask = np.array([e.attention_mask for e in encoded], dtype=np.int64)

        feeds: dict[str, np.ndarray] = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self._input_names:
            feeds["token_type_ids"] = np.zeros_like(ids)

        hidden = self._session.run(None, feeds)[0]

        weights = mask[..., None].astype(np.float32)
        pooled = (hidden * weights).sum(axis=1) / np.clip(weights.sum(axis=1), 1e-9, None)

        norms = np.linalg.norm(pooled, axis=1, keepdims=True)
        return (pooled / np.clip(norms, 1e-12, None)).astype(np.float32)

    def encode_one(self, text: str) -> np.ndarray:
        return self.encode([text])[0]


@lru_cache(maxsize=1)
def get_embedder(directory: Path = EMBEDDING_DIR) -> Embedder:
    return Embedder(directory)
