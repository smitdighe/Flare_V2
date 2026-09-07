"""Retrieval: one numpy dot product. PLAN D3 / §4.4.

The index is a committed float32 matrix of L2-normalised chunk embeddings, so
cosine similarity is `matrix @ query` and nothing else. At a few hundred chunks
that is microseconds — genuinely faster than a vector-DB round trip, with no
client library, no server, no import that can kill startup and no download that
can fail on demo day. Those last two are exactly what disqualified Chroma (D3).

Everything is verified at load: the weights against their committed checksums,
the index against the corpus hash it was built from, and the matrix shape
against the manifest. A mismatch means the index describes a corpus that is no
longer on disk, which would return confidently wrong techniques.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from app.rag.embedder import Embedder, get_embedder
from app.rag.loader import corpus_hash, load_corpus

INDEX_DIR = Path(__file__).resolve().parents[2] / "models" / "index"
MATRIX_NAME = "corpus_embeddings.npy"
MANIFEST_NAME = "chunk_manifest.json"

DEFAULT_TOP_K = 5


class IndexError_(RuntimeError):
    """The committed index is missing, malformed, or stale against the corpus."""


@dataclass(frozen=True)
class Retrieved:
    technique_id: str
    name: str
    section: str
    score: float


# An alert's attack type is a snake_case enum, and the embedder is a language
# model: "web_attack" tokenises to "web ## _ ## attack" and "port_scan" to
# something with no relation to ATT&CK's "Network Service Discovery". Handing
# the raw enum to MiniLM measured recall@5 = 0.61 with every web-attack and
# most botnet queries missing entirely.
#
# So the enum is expanded into the vocabulary the corpus is written in. This is
# query construction, not scoring: the phrase describes what the class MEANS,
# and it is applied identically to every alert of that class whether the
# prediction is right or wrong. The ground-truth label never enters here — the
# caller passes the CLASSIFIER's verdict.
_CLASS_VOCABULARY: dict[str, str] = {
    "benign": "normal application traffic, no adversary behaviour",
    "port_scan": (
        "network service discovery and active scanning: enumerating open ports "
        "and remote hosts, probing IP blocks for reachable services"
    ),
    "ddos": (
        "distributed network denial of service: flooding a target with traffic "
        "from many sources to exhaust bandwidth and availability"
    ),
    "dos": (
        "endpoint denial of service: exhausting a service or application's "
        "resources to degrade or block availability for users"
    ),
    "botnet": (
        "command and control communication: an infected host beaconing to "
        "adversary infrastructure over an application layer protocol, "
        "transferring tools and exfiltrating over the channel"
    ),
    "web_attack": (
        "exploiting a public-facing web application: brute forcing credentials, "
        "injecting script or SQL through web parameters, installing a web shell"
    ),
    "brute_force": (
        "brute force of account credentials by guessing or spraying passwords "
        "against a remote service"
    ),
    "exploit_kit": (
        "drive-by compromise delivering an exploit through a web page to a "
        "user's browser"
    ),
    "unknown": "unclassified network activity",
}


def build_query(attack_type: str, signature: str, dest_port: int | None = None) -> str:
    """The text the retriever embeds. ONE definition, shared by serving and eval.

    Phase 3's retrieve node and `scripts/eval_retrieval.py` both call this, so
    the measured recall@k describes the production path rather than a query
    shape that only the benchmark uses.
    """
    parts = [_CLASS_VOCABULARY.get(attack_type, attack_type.replace("_", " "))]
    if dest_port is not None:
        parts.append(f"destination port {dest_port}")
    parts.append(signature)
    return ". ".join(parts)


class Retriever:
    def __init__(
        self, index_dir: Path = INDEX_DIR, embedder: Embedder | None = None
    ) -> None:
        matrix_path = index_dir / MATRIX_NAME
        manifest_path = index_dir / MANIFEST_NAME

        for path in (matrix_path, manifest_path):
            if not path.exists():
                raise IndexError_(
                    f"{path} missing. The index is committed, not built lazily — "
                    "run `python -m scripts.build_index`."
                )

        self._manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self._matrix: np.ndarray = np.load(matrix_path)

        expected = corpus_hash()
        if self._manifest["corpus_sha256"] != expected:
            raise IndexError_(
                f"index was built from corpus {self._manifest['corpus_sha256'][:16]}… "
                f"and the corpus on disk is {expected[:16]}…. Rebuild with "
                "`python -m scripts.build_index` — a stale index returns "
                "confident answers about documents that are no longer there."
            )

        chunks = self._manifest["chunks"]
        if self._matrix.shape != (len(chunks), self._manifest["dimensions"]):
            raise IndexError_(
                f"index matrix is {self._matrix.shape}, manifest says "
                f"({len(chunks)}, {self._manifest['dimensions']})"
            )
        if self._matrix.dtype != np.float32:
            raise IndexError_(f"index matrix dtype is {self._matrix.dtype}, expected float32")

        self._chunks = chunks
        self._names = {t.technique_id: t.name for t in load_corpus()}
        self._embedder = embedder or get_embedder()

    @property
    def chunk_count(self) -> int:
        return len(self._chunks)

    @property
    def dimensions(self) -> int:
        return int(self._manifest["dimensions"])

    def search(self, text: str, top_k: int = DEFAULT_TOP_K) -> list[Retrieved]:
        """Top-k chunks by cosine, DEDUPED TO ONE HIT PER TECHNIQUE.

        Without the dedupe a single technique's four chunks can fill the whole
        result set, so `top_k=5` returns one technique instead of five — the
        grounding set collapses and the model has nothing to choose between.
        """
        query = self._embedder.encode_one(text)
        scores = self._matrix @ query

        best: dict[str, tuple[float, str]] = {}
        for position in np.argsort(-scores):
            chunk = self._chunks[int(position)]
            technique_id = chunk["technique_id"]
            if technique_id not in best:
                best[technique_id] = (float(scores[position]), chunk["section"])
            if len(best) >= top_k:
                break

        return [
            Retrieved(
                technique_id=technique_id,
                name=self._names.get(technique_id, technique_id),
                section=section,
                score=round(score, 6),
            )
            for technique_id, (score, section) in sorted(
                best.items(), key=lambda kv: -kv[1][0]
            )
        ]

    def ground(self, technique_ids: list[str], retrieved: list[Retrieved]) -> list[str]:
        """PLAN §4.4 — a technique the retriever did not return is dropped.

        This is the half MINE never had: the model can name any ID it likes and
        only the ones actually retrieved survive into the output.
        """
        allowed = {r.technique_id for r in retrieved}
        return [t for t in technique_ids if t in allowed]


_retriever: Retriever | None = None


def load_retriever(index_dir: Path = INDEX_DIR) -> Retriever:
    global _retriever
    _retriever = Retriever(index_dir)
    return _retriever


def get_retriever() -> Retriever:
    if _retriever is None:
        raise IndexError_(
            "retriever not loaded. load_retriever() runs in the app lifespan; "
            "reaching retrieval without it means startup was bypassed."
        )
    return _retriever


def reset_retriever() -> None:
    """Test seam. Production loads once and never resets."""
    global _retriever
    _retriever = None
