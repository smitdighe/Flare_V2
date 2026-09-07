"""The CI checks, as importable functions. PLAN §13.2.

Every check here is a plain function returning a `CheckResult`, so it can be run
from `python -m scripts.ci.run`, from a Makefile target, from the GitHub Actions
workflow, and from a test that deliberately breaks its input and asserts it goes
red. **A check that has never failed is a check you cannot trust**, so the tests
in `tests/ci/` corrupt each input in turn and assert the specific check reports
FAIL — an overlapped row for the disjointness check, a corrupted checksum for
artifact integrity, a planted label string for the leak scan.

Each check takes its paths as arguments rather than reading module constants, so
a test can point it at a temporary copy of the tree without touching the real
one and without monkeypatching.
"""

from __future__ import annotations

import ast
import csv
import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_ROOT.parent

SPLITS_DIR = BACKEND_ROOT / "data" / "splits"
MODELS_DIR = BACKEND_ROOT / "models"
CLASSIFIER_DIR = MODELS_DIR / "classifier"
EMBEDDINGS_DIR = MODELS_DIR / "embeddings"
INDEX_DIR = MODELS_DIR / "index"

PARTITIONS: tuple[str, ...] = ("train", "eval", "replay")


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    artifact: Path | None = None

    def line(self) -> str:
        return f"[{'PASS' if self.ok else 'FAIL'}] {self.name}: {self.detail}"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# 4. three-way disjointness — ids AND feature vectors
# ---------------------------------------------------------------------------


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def check_disjointness(splits_dir: Path = SPLITS_DIR) -> CheckResult:
    """PLAN I15 / §7.3b — pairwise disjoint IDs **and** zero shared vectors.

    **THE FEATURE-VECTOR HALF IS THE ONE THAT CAUGHT THE REAL DEFECT.** Row ids
    hash Flow ID and the endpoints, and those differ between two flows with
    byte-identical statistics — so id-level disjointness passed while 62 eval
    rows were, to a classifier that sees neither field, rows it had trained on.
    Both halves run; failing either fails the build.
    """
    import numpy as np

    from app.ml.features import FEATURE_COLUMNS

    missing = [name for name in PARTITIONS if not (splits_dir / f"{name}.csv").exists()]
    if missing:
        return CheckResult(
            "disjointness",
            False,
            f"partition file(s) missing: {missing}. Rebuild with `python -m "
            "scripts.build_partitions`.",
        )

    rows = {name: _read_rows(splits_dir / f"{name}.csv") for name in PARTITIONS}
    evidence: dict[str, Any] = {
        "row_counts": {name: len(value) for name, value in rows.items()}
    }

    ids = {name: {row["row_id"] for row in value} for name, value in rows.items()}
    id_failures: list[str] = []
    for left, right in (("train", "eval"), ("train", "replay"), ("eval", "replay")):
        shared = ids[left] & ids[right]
        if shared:
            id_failures.append(
                f"{len(shared)} row id(s) shared between {left} and {right}, "
                f"e.g. {sorted(shared)[:3]}"
            )
    evidence["id_overlaps"] = id_failures

    def matrix(name: str) -> set[bytes]:
        data = np.array(
            [
                [float(row.get(column) or 0.0) for column in FEATURE_COLUMNS]
                for row in rows[name]
            ],
            dtype=np.float64,
        )
        return {vector.tobytes() for vector in np.ascontiguousarray(data)}

    vectors = {name: matrix(name) for name in PARTITIONS}
    vector_failures: list[str] = []
    for left, right in (("train", "eval"), ("train", "replay"), ("eval", "replay")):
        shared_vectors = vectors[left] & vectors[right]
        if shared_vectors:
            vector_failures.append(
                f"{len(shared_vectors)} feature vector(s) appear verbatim in "
                f"both {left} and {right}"
            )
    evidence["feature_vector_overlaps"] = vector_failures

    failures = id_failures + vector_failures
    if failures:
        return CheckResult(
            "disjointness",
            False,
            "PLAN I15 is violated: " + "; ".join(failures),
            evidence,
        )
    return CheckResult(
        "disjointness",
        True,
        "train/eval/replay are pairwise disjoint by row id AND by 77-feature "
        f"vector ({evidence['row_counts']})",
        evidence,
    )


# ---------------------------------------------------------------------------
# 5. artifact integrity — checksums, plus the schema fingerprint
# ---------------------------------------------------------------------------

CLASSIFIER_CHECKSUMS = CLASSIFIER_DIR / "CHECKSUMS.json"
INDEX_CHECKSUMS = INDEX_DIR / "CHECKSUMS.json"
EMBEDDING_CHECKSUMS = EMBEDDINGS_DIR / "CHECKSUMS.json"


def _verify_checksum_file(
    manifest_path: Path, directory: Path, label: str
) -> tuple[list[str], dict[str, str]]:
    if not manifest_path.exists():
        return ([f"{label}: {manifest_path.name} is missing"], {})

    expected: dict[str, str] = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    actual: dict[str, str] = {}
    for filename, want in expected.items():
        path = directory / filename
        if not path.exists():
            failures.append(f"{label}: {filename} is missing")
            continue
        got = sha256_of(path)
        actual[filename] = got
        if got != want:
            failures.append(
                f"{label}: {filename} checksum mismatch — committed "
                f"{want[:12]}…, on disk {got[:12]}…"
            )
    return failures, actual


def check_artifact_integrity(models_dir: Path = MODELS_DIR) -> CheckResult:
    """PLAN D21 / I16 — the artifacts are EVIDENCE, so they are pinned.

    Four things verify here and the fourth is the one that catches a silent
    inference bug rather than a corrupted download: the classifier's committed
    `feature_schema.json` fingerprint must equal the fingerprint the SERVING
    code computes from `FEATURE_COLUMNS`. A reordered or renamed column changes
    nothing a file checksum can see — the booster still loads, still returns 77
    inputs' worth of prediction, and is now reading the wrong number for every
    column.
    """
    from app.ml.features import FEATURE_COLUMNS, schema_fingerprint

    classifier_dir = models_dir / "classifier"
    failures: list[str] = []
    evidence: dict[str, Any] = {}

    for manifest, directory, label in (
        (classifier_dir / "CHECKSUMS.json", classifier_dir, "classifier"),
        (models_dir / "embeddings" / "CHECKSUMS.json", models_dir / "embeddings", "embeddings"),
        (models_dir / "index" / "CHECKSUMS.json", models_dir / "index", "index"),
    ):
        problems, actual = _verify_checksum_file(manifest, directory, label)
        failures += problems
        evidence[label] = actual

    schema_path = classifier_dir / "feature_schema.json"
    if not schema_path.exists():
        failures.append("classifier: feature_schema.json is missing")
    else:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        serving = schema_fingerprint()
        evidence["schema_fingerprint"] = {
            "committed": schema.get("fingerprint"),
            "serving": serving,
        }
        if schema.get("fingerprint") != serving:
            failures.append(
                "classifier: the committed feature-schema fingerprint "
                f"({str(schema.get('fingerprint'))[:12]}…) does not match the "
                f"fingerprint the serving code computes ({serving[:12]}…). The "
                "model was trained on a different column order or column set "
                "than the one it is now being fed."
            )
        if schema.get("feature_columns") != list(FEATURE_COLUMNS):
            failures.append(
                "classifier: feature_schema.json lists different columns than "
                "app/ml/features.py FEATURE_COLUMNS"
            )
        if schema.get("feature_count") != len(FEATURE_COLUMNS):
            failures.append(
                f"classifier: feature_count is {schema.get('feature_count')}, "
                f"the serving code has {len(FEATURE_COLUMNS)}"
            )

    if failures:
        return CheckResult(
            "artifact_integrity", False, "; ".join(failures), evidence
        )
    return CheckResult(
        "artifact_integrity",
        True,
        "classifier, embedding weights and index all match their committed "
        "checksums, and the feature schema matches the serving fingerprint",
        evidence,
    )


# ---------------------------------------------------------------------------
# 6. train/serve skew
# ---------------------------------------------------------------------------


def check_train_serve_skew(splits_dir: Path = SPLITS_DIR) -> CheckResult:
    """One fixture row through BOTH builders must produce identical vectors.

    **THIS CHECK CAUGHT A REAL BUG.** pandas can return a read-only zero-copy
    view for a single-row frame, and the in-place infinity mask then raised
    "assignment destination is read-only" — so every SINGLE-ROW inference failed
    to `unknown` while batch training worked perfectly. Nothing about the model
    was wrong and no test that only exercised the batch path could see it.
    """
    import numpy as np
    import pandas as pd

    from app.ml.features import FEATURE_COLUMNS, build_matrix, build_vector

    fixture = splits_dir / "eval.csv"
    if not fixture.exists():
        return CheckResult(
            "train_serve_skew", False, f"{fixture} is missing; cannot compare"
        )

    rows = _read_rows(fixture)[:5]
    if not rows:
        return CheckResult("train_serve_skew", False, "eval.csv has no rows")

    frame = pd.DataFrame(rows)
    for column in FEATURE_COLUMNS:
        frame[column] = pd.to_numeric(frame[column], errors="coerce")

    # TRAINING path — the whole frame at once.
    batch = build_matrix(frame)

    # SERVING path — one row at a time, through the single-row builder.
    singles = np.vstack(
        [
            build_vector(
                {column: float(row.get(column) or 0.0) for column in FEATURE_COLUMNS}
            )
            for row in rows
        ]
    )

    if batch.shape != singles.shape:
        return CheckResult(
            "train_serve_skew",
            False,
            f"shape mismatch: training builder produced {batch.shape}, serving "
            f"builder produced {singles.shape}",
        )
    if batch.dtype != singles.dtype:
        return CheckResult(
            "train_serve_skew",
            False,
            f"dtype mismatch: {batch.dtype} vs {singles.dtype} — a float64 "
            "serving vector against a float32-trained booster is silent skew",
        )

    same = np.array_equal(batch, singles, equal_nan=True)
    if not same:
        differing = int(
            np.count_nonzero(~(np.isclose(batch, singles, equal_nan=True)))
        )
        return CheckResult(
            "train_serve_skew",
            False,
            f"{differing} cell(s) differ between the training and serving "
            "feature builders on identical input rows",
            {"shape": list(batch.shape)},
        )
    return CheckResult(
        "train_serve_skew",
        True,
        f"{len(rows)} fixture row(s) produce byte-identical {batch.dtype} "
        f"vectors through both builders",
        {"shape": list(batch.shape), "dtype": str(batch.dtype)},
    )


# ---------------------------------------------------------------------------
# 7. label leak — dump the prompt corpus, then grep it
# ---------------------------------------------------------------------------

#: Every string that would be an answer if it appeared in a prompt: the six
#: canonical classes, and the raw CICIDS spellings they were mapped from.
LEAK_TOKENS: tuple[str, ...] = (
    "ddos",
    "dos hulk",
    "dos goldeneye",
    "dos slowloris",
    "dos slowhttptest",
    "portscan",
    "port scan",
    "port_scan",
    "web attack",
    "web_attack",
    "brute force",
    "sql injection",
    "xss",
    "infiltration",
    "heartbleed",
    "botnet",
    "canonical_class",
    "ground_truth",
    "true_attack_type",
    "true_severity",
)

#: `benign` is deliberately NOT in the list above. It is one of the six enum
#: members the system prompt DECLARES, so it appears in every prompt by design
#: — that is the answer space, not the answer. The tokens above are the ones
#: that would only be present if a specific row's label had travelled.


def check_label_leak(
    sample_size: int = 120, dump_path: Path | None = None
) -> CheckResult:
    """PLAN I4 — dump the constructed prompt corpus and grep it.

    The dump is kept as a build artifact so the claim is AUDITABLE rather than
    asserted: anyone can open the file CI uploaded and read the bytes that would
    have gone to the provider. A prior build put the answer in 450 of 450
    prompts and looked rigorous doing it.
    """
    from app.agent.graph import initial_state
    from app.agent.prompts import build_classify_prompt, build_reason_prompt
    from app.config import Settings
    from app.eval.dataset import load_partition_rows, stratified_sample, to_eval_rows

    # A DETERMINISTIC Settings, built here rather than read from the
    # environment, for two reasons and both of them matter.
    #
    # 1. **A cold clone has no `.env`,** and `jwt_secret` fails closed with no
    #    default (PLAN §9) — correctly, for the app. `get_settings()` here made
    #    `python -m scripts.ci.run` impossible on a fresh checkout, which is
    #    precisely where CI runs it. Found by the cold-clone job.
    # 2. **The dump is committed evidence.** A corpus whose contents depended on
    #    whatever severity floor a developer happened to have set would not be
    #    the corpus CI uploaded, and the whole point of the artifact is that
    #    anyone can compare it to the bytes the shipped system builds.
    #
    # The secret is never used: nothing here signs a token. Only the prompt-
    # shaping fields matter, and they are left at their declared defaults.
    settings = Settings(
        jwt_secret="ci-label-leak-check-not-a-credential-000000",  # noqa: S106
        offline_mode=True,
        _env_file=None,
    )
    rows = to_eval_rows(
        stratified_sample(load_partition_rows("eval"), cap=sample_size, seed=20260904)
    )

    corpus: list[dict[str, Any]] = []
    hits: list[str] = []

    for row in rows:
        state = initial_state(row.alert, settings)
        prompts = {"classify": build_classify_prompt(state)}
        try:
            prompts["reason"] = build_reason_prompt(state, [])
        except Exception as exc:
            prompts["reason"] = f"<not constructible: {type(exc).__name__}: {exc}>"

        corpus.append(
            {
                "alert_id": row.alert.id,
                # The truth is recorded BESIDE the prompt in the dump so a
                # reader can check for themselves that it is not IN it.
                "withheld_true_attack_type": row.true_attack_type,
                "withheld_true_severity": row.true_severity,
                "prompts": prompts,
            }
        )

        for name, text in prompts.items():
            lowered = text.lower()
            for token in LEAK_TOKENS:
                if token in lowered:
                    hits.append(f"{row.alert.id} [{name}]: {token!r}")
            if row.true_attack_type != "benign" and row.true_attack_type in lowered:
                hits.append(
                    f"{row.alert.id} [{name}]: its own label "
                    f"{row.true_attack_type!r}"
                )

    dump = dump_path or (BACKEND_ROOT / "build" / "prompt_corpus.json")
    dump.parent.mkdir(parents=True, exist_ok=True)
    dump.write_text(
        json.dumps(
            {
                "generated_from": "data/splits/eval.csv",
                "sample_size": len(rows),
                "seed": 20260904,
                "scanned_for": list(LEAK_TOKENS),
                "note": (
                    "`benign` is excluded from the scan list on purpose: it is "
                    "an enum member the system prompt declares, so it is the "
                    "answer SPACE rather than any row's answer."
                ),
                "hits": hits,
                "corpus": corpus,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    if hits:
        return CheckResult(
            "label_leak",
            False,
            f"{len(hits)} label string(s) reached a constructed prompt: "
            + "; ".join(hits[:5]),
            {"hits": hits[:50]},
            dump,
        )
    return CheckResult(
        "label_leak",
        True,
        f"{len(corpus)} alerts x {len(corpus[0]['prompts'])} prompts scanned for "
        f"{len(LEAK_TOKENS)} label strings; zero hits",
        {"sample_size": len(rows)},
        dump,
    )


# ---------------------------------------------------------------------------
# 8. secret scan
# ---------------------------------------------------------------------------

#: Provider key shapes, keyed by what they belong to. Anchored on the vendor
#: prefix rather than on entropy: an entropy heuristic on a repo that commits
#: checksums, ONNX weights and a numpy index is nothing but false positives.
SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("groq", r"gsk_[A-Za-z0-9]{20,}"),
    ("google", r"AIza[0-9A-Za-z_\-]{30,}"),
    ("openai", r"sk-[A-Za-z0-9]{32,}"),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("slack", r"xox[abprs]-[0-9A-Za-z-]{10,}"),
    ("github", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("private_key_block", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
)

#: Files that MUST NOT be committed at all, checked by name.
FORBIDDEN_FILES: tuple[str, ...] = (".env", "flare.db", "*.db", "*.sqlite", "*.sqlite3")

SCAN_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".next",
    }
)

SCAN_SKIP_SUFFIXES: frozenset[str] = frozenset(
    {".onnx", ".npy", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff", ".woff2"}
)


def _gitignore_patterns(root: Path) -> list[str]:
    """Every pattern from every .gitignore in the tree, flattened.

    Deliberately simple: this is used to decide what a `git add .` WOULD
    commit, and the patterns in this project are plain globs and directory
    names. Anything more exotic would want `pathspec`, and adding a dependency
    to a security check is a poor trade.
    """
    patterns: list[str] = []
    for path in [root / ".gitignore", *root.glob("*/.gitignore")]:
        if not path.exists():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and not line.startswith("!"):
                patterns.append(line.rstrip("/"))
    return patterns


def _is_ignored(relative: Path, patterns: Sequence[str]) -> bool:
    from fnmatch import fnmatch

    parts = relative.parts
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch(relative.as_posix(), pattern.lstrip("/")):
                return True
            continue
        if any(fnmatch(part, pattern) for part in parts):
            return True
    return False


def _tracked_files(root: Path) -> list[Path] | None:
    """What git actually tracks, when git can tell us.

    `git ls-files` is the authority on what is committed, and the whole rule is
    about what is committed. When there is no git repository yet — which is the
    state of this tree until Phase 7 initialises one — this returns None and the
    caller falls back to walking the tree while honouring .gitignore, which
    answers the same question one step earlier: what a `git add .` would take.
    """
    import subprocess

    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z"],  # noqa: S607
            cwd=root,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 or not completed.stdout:
        return None
    names = completed.stdout.decode("utf-8", errors="replace").split("\0")
    return [root / name for name in names if name]


def _scannable_files(root: Path) -> tuple[list[Path], str]:
    """The files a secret scan should look at, and how they were chosen.

    **THE DISTINCTION MATTERS AND IT IS NOT PEDANTRY.** A developer's working
    `.env` is expected to exist and is gitignored; flagging it would make the
    check cry wolf on every workstation until somebody adds `--no-verify` to
    their habit. What must never exist is a `.env` that is TRACKED. So the scan
    asks git what is tracked, and when there is no repository yet it asks
    .gitignore what a commit would take.
    """
    tracked = _tracked_files(root)
    if tracked is not None:
        candidates = [path for path in tracked if path.is_file()]
        source = f"git ls-files ({len(candidates)} tracked)"
    else:
        patterns = _gitignore_patterns(root)
        candidates = [
            path
            for path in root.rglob("*")
            if path.is_file() and not _is_ignored(path.relative_to(root), patterns)
        ]
        source = f"tree walk honouring .gitignore ({len(patterns)} patterns)"

    keep: list[Path] = []
    for path in candidates:
        if any(part in SCAN_SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SCAN_SKIP_SUFFIXES:
            continue
        # The dataset CSVs are committed evidence, are large, and are flow
        # statistics; scanning them costs minutes and can only produce false
        # positives on a base64-shaped pattern.
        if path.suffix.lower() == ".csv" and path.stat().st_size > 2_000_000:
            continue
        keep.append(path)
    return keep, source


def check_secrets(root: Path = REPO_ROOT) -> CheckResult:
    """PLAN §9 — no provider key, `.env` or `.db` ever committed.

    Three separate things, because they fail differently: a key MATERIALISED in
    a committed file, a forbidden FILE committed, and key material inside a
    trace FIXTURE — the last being the one that slips through review, since a
    trace fixture looks like test data rather than like a credential.
    """
    compiled = [(name, re.compile(pattern)) for name, pattern in SECRET_PATTERNS]
    findings: list[str] = []
    files, source = _scannable_files(root)
    scanned = 0

    for path in files:
        relative = path.relative_to(root)

        # `.env` is the file the whole rule is about. `.env.example` is the
        # documented template and IS meant to be committed — it must carry no
        # material, which the pattern scan below checks like any other file.
        if path.name == ".env":
            findings.append(f"{relative}: a .env file is committed")
        if path.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
            findings.append(f"{relative}: a database file is committed")
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1

        for name, pattern in compiled:
            for match in pattern.finditer(text):
                line = text[: match.start()].count("\n") + 1
                findings.append(
                    f"{relative}:{line}: possible {name} credential "
                    f"({match.group(0)[:8]}\u2026)"
                )

    if findings:
        return CheckResult(
            "secret_scan",
            False,
            f"{len(findings)} finding(s): " + "; ".join(findings[:5]),
            {"findings": findings[:50], "files_scanned": scanned, "source": source},
        )
    return CheckResult(
        "secret_scan",
        True,
        f"{scanned} text file(s) scanned via {source} for {len(compiled)} "
        "credential shapes; no committed .env, no committed database, no key "
        "material",
        {"files_scanned": scanned, "source": source},
    )


def check_gitignore(root: Path = REPO_ROOT) -> CheckResult:
    """The scan above catches what IS there; this catches what will be.

    A `.gitignore` that does not name `.env` means the next `git add .` commits
    one, and the scan only finds it after the fact.
    """
    candidates = [root / ".gitignore", root / "backend" / ".gitignore"]
    present = [path for path in candidates if path.exists()]
    if not present:
        return CheckResult("gitignore", False, "no .gitignore anywhere in the tree")

    text = "\n".join(path.read_text(encoding="utf-8") for path in present)
    required = (".env", "*.db", "__pycache__", ".venv")
    missing = [entry for entry in required if entry not in text]
    if missing:
        return CheckResult(
            "gitignore",
            False,
            f".gitignore does not exclude {missing}",
            {"files": [str(p) for p in present]},
        )
    return CheckResult(
        "gitignore",
        True,
        f".gitignore excludes {list(required)}",
        {"files": [str(p) for p in present]},
    )


# ---------------------------------------------------------------------------
# helpers used by more than one check
# ---------------------------------------------------------------------------


def check_no_metric_literals(app_dir: Path | None = None) -> CheckResult:
    """PLAN I2, as a CI check rather than only as a test.

    Kept here as well as in the invariant suite so a CI job can report it as its
    own line rather than as one failure inside 700 tests.
    """
    root = app_dir or (BACKEND_ROOT / "app")
    metric_keys = {
        "avg_latency_ms",
        "attack_type_accuracy",
        "severity_accuracy",
        "binary_detection_accuracy",
        "high_severity_f1",
        "success_rate",
    }
    offenders: list[str] = []

    for path in sorted(root.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values, strict=True):
                if not isinstance(key, ast.Constant) or key.value not in metric_keys:
                    continue
                if not (
                    isinstance(value, ast.Constant)
                    and isinstance(value.value, (int, float))
                ):
                    continue
                window = "".join(lines[max(0, value.lineno - 4) : value.lineno])
                if "setdefault" in window:
                    continue
                offenders.append(f"{path.relative_to(BACKEND_ROOT)}:{value.lineno}")

    if offenders:
        return CheckResult(
            "metric_literals", False, "hardcoded metric(s): " + ", ".join(offenders)
        )
    return CheckResult("metric_literals", True, "no metric is assigned a literal")


def check_env_example(backend_root: Path | None = None) -> CheckResult:
    """PLAN §14 — the `.env.example` is COMPLETE and accurate.

    **A SETTING THAT EXISTS AND IS DOCUMENTED NOWHERE IS A SETTING NOBODY CAN
    SET.** Thirty-one of eighty-seven were missing when this check was written,
    including every provider key — so a cold clone following the template could
    only run in offline mode, and §10.3's fail-closed startup would name a
    variable the template never mentioned. Same family as an undeclared
    dependency: the working `.env` has it, so nobody notices the template
    does not.

    Both directions are checked. A documented variable that no `Settings` field
    reads is a dead flag, which §14 forbids just as plainly.
    """
    root = backend_root or BACKEND_ROOT
    example = root / ".env.example"
    if not example.exists():
        return CheckResult("env_example", False, f"{example} is missing")

    from app.config import Settings

    text = example.read_text(encoding="utf-8")
    documented = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", text, re.M))
    fields = {name.upper() for name in Settings.model_fields}

    undocumented = sorted(fields - documented)
    # `DEMO_SEED_ENABLED` and friends are real fields; anything documented that
    # is NOT a field is either a rename that was never finished or a flag the
    # code stopped reading.
    dead = sorted(documented - fields - {"FLARE_DISABLE_ENV_FILE"})

    failures: list[str] = []
    if undocumented:
        failures.append(
            f"{len(undocumented)} setting(s) read by code and documented "
            f"nowhere: {undocumented[:6]}"
            + ("…" if len(undocumented) > 6 else "")
        )
    if dead:
        failures.append(
            f"{len(dead)} variable(s) documented that no Settings field reads "
            f"(PLAN §14 forbids dead flags): {dead}"
        )

    if failures:
        return CheckResult(
            "env_example",
            False,
            "; ".join(failures),
            {"undocumented": undocumented, "dead": dead},
        )
    return CheckResult(
        "env_example",
        True,
        f"all {len(fields)} settings are documented in .env.example and nothing "
        "is documented that the code does not read",
        {"settings": len(fields)},
    )


ALL_CHECKS: tuple[str, ...] = (
    "disjointness",
    "artifact_integrity",
    "train_serve_skew",
    "label_leak",
    "secret_scan",
    "gitignore",
    "env_example",
    "metric_literals",
)


def run_named(names: Sequence[str]) -> list[CheckResult]:
    # All seven take only defaulted arguments, so each is callable with none.
    # Annotated because the values have different signatures and mypy would
    # otherwise widen the dict's value type to `object`.
    registry: dict[str, Callable[[], CheckResult]] = {
        "disjointness": check_disjointness,
        "artifact_integrity": check_artifact_integrity,
        "train_serve_skew": check_train_serve_skew,
        "label_leak": check_label_leak,
        "secret_scan": check_secrets,
        "gitignore": check_gitignore,
        "env_example": check_env_example,
        "metric_literals": check_no_metric_literals,
    }
    unknown = [name for name in names if name not in registry]
    if unknown:
        raise SystemExit(f"unknown check(s) {unknown}; known: {sorted(registry)}")
    return [registry[name]() for name in names]
