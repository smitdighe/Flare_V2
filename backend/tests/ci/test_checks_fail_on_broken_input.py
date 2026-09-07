"""Every CI check is proved to FAIL on a deliberately broken input. PLAN §13.2.

**A CHECK THAT HAS NEVER FAILED IS A CHECK YOU CANNOT TRUST.** Each check in
`scripts/ci/checks.py` returns PASS today. That is exactly the state a check
would be in if it were silently broken — if it globbed the wrong directory, or
compared a value to itself, or found zero files to scan and reported success. A
green board proves nothing about a scanner nobody has ever seen go red.

So each check here is run twice: once against the real tree, where it must PASS,
and once against a copy of the tree with the specific defect it exists to catch
planted in it, where it must FAIL **and name the planted defect**. Every
negative case works on a temporary copy; nothing here touches the real
partitions, the real artifacts, or the real repository.

  * overlap a row       -> disjointness FAILS
  * corrupt a checksum  -> artifact integrity FAILS
  * plant a label       -> label leak FAILS
  * commit a key        -> secret scan FAILS
  * skew a builder      -> train/serve skew FAILS
"""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

import pytest

from scripts.ci import checks

pytestmark = pytest.mark.invariant

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REAL_SPLITS = BACKEND_ROOT / "data" / "splits"
REAL_MODELS = BACKEND_ROOT / "models"


# ---------------------------------------------------------------------------
# 4. disjointness
# ---------------------------------------------------------------------------


def test_disjointness_passes_on_the_real_partitions() -> None:
    result = checks.check_disjointness(REAL_SPLITS)
    assert result.ok, result.detail
    assert result.evidence["row_counts"] == {
        "train": 5400,
        "eval": 1800,
        "replay": 1800,
    }


def _copy_splits(tmp_path: Path) -> Path:
    target = tmp_path / "splits"
    target.mkdir()
    for name in ("train", "eval", "replay"):
        shutil.copy2(REAL_SPLITS / f"{name}.csv", target / f"{name}.csv")
    return target


def _read(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def _write(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_disjointness_FAILS_when_a_row_id_is_shared(tmp_path: Path) -> None:
    """The id-level half. Copy one train row's id onto an eval row."""
    splits = _copy_splits(tmp_path)
    _, train_rows = _read(splits / "train.csv")
    eval_fields, eval_rows = _read(splits / "eval.csv")

    eval_rows[0]["row_id"] = train_rows[0]["row_id"]
    _write(splits / "eval.csv", eval_fields, eval_rows)

    result = checks.check_disjointness(splits)

    assert not result.ok, "one shared row id must fail the build"
    assert "row id(s) shared between train and eval" in result.detail
    assert result.evidence["id_overlaps"]


def test_disjointness_FAILS_when_a_FEATURE_VECTOR_is_shared_but_the_id_is_not(
    tmp_path: Path,
) -> None:
    """PLAN §7.3b — THE CHECK THAT CAUGHT THE REAL DEFECT.

    This is the exact shape of the Phase 2a bug: the row id differs, so the
    id-level check is clean, while the 77-feature vector is byte-identical and
    the classifier is being tested on a row it trained on. An id-only check
    passes this and a build with it would be wrong in exactly the way that
    matters.
    """
    from app.ml.features import FEATURE_COLUMNS

    splits = _copy_splits(tmp_path)
    _, train_rows = _read(splits / "train.csv")
    eval_fields, eval_rows = _read(splits / "eval.csv")

    # Copy the feature vector across, keep the eval row's own id.
    for column in FEATURE_COLUMNS:
        eval_rows[0][column] = train_rows[0][column]
    assert eval_rows[0]["row_id"] != train_rows[0]["row_id"]
    _write(splits / "eval.csv", eval_fields, eval_rows)

    result = checks.check_disjointness(splits)

    assert not result.ok, (
        "a shared FEATURE VECTOR with a different row id is the defect that "
        "shipped once already; an id-only check would call this clean"
    )
    assert not result.evidence["id_overlaps"], (
        "the id-level check is genuinely clean here — which is the point"
    )
    assert result.evidence["feature_vector_overlaps"]
    assert "feature vector(s) appear verbatim in both train and eval" in result.detail


def test_disjointness_FAILS_when_a_partition_is_missing(tmp_path: Path) -> None:
    splits = _copy_splits(tmp_path)
    (splits / "replay.csv").unlink()

    result = checks.check_disjointness(splits)
    assert not result.ok
    assert "replay" in result.detail


# ---------------------------------------------------------------------------
# 5. artifact integrity
# ---------------------------------------------------------------------------


def test_artifact_integrity_passes_on_the_real_artifacts() -> None:
    result = checks.check_artifact_integrity(REAL_MODELS)
    assert result.ok, result.detail
    assert result.evidence["schema_fingerprint"]["committed"] == (
        result.evidence["schema_fingerprint"]["serving"]
    )


def _copy_models(tmp_path: Path) -> Path:
    target = tmp_path / "models"
    shutil.copytree(REAL_MODELS, target)
    return target


def test_artifact_integrity_FAILS_on_a_corrupted_checksum(tmp_path: Path) -> None:
    """Change one hex digit in the committed manifest."""
    models = _copy_models(tmp_path)
    manifest_path = models / "classifier" / "CHECKSUMS.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    booster = "attack_type.booster.txt"
    original = manifest[booster]
    manifest[booster] = ("f" if original[0] != "f" else "0") + original[1:]
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    result = checks.check_artifact_integrity(models)

    assert not result.ok
    assert "checksum mismatch" in result.detail
    assert booster in result.detail


def test_artifact_integrity_FAILS_on_a_MODIFIED_ARTIFACT(tmp_path: Path) -> None:
    """The other direction: the manifest is honest and the FILE changed.

    This is the case that actually happens — a booster regenerated without a
    training run, or a file truncated by a bad copy.
    """
    models = _copy_models(tmp_path)
    booster = models / "classifier" / "attack_type.booster.txt"
    booster.write_text(
        booster.read_text(encoding="utf-8") + "\n# an unrecorded edit\n",
        encoding="utf-8",
    )

    result = checks.check_artifact_integrity(models)
    assert not result.ok
    assert "attack_type.booster.txt" in result.detail


def test_artifact_integrity_FAILS_when_an_artifact_is_missing(
    tmp_path: Path,
) -> None:
    models = _copy_models(tmp_path)
    (models / "embeddings" / "model_quantized.onnx").unlink()

    result = checks.check_artifact_integrity(models)
    assert not result.ok
    assert "model_quantized.onnx is missing" in result.detail


def test_artifact_integrity_FAILS_when_the_SCHEMA_FINGERPRINT_diverges(
    tmp_path: Path,
) -> None:
    """The half a file checksum cannot see.

    A reordered column list still loads, still returns a prediction, and is now
    reading the wrong number for every feature. Only the fingerprint catches it.
    """
    models = _copy_models(tmp_path)
    schema_path = models / "classifier" / "feature_schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema["fingerprint"] = "0" * 64
    schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")

    # Re-stamp the checksum so the FILE verifies and only the fingerprint is
    # wrong — otherwise this test would pass for the wrong reason.
    manifest_path = models / "classifier" / "CHECKSUMS.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["feature_schema.json"] = checks.sha256_of(schema_path)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    result = checks.check_artifact_integrity(models)

    assert not result.ok
    assert "does not match the fingerprint the serving code computes" in result.detail


def test_artifact_integrity_FAILS_when_the_column_LIST_diverges(
    tmp_path: Path,
) -> None:
    from app.ml.features import FEATURE_COLUMNS

    models = _copy_models(tmp_path)
    schema_path = models / "classifier" / "feature_schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    columns = list(FEATURE_COLUMNS)
    columns[0], columns[1] = columns[1], columns[0]
    schema["feature_columns"] = columns
    schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")

    manifest_path = models / "classifier" / "CHECKSUMS.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["feature_schema.json"] = checks.sha256_of(schema_path)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    result = checks.check_artifact_integrity(models)
    assert not result.ok
    assert "different columns" in result.detail


# ---------------------------------------------------------------------------
# 6. train/serve skew
# ---------------------------------------------------------------------------


def test_train_serve_skew_passes_on_the_real_builders() -> None:
    result = checks.check_train_serve_skew(REAL_SPLITS)
    assert result.ok, result.detail
    assert result.evidence["dtype"] == "float32"


def test_train_serve_skew_FAILS_when_the_serving_builder_diverges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inject the skew, and watch the check catch it.

    The real bug this guards against was subtler than a scaled column — pandas
    handed back a read-only view and the single-row path raised — but the check
    is the same one either way: identical input through both builders must
    produce identical output, and here it deliberately does not.
    """
    import app.ml.features as features_mod

    real_build_vector = features_mod.build_vector

    def skewed(row: dict[str, float]):  # type: ignore[no-untyped-def]
        vector = real_build_vector(row).copy()
        vector[0][0] = vector[0][0] + 1.0  # a units bug, one column wide
        return vector

    monkeypatch.setattr(features_mod, "build_vector", skewed)

    result = checks.check_train_serve_skew(REAL_SPLITS)

    assert not result.ok, (
        "a one-column divergence between the training and serving builders is "
        "exactly the silent skew this check exists for"
    )
    assert "differ between the training and serving feature builders" in result.detail


def test_train_serve_skew_FAILS_on_a_DTYPE_divergence(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """float64 serving vectors against a float32-trained booster is skew too,
    and it is invisible to an equality check that casts."""
    import numpy as np

    import app.ml.features as features_mod

    real_build_vector = features_mod.build_vector

    def widened(row: dict[str, float]):  # type: ignore[no-untyped-def]
        return real_build_vector(row).astype(np.float64)

    monkeypatch.setattr(features_mod, "build_vector", widened)

    result = checks.check_train_serve_skew(REAL_SPLITS)
    assert not result.ok
    assert "dtype mismatch" in result.detail


# ---------------------------------------------------------------------------
# 7. label leak
# ---------------------------------------------------------------------------


def test_label_leak_passes_on_the_real_prompts(tmp_path: Path) -> None:
    result = checks.check_label_leak(sample_size=24, dump_path=tmp_path / "dump.json")
    assert result.ok, result.detail

    # The dump is a build artifact and must be readable evidence, not a claim.
    dump = json.loads((tmp_path / "dump.json").read_text(encoding="utf-8"))
    assert dump["hits"] == []
    assert dump["sample_size"] == 24
    assert len(dump["corpus"]) == 24
    for entry in dump["corpus"]:
        assert entry["prompts"]["classify"]
        assert entry["withheld_true_attack_type"], (
            "the truth is recorded BESIDE the prompt so a reader can verify for "
            "themselves that it is not IN it"
        )
        # `benign` is the one label that legitimately appears, because it is an
        # enum member the system prompt declares — the answer SPACE, not this
        # row's answer. Every other label must be absent from the bytes.
        if entry["withheld_true_attack_type"] != "benign":
            assert (
                entry["withheld_true_attack_type"]
                not in entry["prompts"]["classify"].lower()
            ), f"{entry['alert_id']} carries its own answer in its prompt"


def test_label_leak_FAILS_when_a_label_is_planted_in_a_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plant the answer, exactly the way a prior build did by accident.

    That build pasted the raw CICIDS label into the synthesized signature and
    then put the signature into the prompt — 450 of 450 prompts contained the
    answer in plain text. This reproduces the shape and asserts the scan catches
    it.
    """
    import app.agent.prompts as prompts_mod

    real_builder = prompts_mod.build_classify_prompt

    def leaking(state):  # type: ignore[no-untyped-def]
        # The signature is where the prior build's leak lived.
        return real_builder(state) + "\n\nSignature note: CICIDS DDoS flow"

    monkeypatch.setattr(prompts_mod, "build_classify_prompt", leaking)

    result = checks.check_label_leak(sample_size=8, dump_path=tmp_path / "leak.json")

    assert not result.ok, "a planted label string must fail the build (PLAN I4)"
    assert "label string(s) reached a constructed prompt" in result.detail
    assert "'ddos'" in result.detail

    dump = json.loads((tmp_path / "leak.json").read_text(encoding="utf-8"))
    assert dump["hits"], "and the dump records the hits for an auditor"


def test_label_leak_FAILS_on_the_rows_OWN_label_even_if_it_is_not_in_the_token_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The token list is a belt; the per-row check is the braces.

    A label the token list happened to miss still fails, because every row is
    additionally scanned for its own answer.
    """
    import app.agent.prompts as prompts_mod
    from app.eval.dataset import load_partition_rows, stratified_sample, to_eval_rows

    rows = to_eval_rows(
        stratified_sample(load_partition_rows("eval"), cap=8, seed=20260904)
    )
    truths = {row.alert.id: row.true_attack_type for row in rows}
    real_builder = prompts_mod.build_classify_prompt

    def leaking(state):  # type: ignore[no-untyped-def]
        answer = truths.get(state.alert_id, "")
        return real_builder(state) + f"\n\nAnalyst note: looks like {answer}."

    monkeypatch.setattr(prompts_mod, "build_classify_prompt", leaking)

    result = checks.check_label_leak(sample_size=8, dump_path=tmp_path / "own.json")
    assert not result.ok
    assert "reached a constructed prompt" in result.detail
    dump = json.loads((tmp_path / "own.json").read_text(encoding="utf-8"))
    assert any("its own label" in hit for hit in dump["hits"]), (
        "the per-row check is what caught it, not the token list"
    )


def test_the_leak_scanner_deliberately_ignores_benign(tmp_path: Path) -> None:
    """`benign` is the answer SPACE, not any row's answer.

    It is one of the six enum members the system prompt declares, so it appears
    in every prompt by construction. Scanning for it would make the check fire
    on every honest run, which is how a guard gets ignored.
    """
    assert "benign" not in checks.LEAK_TOKENS
    result = checks.check_label_leak(sample_size=8, dump_path=tmp_path / "b.json")
    assert result.ok


# ---------------------------------------------------------------------------
# 8. secret scan
# ---------------------------------------------------------------------------


def test_secret_scan_passes_on_the_real_tree() -> None:
    result = checks.check_secrets(checks.REPO_ROOT)
    assert result.ok, result.detail
    assert result.evidence["files_scanned"] > 50, (
        "a scanner that found almost nothing to scan reports PASS for the wrong "
        "reason; this pins that it actually looked"
    )


def _tree_with(tmp_path: Path, name: str, content: str) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text(".env\n*.db\n__pycache__\n.venv\n", "utf-8")
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(content, encoding="utf-8")
    return root


@pytest.mark.parametrize(
    ("label", "planted"),
    [
        ("groq", "GROQ_API_KEY_DEV=gsk_" + "A" * 40),
        ("google", "GEMINI_API_KEY_DEV=AIza" + "B" * 35),
        ("openai", "OPENAI_API_KEY=sk-" + "C" * 40),
        ("aws_access_key", "aws_key = 'AKIA" + "D" * 16 + "'"),
        ("github", "token: ghp_" + "E" * 36),
        # Assembled from fragments on purpose. Written as one literal, this
        # fixture makes the scanner flag THIS FILE when it scans the real tree —
        # which is the scanner being right, so the fixture is what changes.
        (
            "private_key_block",
            "-----BEGIN " + "RSA PRIVATE" + " KEY-----\nMIIEow==\n",
        ),
    ],
)
def test_secret_scan_FAILS_on_each_credential_shape(
    tmp_path: Path, label: str, planted: str
) -> None:
    root = _tree_with(tmp_path, "config/settings.py", f'VALUE = """{planted}"""\n')

    result = checks.check_secrets(root)

    assert not result.ok, f"a {label} credential was committed and the scan passed"
    assert label in result.detail


def test_secret_scan_FAILS_on_key_material_inside_a_TRACE_FIXTURE(
    tmp_path: Path,
) -> None:
    """PLAN I16 — the case that slips through review.

    A trace fixture looks like test data, so a key pasted into one reads as a
    plausible string rather than as a credential. The scan does not care where
    it is.
    """
    fixture = json.dumps(
        {
            "node": "reason",
            "status": "ok",
            "provider": "groq",
            "key_id": "groq-dev",
            "raw_key": "gsk_" + "Z" * 40,
        },
        indent=2,
    )
    root = _tree_with(tmp_path, "tests/fixtures/trace.json", fixture)

    result = checks.check_secrets(root)
    assert not result.ok
    assert "groq credential" in result.detail
    assert "trace.json" in result.detail


def test_secret_scan_FAILS_on_a_COMMITTED_dotenv(tmp_path: Path) -> None:
    """The file, by name, even if it happens to contain no live key."""
    root = tmp_path / "repo"
    root.mkdir()
    # No .gitignore, so a tree walk treats everything as committed.
    (root / ".env").write_text("JWT_SECRET=x\n", encoding="utf-8")

    result = checks.check_secrets(root)
    assert not result.ok
    assert "a .env file is committed" in result.detail


def test_secret_scan_FAILS_on_a_COMMITTED_database(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "flare.db").write_bytes(b"SQLite format 3\x00")

    result = checks.check_secrets(root)
    assert not result.ok
    assert "a database file is committed" in result.detail


def test_secret_scan_does_NOT_fail_on_a_gitignored_working_dotenv(
    tmp_path: Path,
) -> None:
    """The distinction that stops the check crying wolf on every workstation.

    A developer's local `.env` is expected to exist and is gitignored. Flagging
    it teaches people to pass `--no-verify`, and a check people route around is
    worse than no check.
    """
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text(".env\n*.db\n", encoding="utf-8")
    (root / ".env").write_text("GROQ_API_KEY_DEV=gsk_" + "A" * 40, encoding="utf-8")
    (root / "README.md").write_text("nothing secret here\n", encoding="utf-8")

    result = checks.check_secrets(root)
    assert result.ok, (
        "a gitignored .env is not a committed .env, and the check must say so: "
        f"{result.detail}"
    )


def test_gitignore_check_FAILS_when_dotenv_is_not_excluded(tmp_path: Path) -> None:
    """Catches it one step earlier than the scan: the NEXT `git add .`."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text("__pycache__\n.venv\n*.db\n", encoding="utf-8")

    result = checks.check_gitignore(root)
    assert not result.ok
    assert ".env" in result.detail


# ---------------------------------------------------------------------------
# the runner itself
# ---------------------------------------------------------------------------


def test_the_runner_reports_every_check_and_exits_zero_when_clean() -> None:
    results = checks.run_named(list(checks.ALL_CHECKS))

    assert len(results) == len(checks.ALL_CHECKS)
    assert {r.name for r in results} == set(checks.ALL_CHECKS)
    failed = [r.line() for r in results if not r.ok]
    assert not failed, "\n".join(failed)


def test_the_runner_rejects_an_unknown_check_name() -> None:
    with pytest.raises(SystemExit, match="unknown check"):
        checks.run_named(["not_a_real_check"])


# ---------------------------------------------------------------------------
# .env.example completeness — PLAN §14
# ---------------------------------------------------------------------------


def test_env_example_passes_on_the_real_template() -> None:
    result = checks.check_env_example()
    assert result.ok, result.detail
    assert result.evidence["settings"] > 50, (
        "a template check that found almost no settings would pass for the "
        "wrong reason; this pins that it actually read the model"
    )


def test_env_example_FAILS_when_a_setting_is_undocumented(tmp_path: Path) -> None:
    """The defect this caught: 31 of 87 missing, every provider key among them.

    A cold clone following that template could only run in offline mode, and
    §10.3's fail-closed startup would name a variable the template never
    mentioned.
    """
    root = tmp_path / "backend"
    root.mkdir()
    real = (BACKEND_ROOT / ".env.example").read_text(encoding="utf-8")
    stripped = "\n".join(
        line
        for line in real.splitlines()
        if not line.lstrip("# ").startswith("GROQ_API_KEY_DEV=")
    )
    (root / ".env.example").write_text(stripped, encoding="utf-8")

    result = checks.check_env_example(root)

    assert not result.ok
    assert "documented" in result.detail
    assert result.evidence["undocumented"] == ["GROQ_API_KEY_DEV"], (
        "exactly the one variable that was removed, and nothing else"
    )


def test_env_example_FAILS_on_a_DEAD_FLAG(tmp_path: Path) -> None:
    """PLAN §14 — 'no dead flags'. The other direction, and it matters:

    a documented variable that no `Settings` field reads is a knob an operator
    will turn expecting an effect, and get none.
    """
    root = tmp_path / "backend"
    root.mkdir()
    real = (BACKEND_ROOT / ".env.example").read_text(encoding="utf-8")
    (root / ".env.example").write_text(
        real + "\n# A knob nothing reads.\nENABLE_TIME_TRAVEL=true\n", encoding="utf-8"
    )

    result = checks.check_env_example(root)

    assert not result.ok
    assert "dead flags" in result.detail
    assert "ENABLE_TIME_TRAVEL" in result.evidence["dead"]
