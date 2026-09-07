"""The three places a check can live must agree. PLAN §13.2.

A check exists in three forms — a Makefile target, a `make.ps1` target, and a
step in `.github/workflows/ci.yml` — and each of those is a separate file that
somebody can edit without touching the others. The failure that follows is the
worst kind: a gate that is green locally and red in CI, or green in CI and never
run locally, with nothing anywhere reporting the divergence.

These tests are the seam. They do not check that the commands WORK — the other
files in this directory do that — they check that the three lists describe the
same set of checks.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

pytestmark = pytest.mark.invariant

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_ROOT.parent

MAKEFILE = BACKEND_ROOT / "Makefile"
MAKE_PS1 = BACKEND_ROOT / "make.ps1"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _makefile_targets() -> set[str]:
    text = MAKEFILE.read_text(encoding="utf-8")
    phony = re.search(r"^\.PHONY:\s*(.+?)(?=\n\w|\n\n)", text, re.M | re.S)
    assert phony, "the Makefile has no .PHONY line to read targets from"
    return set(phony.group(1).replace("\\\n", " ").split())


def _powershell_targets() -> set[str]:
    text = MAKE_PS1.read_text(encoding="utf-8")
    body = text.split("switch ($Target)", 1)[1]
    return set(re.findall(r"^\s*'([a-z-]+)'\s*\{", body, re.M))


def test_the_makefile_and_the_powershell_script_expose_the_same_targets() -> None:
    """`make` is not installed on Windows, and this project is built on Windows.

    A Makefile alone would be a commit gate nobody here could run, which is how
    a repository ends up with a gate only CI enforces.
    """
    make_targets = _makefile_targets() - {"help"}
    ps_targets = _powershell_targets() - {"help"}

    only_make = sorted(make_targets - ps_targets)
    only_ps = sorted(ps_targets - make_targets)

    assert not only_make, f"targets in the Makefile with no make.ps1 equivalent: {only_make}"
    assert not only_ps, f"targets in make.ps1 with no Makefile equivalent: {only_ps}"
    assert "check" in make_targets and "ci" in make_targets


def test_make_check_is_lint_types_tests_in_that_order() -> None:
    """PLAN §13.2 — `make check` is the commit gate and its contents are named."""
    text = MAKEFILE.read_text(encoding="utf-8")
    recipe = re.search(r"^check:\s*(.+)$", text, re.M)
    assert recipe, "no `check` target in the Makefile"
    assert recipe.group(1).split() == ["lint", "types", "test"]


def test_every_ci_check_module_the_workflow_names_actually_exists() -> None:
    """A workflow step naming a module that does not exist fails at 2am."""
    from scripts.ci.checks import ALL_CHECKS

    workflow = WORKFLOW.read_text(encoding="utf-8")
    named = set(re.findall(r"python -m scripts\.ci\.run ([a-z_ ]+)", workflow))
    invoked = {name for group in named for name in group.split()}

    assert invoked, "the workflow does not invoke scripts.ci.run at all"
    unknown = sorted(invoked - set(ALL_CHECKS))
    assert not unknown, f"the workflow runs check(s) that do not exist: {unknown}"


def test_the_workflow_covers_every_check_plan_13_2_lists() -> None:
    """PLAN §13.2 enumerates nine checks. All nine appear in the workflow.

    Asserted against the workflow TEXT rather than against a parsed job graph,
    because what matters is that the command is there — a step that exists but
    is `if: false` would need a different kind of test, and a step that is
    missing entirely is the failure that actually happens.
    """
    workflow = WORKFLOW.read_text(encoding="utf-8")

    # `ruff format --check` is NOT required and its absence is deliberate:
    # PLAN §13.2 names ruff the linter, and a formatter gate introduced in the
    # CI phase would rewrite 107 files from earlier phases.
    required = {
        "1 ruff": "ruff check",
        "2 mypy": "mypy app scripts",
        "3 pytest": "pytest -q",
        "4 disjointness": "scripts.ci.run disjointness",
        "5 artifact integrity": "scripts.ci.run artifact_integrity",
        "6 train/serve skew": "scripts.ci.run train_serve_skew",
        "7 label leak": "scripts.ci.run label_leak",
        "8 secret scan": "scripts.ci.run secret_scan",
        "9 cold-clone smoke": "scripts.ci.smoke",
    }
    missing = [name for name, needle in required.items() if needle not in workflow]
    assert not missing, f"PLAN §13.2 check(s) absent from the workflow: {missing}"


def test_ruff_is_never_run_with_fix_in_ci() -> None:
    """PLAN §13.2 — 'config-only; NEVER --fix in CI'.

    A CI job that rewrites the tree it is checking is reporting on code that is
    not the code under review, and the rewrite is discarded when the runner
    exits — so the defect ships and the board stays green.
    """
    workflow = WORKFLOW.read_text(encoding="utf-8")
    for banned in ("ruff check --fix", "ruff check . --fix", "--unsafe-fixes"):
        assert banned not in workflow, f"the workflow runs `{banned}`"

    # The Makefile's help text SAYS "never --fix", so the check has to look at
    # the recipe rather than at the file — a scan of the whole text would fire
    # on the line that documents the rule.
    makefile = MAKEFILE.read_text(encoding="utf-8")
    recipe = re.search(r"^lint:\n((?:\t.+\n)+)", makefile, re.M)
    assert recipe, "no `lint` recipe in the Makefile"
    assert "--fix" not in recipe.group(1), (
        f"the Makefile's lint target rewrites the tree: {recipe.group(1)!r}"
    )


def test_the_prompt_corpus_is_uploaded_as_a_build_artifact() -> None:
    """PLAN §13.2 check 5 — 'the dump is kept as a build artifact so the claim
    is auditable rather than asserted'."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "prompt_corpus.json" in workflow
    assert "upload-artifact" in workflow
    assert "if-no-files-found: error" in workflow, (
        "a missing dump must fail the step; `warn` would let the label-leak "
        "claim go unevidenced"
    )


def test_warnings_are_errors_in_the_pytest_config() -> None:
    """PLAN §12 — 'a warning fails the run'. Checked in the config, not the
    workflow, so it holds for a local run too."""
    config = tomllib.loads((BACKEND_ROOT / "pyproject.toml").read_text("utf-8"))
    filters = config["tool"]["pytest"]["ini_options"]["filterwarnings"]
    assert filters[0] == "error", (
        "the first filterwarnings entry must be `error`; anything else means "
        "warnings are ignored by default"
    )


def test_every_marker_used_in_the_suite_is_declared() -> None:
    """`--strict-markers` makes a typo a collection error rather than a silently
    unselected test. This asserts the declarations exist to be strict about."""
    config = tomllib.loads((BACKEND_ROOT / "pyproject.toml").read_text("utf-8"))
    options = config["tool"]["pytest"]["ini_options"]

    assert "--strict-markers" in options.get("addopts", "")
    declared = {entry.split(":", 1)[0] for entry in options["markers"]}
    assert {"failure", "load", "invariant", "contract"} <= declared


def test_the_ml_dependencies_are_declared_rather_than_assumed() -> None:
    """A cold clone installs what pyproject names, and nothing else.

    `lightgbm` and `onnxruntime` lived only in the development virtualenv for
    five phases: the app imported fine on a fresh machine and failed at the
    first inference. The cold-clone job is what catches that now, and this is
    what stops the declaration being deleted.
    """
    config = tomllib.loads((BACKEND_ROOT / "pyproject.toml").read_text("utf-8"))
    extras = config["project"]["optional-dependencies"]

    assert "ml" in extras, "there is no `ml` extra for the model stack"
    names = {re.split(r"[><=!\[]", spec)[0].strip() for spec in extras["ml"]}
    assert {"lightgbm", "onnxruntime", "tokenizers", "numpy", "pandas"} <= names

    # D3/D4 — the whole reason the ONNX path exists.
    forbidden = {"torch", "sentence-transformers", "chromadb"}
    everything = set(config["project"]["dependencies"])
    for group in extras.values():
        everything |= set(group)
    all_names = {re.split(r"[><=!\[]", spec)[0].strip() for spec in everything}
    assert not (all_names & forbidden), (
        f"PLAN D3/D4 — {sorted(all_names & forbidden)} is a dependency this "
        "project exists to avoid"
    )


def test_the_workflow_installs_the_ml_extra() -> None:
    """Otherwise the cold-clone job proves the opposite of what it claims."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    installs = re.findall(r"pip install -e \"?\.\[([a-z,]+)\]\"?", workflow)
    assert installs, "the workflow does not install the package with extras"
    for extras in installs:
        assert "ml" in extras.split(","), (
            f"an install step asks for [{extras}] — without `ml` the artifacts "
            "cannot load and the job would be testing a different program"
        )
