"""Every third-party import is declared in `pyproject.toml`. PLAN §13.2 check 7.

**THIS TEST EXISTS BECAUSE THE COLD-CLONE JOB CAUGHT TWO REAL GAPS ON ITS FIRST
RUN.** `langgraph` — the library the entire pipeline is built on — and the ML
stack were installed by hand into the development virtualenv and named in no
dependency list at all. Five phases of green local runs never surfaced it,
because the machine running them already had everything.

The cold-clone job catches this by installing from `pyproject.toml` alone into a
runner that has never seen the project. That job takes minutes; this test takes
milliseconds and fails on the same defect, so the loop closes at commit time
rather than at push time. Both are kept: the static scan cannot see a package
imported only through a plugin entry point, and the cold clone cannot tell you
WHICH import was missing.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

import pytest

pytestmark = pytest.mark.invariant

BACKEND_ROOT = Path(__file__).resolve().parents[2]

#: Distribution name -> the module name it actually installs, where they differ.
DISTRIBUTION_TO_MODULE: dict[str, str] = {
    "pyjwt": "jwt",
    "python-multipart": "multipart",
    "pydantic-settings": "pydantic_settings",
    "scikit-learn": "sklearn",
    "pytest-asyncio": "pytest_asyncio",
    "pandas-stubs": "pandas",
    "types-regex": "regex",
    "types-reportlab": "reportlab",
    "uvicorn[standard]": "uvicorn",
    "pydantic[email]": "pydantic",
    "sqlalchemy[asyncio]": "sqlalchemy",
}

#: Packages in this repository. Not third-party, nothing to declare.
FIRST_PARTY: frozenset[str] = frozenset({"app", "scripts", "tests", "alembic"})


def _declared_modules() -> set[str]:
    config = tomllib.loads((BACKEND_ROOT / "pyproject.toml").read_text("utf-8"))
    project = config["project"]

    specs: list[str] = list(project["dependencies"])
    for group in project.get("optional-dependencies", {}).values():
        specs.extend(group)

    modules: set[str] = set()
    for spec in specs:
        name = spec.split(">")[0].split("<")[0].split("=")[0].split(";")[0].strip()
        bare = name.split("[")[0].strip().lower()
        modules.add(DISTRIBUTION_TO_MODULE.get(name.lower(), bare.replace("-", "_")))
        modules.add(bare.replace("-", "_"))
    return modules


def _imported_top_level(directories: tuple[str, ...]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for directory in directories:
        for path in sorted((BACKEND_ROOT / directory).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    # A relative import resolves inside this package.
                    if node.level == 0 and node.module:
                        names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    found.setdefault(top, []).append(
                        f"{path.relative_to(BACKEND_ROOT)}:{node.lineno}"
                    )
    return found


def test_every_runtime_import_is_a_declared_dependency() -> None:
    """`app/` and `scripts/` are what a cold clone has to be able to import."""
    declared = _declared_modules()
    stdlib = set(sys.stdlib_module_names)
    imported = _imported_top_level(("app", "scripts"))

    undeclared = {
        module: sites
        for module, sites in imported.items()
        if module not in stdlib
        and module not in FIRST_PARTY
        and module not in declared
    }

    assert not undeclared, (
        "these are imported by shipped code and declared in no dependency "
        "list, so `pip install -e .` on a fresh machine produces a package "
        "that cannot import itself:\n"
        + "\n".join(
            f"  {module}: {sites[0]}" + (f" (+{len(sites) - 1} more)" if len(sites) > 1 else "")
            for module, sites in sorted(undeclared.items())
        )
    )


def test_langgraph_is_declared_because_the_pipeline_IS_a_langgraph() -> None:
    """Named explicitly, because this is the one the cold clone actually caught.

    `app/agent/graph.py` builds a real `StateGraph` with real
    `add_conditional_edges` (PLAN §4.1). Without the dependency the module does
    not import and no alert is ever triaged — and `app.main` imports it lazily,
    so the failure surfaces at the FIRST ALERT rather than at startup.
    """
    declared = _declared_modules()
    assert "langgraph" in declared
    assert "starlette" in declared, (
        "app/api/errors.py imports StarletteHTTPException directly; relying on "
        "FastAPI to pull it in breaks the day FastAPI changes its pin"
    )


def test_the_test_dependencies_are_declared_too() -> None:
    """A cold clone that can run the app but not the suite is half a clone."""
    declared = _declared_modules()
    stdlib = set(sys.stdlib_module_names)
    imported = _imported_top_level(("tests",))

    undeclared = sorted(
        module
        for module in imported
        if module not in stdlib
        and module not in FIRST_PARTY
        and module not in declared
    )
    assert not undeclared, f"imported by tests and declared nowhere: {undeclared}"


def test_the_scanner_would_notice_a_missing_declaration() -> None:
    """A check that has never failed is a check you cannot trust.

    The scan reports "clean" when it finds nothing, which is also what it does
    when it is broken. This runs its logic against a synthetic import that is
    definitely not declared.
    """
    declared = _declared_modules()
    stdlib = set(sys.stdlib_module_names)

    synthetic = "definitely_not_a_declared_package"
    assert synthetic not in stdlib
    assert synthetic not in declared
    assert synthetic not in FIRST_PARTY

    # And it does NOT flag a real declaration, a stdlib module, or first-party.
    for benign in ("fastapi", "json", "app"):
        flagged = (
            benign not in stdlib
            and benign not in FIRST_PARTY
            and benign not in declared
        )
        assert not flagged, f"{benign} would be reported as undeclared"
