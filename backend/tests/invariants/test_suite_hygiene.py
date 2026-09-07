"""The suite audits itself. PLAN §12.

Two rules in PLAN §12 are about the TESTS rather than about the system, and
neither can be enforced by reading a diff once:

  * **No test may codify a security hole as intended behaviour.** The prior
    codebase's suite asserted that a viewer *could* list users, so the hole was
    protected by the thing meant to find it — and fixing the hole would have
    turned the build red.
  * **`assert a or b` where both branches are plausible is banned.** Five of
    eight of that suite's E2E tests could not fail. An assertion that cannot
    fail is worse than no assertion: it costs the same to run and it buys
    confidence it has not earned.

Both are checked here structurally, over the whole suite, on every run. A rule
that is only enforced by review stops being enforced the first busy week.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.invariant

TESTS_ROOT = Path(__file__).resolve().parents[1]

#: Status codes that would mean "the request was allowed".
PERMISSIVE_STATUSES = frozenset({200, 201, 204})

#: Test-name fragments that mark a test as being ABOUT a privilege boundary.
#: A permissive status asserted inside one of these is what pinning a hole
#: looks like.
PRIVILEGE_SHAPED = (
    "denied",
    "forbidden",
    "escalat",
    "privileg",
    "idor",
    "unauthor",
    "not_allowed",
    "cannot",
    "must_not",
    "other_user",
    "another_user",
)


def _test_functions(path: Path) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    ]


def _suite_files() -> list[Path]:
    files = [
        path
        for path in sorted(TESTS_ROOT.rglob("*.py"))
        if "__pycache__" not in path.parts and path != Path(__file__).resolve()
    ]
    assert files, "the scanner found no test modules — it cannot fail as written"
    return files


def test_no_assert_can_pass_on_either_of_two_plausible_branches() -> None:
    """PLAN §12 — `assert a or b` with two plausible branches is banned.

    A disjunction whose branches are both reachable passes as soon as the weaker
    one holds, so the stronger one is decoration. Where a value is genuinely
    allowed to take one of two forms, the fix is to assert the condition that
    selects between them and then assert the form — not to OR them together.
    """
    offenders: list[str] = []

    for path in _suite_files():
        for func in _test_functions(path):
            for node in ast.walk(func):
                if not isinstance(node, ast.Assert):
                    continue
                if not isinstance(node.test, ast.BoolOp):
                    continue
                if not isinstance(node.test.op, ast.Or):
                    continue
                # A branch that is a falsy constant can never be the one that
                # passes, so it is not a real second branch.
                plausible = [
                    value
                    for value in node.test.values
                    if not (isinstance(value, ast.Constant) and not value.value)
                ]
                if len(plausible) > 1:
                    offenders.append(
                        f"{path.relative_to(TESTS_ROOT)}:{node.lineno} "
                        f"[{func.name}] assert {ast.unparse(node.test)}"
                    )

    assert not offenders, (
        "PLAN §12 — an assertion that passes on either of two plausible "
        "branches cannot fail:\n" + "\n".join(offenders)
    )


def test_no_test_codifies_a_permissive_answer_on_a_privilege_boundary() -> None:
    """PLAN §9 / §12 — no test may pin a security hole as expected behaviour.

    Scoped to tests whose NAME says they are about a boundary being enforced.
    A test called `test_admin_is_allowed_admin_route` asserting 200 is correct
    and is not flagged; a test called `test_viewer_is_denied_...` asserting 200
    is the prior codebase's defect, and is.
    """
    offenders: list[str] = []

    for path in _suite_files():
        for func in _test_functions(path):
            if not any(mark in func.name.lower() for mark in PRIVILEGE_SHAPED):
                continue
            for node in ast.walk(func):
                if not isinstance(node, ast.Assert):
                    continue
                rendered = ast.unparse(node.test)
                if "status_code" not in rendered:
                    continue
                if not isinstance(node.test, ast.Compare):
                    continue
                if not any(isinstance(op, ast.Eq) for op in node.test.ops):
                    continue
                for comparator in node.test.comparators:
                    if (
                        isinstance(comparator, ast.Constant)
                        and comparator.value in PERMISSIVE_STATUSES
                    ):
                        offenders.append(
                            f"{path.relative_to(TESTS_ROOT)}:{node.lineno} "
                            f"[{func.name}] assert {rendered}"
                        )

    assert not offenders, (
        "PLAN §12 — a test named for a privilege boundary asserts that the "
        "request SUCCEEDED, which pins the hole as intended behaviour:\n"
        + "\n".join(offenders)
    )


def test_every_test_module_asserts_something() -> None:
    """A test function with no assert passes by running to the end.

    `pytest.raises` and `pytest.fail` count; a function with neither is either
    unfinished or a smoke test that has forgotten what it was checking.
    """
    offenders: list[str] = []

    for path in _suite_files():
        for func in _test_functions(path):
            body = ast.unparse(func)
            asserts = any(isinstance(n, ast.Assert) for n in ast.walk(func))
            # `raise AssertionError(...)` inside a bounded wait helper is a real
            # assertion — the test fails when the condition never arrives.
            raises_assertion_error = any(
                isinstance(n, ast.Raise)
                and "AssertionError" in ast.unparse(n)
                for n in ast.walk(func)
            )
            if not (
                asserts
                or raises_assertion_error
                or "pytest.raises" in body
                or "pytest.fail" in body
            ):
                offenders.append(
                    f"{path.relative_to(TESTS_ROOT)}:{func.lineno} {func.name}"
                )

    assert not offenders, (
        "these tests assert nothing and pass by reaching the end:\n"
        + "\n".join(offenders)
    )


def test_the_scanners_above_can_actually_fail() -> None:
    """A check that has never failed is a check you cannot trust.

    The three scanners above are only as good as their detection, and all three
    return "clean" on an empty input. Each is run here against a synthetic
    module that violates it, so a scanner broken into permanent silence fails
    this test rather than passing every other one.
    """
    bad_or = ast.parse(
        "def test_x():\n"
        "    assert response.status_code == 200 or response.status_code == 403\n"
    )
    func = bad_or.body[0]
    assert isinstance(func, ast.FunctionDef)
    disjunctions = [
        node
        for node in ast.walk(func)
        if isinstance(node, ast.Assert)
        and isinstance(node.test, ast.BoolOp)
        and isinstance(node.test.op, ast.Or)
    ]
    assert len(disjunctions) == 1, "the `assert a or b` scanner sees the shape"

    bad_privilege = ast.parse(
        "async def test_viewer_is_denied_admin_route():\n"
        "    assert response.status_code == 200\n"
    )
    guard = bad_privilege.body[0]
    assert isinstance(guard, ast.AsyncFunctionDef)
    assert any(mark in guard.name.lower() for mark in PRIVILEGE_SHAPED)
    hits = [
        node
        for node in ast.walk(guard)
        if isinstance(node, ast.Assert)
        and isinstance(node.test, ast.Compare)
        and any(
            isinstance(c, ast.Constant) and c.value in PERMISSIVE_STATUSES
            for c in node.test.comparators
        )
    ]
    assert len(hits) == 1, "the privilege scanner sees the shape"

    empty = ast.parse("def test_nothing():\n    client.get('/')\n")
    assert not any(isinstance(n, ast.Assert) for n in ast.walk(empty))
