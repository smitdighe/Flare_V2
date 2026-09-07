"""The standalone EVE forwarder. PLAN D23 / §4.4a.

`tools/eve_forwarder.py` runs on the target box and imports nothing from
`app/`, so it is loaded here by path rather than as a package module — which is
also the property being asserted by the first test.

Only the file-position machinery is covered, because that is where the failure
modes live: a tail on a rotating, truncating, partially-written file, and a
delivery that fails halfway through a pass.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

TOOLS = Path(__file__).resolve().parents[2] / "tools" / "eve_forwarder.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("eve_forwarder", TOOLS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fwd() -> ModuleType:
    return _load()


def test_the_forwarder_imports_nothing_from_the_application(fwd: ModuleType) -> None:
    """§4.4a — it runs on the target box, which has no copy of `app/`."""
    source = TOOLS.read_text(encoding="utf-8")
    assert "from app." not in source
    assert "import app" not in source


def test_it_reads_only_complete_lines_and_holds_the_partial_tail(
    fwd: ModuleType, tmp_path: Path
) -> None:
    """A tail on a live file routinely reads half a JSON object.

    The partial line must be buffered, NOT counted as malformed and NOT parsed.
    """
    eve = tmp_path / "eve.json"
    eve.write_text('{"a": 1}\n{"b": 2}\n{"c": 3', encoding="utf-8")
    position = fwd.Position(tmp_path / "pos")

    lines, carry = fwd._read_new_lines(eve, position, "")

    assert lines == ['{"a": 1}', '{"b": 2}']
    assert carry == '{"c": 3', "the half-written record is held, not dropped"

    # The rest of that record arrives on the next append.
    with eve.open("a", encoding="utf-8") as handle:
        handle.write('}\n')
    lines, carry = fwd._read_new_lines(eve, position, carry)
    assert lines == ['{"c": 3}']
    assert carry == ""
    assert json.loads(lines[0]) == {"c": 3}


def test_a_rotation_reopens_from_zero(fwd: ModuleType, tmp_path: Path) -> None:
    """A new inode is a new file. A naive tail goes silent for the whole demo."""
    eve = tmp_path / "eve.json"
    eve.write_text('{"a": 1}\n', encoding="utf-8")
    position = fwd.Position(tmp_path / "pos")
    fwd._read_new_lines(eve, position, "")
    assert position.offset > 0

    eve.unlink()
    eve.write_text('{"fresh": true}\n', encoding="utf-8")
    position.inode = position.inode + 1 if position.inode is not None else 1

    lines, _ = fwd._read_new_lines(eve, position, "")
    assert lines == ['{"fresh": true}'], "rotation must reread from the start"


def test_a_truncation_in_place_reopens_from_zero(
    fwd: ModuleType, tmp_path: Path
) -> None:
    """`> eve.json`, or a log manager that copies and truncates."""
    eve = tmp_path / "eve.json"
    eve.write_text('{"a": 1}\n{"b": 2}\n', encoding="utf-8")
    position = fwd.Position(tmp_path / "pos")
    fwd._read_new_lines(eve, position, "")

    eve.write_text('{"small": 1}\n', encoding="utf-8")
    lines, _ = fwd._read_new_lines(eve, position, "")
    assert lines == ['{"small": 1}']


def test_a_missing_file_during_rotation_is_not_an_error(
    fwd: ModuleType, tmp_path: Path
) -> None:
    position = fwd.Position(tmp_path / "pos")
    lines, carry = fwd._read_new_lines(tmp_path / "gone.json", position, "")
    assert lines == [] and carry == ""


def test_the_position_survives_a_restart(fwd: ModuleType, tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text('{"a": 1}\n', encoding="utf-8")
    state = tmp_path / "pos"

    first = fwd.Position(state)
    fwd._read_new_lines(eve, first, "")
    first.save()

    restarted = fwd.Position(state)
    assert restarted.offset == first.offset
    assert restarted.inode == first.inode
    assert fwd._read_new_lines(eve, restarted, "")[0] == [], (
        "a restart must not replay the file it already delivered"
    )


def test_a_failed_pass_rolls_the_position_BACK_so_nothing_is_stranded(
    fwd: ModuleType, tmp_path: Path
) -> None:
    """The defect the Phase 4a re-run found, asserted so it cannot return.

    `_read_new_lines` advances `position.offset` to EOF as a side effect of
    reading. Skipping `position.save()` on a failed delivery only leaves the
    ON-DISK offset behind — the in-memory one has already moved. The next poll
    then sees `st_size == offset`, returns nothing, and every event after the
    failing batch is stranded until the process restarts, with the forwarder
    sitting in its poll loop reporting nothing wrong.

    One 429 from the endpoint's own rate limiter stranded 27 of 107 alerts that
    way. Re-sending is safe: the endpoint is idempotent by alert id.
    """
    eve = tmp_path / "eve.json"
    eve.write_text('{"a": 1}\n{"b": 2}\n{"c": 3}\n', encoding="utf-8")
    position = fwd.Position(tmp_path / "pos")

    checkpoint = (position.inode, position.offset, "")
    lines, carry = fwd._read_new_lines(eve, position, "")
    assert len(lines) == 3
    assert position.offset > 0, "the read advanced the in-memory offset"

    # Delivery fails. This is the rollback the run loop performs.
    position.inode, position.offset, carry = checkpoint

    replayed, _ = fwd._read_new_lines(eve, position, carry)
    assert replayed == lines, (
        "after a failed pass the same window must be re-read, not skipped"
    )


def test_the_run_loop_actually_performs_that_rollback(fwd: ModuleType) -> None:
    """Asserted on the source, because the loop needs a live server to run.

    The test above proves the rollback WORKS; this proves it is WIRED. Without
    both, the mechanism could be correct and never invoked.
    """
    source = TOOLS.read_text(encoding="utf-8")
    assert "checkpoint = (position.inode, position.offset, carry)" in source
    assert "position.inode, position.offset, carry = checkpoint" in source
    # And that it is the failure branch doing it, not the success branch.
    failure_branch = source.split("if ok:")[1]
    assert "= checkpoint" in failure_branch


def test_the_token_is_never_taken_from_argv(fwd: ModuleType) -> None:
    """§9 — `ps` is readable by every user on the box we are attacking."""
    source = TOOLS.read_text(encoding="utf-8")
    assert '"--token"' not in source
    assert "--token-env" in source
    assert 'os.environ.get(args.token_env' in source
