"""Signature synthesis, label-leak, replay ordering and bounded queues."""

from __future__ import annotations

import asyncio
import csv
import inspect
import ipaddress
import itertools
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ingestion.labels import CANONICAL_CLASSES, RAW_TO_CANONICAL
from app.ingestion.normalize import (
    NormalizedAlert,
    parse_cicids_row,
    synthesize_signature,
)
from app.ingestion.replay import ReplayEngine, WrongPartitionError, load_replay_rows
from app.workers.queue import BoundedQueue, QueueFullError

SPLITS = Path(__file__).resolve().parents[2] / "data" / "splits"
REPLAY_CSV = SPLITS / "replay.csv"

needs_data = pytest.mark.skipif(
    not REPLAY_CSV.exists(),
    reason="partitions not built — run scripts.fetch_dataset then scripts.build_partitions",
)


def _rows(limit: int = 200) -> list[dict[str, str]]:
    with REPLAY_CSV.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [row for _, row in zip(range(limit), reader, strict=False)]


# ---------------------------------------------------------------------------
# PLAN I4 — the label never reaches the signature
# ---------------------------------------------------------------------------


def test_synthesize_signature_cannot_receive_a_label() -> None:
    """Structural guard, not a behavioural one.

    The prior codebase built f"CICIDS {raw_label} flow ..." and then put the
    signature in the prompt, so 450/450 eval prompts carried the answer. Here
    the label is not a parameter, so leaking it would require changing this
    function's signature — which this test would fail on.
    """
    parameters = set(inspect.signature(synthesize_signature).parameters)
    forbidden = {"label", "raw_label", "canonical", "canonical_class", "attack_type"}
    assert not (parameters & forbidden), (
        f"synthesize_signature accepts label-bearing parameters: {parameters & forbidden}"
    )


@needs_data
def test_no_canonical_class_name_appears_in_any_signature() -> None:
    """PLAN I4 — the assertion that would have caught the prior 450/450 leak."""
    haystack_terms = {c.replace("_", " ") for c in CANONICAL_CLASSES} | set(
        CANONICAL_CLASSES
    )
    raw_terms = {s.lower() for s in RAW_TO_CANONICAL}

    for row in _rows():
        alert = parse_cicids_row(row, timestamp=datetime.now(UTC))
        lowered = alert.signature.lower()

        for term in haystack_terms:
            assert term not in lowered, (
                f"class name {term!r} leaked into signature: {alert.signature!r}"
            )
        for term in raw_terms:
            assert term not in lowered, (
                f"raw label {term!r} leaked into signature: {alert.signature!r}"
            )


@needs_data
def test_ground_truth_is_carried_separately_from_the_signature() -> None:
    row = _rows(1)[0]
    alert = parse_cicids_row(row, timestamp=datetime.now(UTC))
    assert alert.ground_truth_class == row["canonical_class"]
    assert alert.ground_truth_class not in alert.signature


@needs_data
def test_serialized_alert_never_carries_the_label() -> None:
    """PLAN I4 — the label must not travel with a rendered alert."""
    from app.store.models import Alert
    from app.store.repositories import alert_to_dict

    row = _rows(1)[0]
    normalized = parse_cicids_row(row, timestamp=datetime.now(UTC))
    stored = Alert(
        id=normalized.id,
        timestamp=normalized.timestamp,
        source=normalized.source,
        severity=normalized.severity,
        attack_type=normalized.attack_type,
        src_ip=normalized.src_ip,
        dest_ip=normalized.dest_ip,
        dest_port=normalized.dest_port,
        protocol=normalized.protocol,
        signature=normalized.signature,
        trace=[],
    )
    payload = alert_to_dict(stored)
    assert "ground_truth_class" not in payload
    assert "row_id" not in payload
    assert "features" not in payload


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


@needs_data
def test_parsed_alert_uses_contract_field_names() -> None:
    row = _rows(1)[0]
    alert = parse_cicids_row(row, timestamp=datetime.now(UTC))
    assert alert.source == "cicids_replay"
    assert alert.id.startswith("ALT-") and len(alert.id) == 10
    assert hasattr(alert, "dest_ip") and hasattr(alert, "dest_port")
    assert not hasattr(alert, "dst_ip"), "PLAN D16 — dest_*, never dst_*"
    assert len(alert.features) == 77


@needs_data
def test_parsing_is_deterministic() -> None:
    row = _rows(1)[0]
    when = datetime.now(UTC)
    first = parse_cicids_row(row, timestamp=when)
    second = parse_cicids_row(row, timestamp=when)
    assert first.id == second.id
    assert first.signature == second.signature
    assert (first.src_ip, first.dest_ip) == (second.src_ip, second.dest_ip)


@needs_data
def test_endpoints_come_from_the_row_not_from_code() -> None:
    """The migration's whole point: addresses are read, never derived.

    Verified by identity rather than by shape — an address that matches the
    row's own column cannot have been generated, whereas a plausible-looking
    192.168.10.x could have been.
    """
    for row in _rows(300):
        alert = parse_cicids_row(row, timestamp=datetime.now(UTC))
        assert alert.src_ip == row["Source IP"]
        assert alert.dest_ip == row["Destination IP"]
        ipaddress.ip_address(alert.src_ip)
        ipaddress.ip_address(alert.dest_ip)


@needs_data
def test_replayed_endpoints_match_the_published_topology() -> None:
    """Provenance check on the data itself, not on the parser.

    CICIDS2017 ran its attacks from 172.16.0.1 and 205.174.165.x against the
    192.168.10.0/24 victim network. If a mirror had been quietly swapped for
    one with mangled addresses — the defect that disqualified bvk/CICIDS-2017 —
    the attack rows would stop matching.
    """
    attackers = {"172.16.0.1", "205.174.165.73", "205.174.165.70"}
    seen: set[str] = set()
    for row in _rows(1800):
        if row["canonical_class"] == "benign":
            continue
        alert = parse_cicids_row(row, timestamp=datetime.now(UTC))
        seen.add(alert.src_ip)

    assert seen & attackers, f"no published attacker address in the replay set: {seen}"


@needs_data
def test_capture_time_is_kept_separately_from_arrival_time() -> None:
    """Both are true statements about different things — neither is invented."""
    row = _rows(1)[0]
    arrived = datetime.now(UTC)
    alert = parse_cicids_row(row, timestamp=arrived)

    assert alert.timestamp == arrived
    assert alert.captured_at is not None
    assert alert.captured_at.year == 2017, "the source capture ran in July 2017"
    assert alert.captured_at.isoformat() == row["captured_at"]


def test_no_endpoint_synthesis_path_remains() -> None:
    """PLAN §14 — a removed capability leaves no dead flag behind.

    Checked three ways because each catches a different resurrection: the
    record can no longer carry the provenance stamp, the settings object can no
    longer carry the toggle, and no module under app/ mentions either.
    """
    from app.config import Settings

    assert not hasattr(NormalizedAlert("", datetime.now(UTC), "cicids_replay", "", "",
                                       "", "", 0, "", ""), "endpoints_synthetic")
    assert "replay_synthesize_endpoints" not in Settings.model_fields

    app_dir = Path(__file__).resolve().parents[2] / "app"
    banned = ("EndpointPolicy", "endpoints_synthetic", "replay_synthesize_endpoints")
    offenders = [
        f"{path.name}:{term}"
        for path in app_dir.rglob("*.py")
        for term in banned
        if term in path.read_text(encoding="utf-8")
    ]
    assert not offenders, f"synthesis machinery still referenced: {offenders}"


# ---------------------------------------------------------------------------
# replay engine
# ---------------------------------------------------------------------------


@needs_data
def test_replay_refuses_a_non_replay_partition() -> None:
    """PLAN I15 — train and eval rows must never reach the demo feed."""
    with pytest.raises(WrongPartitionError, match="non-replay row id"):
        load_replay_rows(SPLITS / "train.csv")


@needs_data
def test_replay_ordering_is_deterministic() -> None:
    rows = load_replay_rows(REPLAY_CSV)
    first = [a.id for a in ReplayEngine(rows).iter_alerts(40)]
    second = [a.id for a in ReplayEngine(rows).iter_alerts(40)]
    assert first == second
    assert len(first) == 40


@needs_data
def test_replay_timestamps_are_monotonic() -> None:
    """PLAN §6.4 — no backwards jitter desyncing arrival from timestamp order."""
    rows = load_replay_rows(REPLAY_CSV)
    engine = ReplayEngine(rows)
    stamps = [a.timestamp for a in engine.iter_alerts(200)]

    assert len(stamps) == 200
    for earlier, later in itertools.pairwise(stamps):
        assert later > earlier, "timestamps must strictly increase"


def test_the_triage_queue_returns_slots_and_does_not_fill_forever() -> None:
    """REGRESSION — a feed that stops dead after exactly `maxsize` alerts.

    The queue reserves a slot per alert and NOTHING consumed it, so `qsize()`
    only ever climbed. At `TRIAGE_QUEUE_SIZE` (1000) every further alert was
    dropped: at 30 alerts/min the stream would die silently ~33 minutes into a
    rehearsal, which reads as the feed having broken rather than as a limit.
    A live run showed depth at 94 and climbing.
    """
    from app.workers.queue import BoundedQueue, QueueFullError

    queue: BoundedQueue[int] = BoundedQueue("triage", 2)
    for value in range(50):
        queue.put_nowait(value)
        queue.release()

    assert queue.stats().depth == 0
    assert queue.accepted == 50
    assert queue.dropped == 0

    # The bound is still a real bound for genuinely concurrent items.
    queue.put_nowait(1)
    queue.put_nowait(2)
    with pytest.raises(QueueFullError):
        queue.put_nowait(3)


def test_releasing_an_empty_queue_is_a_no_op() -> None:
    """A failure path may release twice; that must not raise inside a `finally`."""
    from app.workers.queue import BoundedQueue

    queue: BoundedQueue[int] = BoundedQueue("triage", 2)
    queue.release()
    queue.put_nowait(1)
    queue.release()
    queue.release()
    assert queue.stats().depth == 0


@needs_data
def test_replay_parser_emits_no_verdict_of_its_own() -> None:
    """PLAN I4/I5 — the parser does not predict, and does not copy the label.

    Phase 2 stamped the dataset's severity for the true class onto the alert as
    a placeholder. Phase 3 removed it: a parser that copies the ground-truth
    class onto the rendered alert is a label leak with a plausible name on it,
    and it leaves the classifier nothing to disagree with. Both fields stay
    `unknown` until the classify node writes a real verdict.
    """
    rows = load_replay_rows(REPLAY_CSV)
    alerts = list(ReplayEngine(rows).iter_alerts(300))
    assert alerts

    for alert in alerts:
        assert alert.severity == "unknown"
        assert alert.attack_type == "unknown"
        # The label still travels for the eval harness — it just never reaches
        # a rendered field.
        assert alert.ground_truth_class


@needs_data
def test_replay_loops_without_running_dry() -> None:
    rows = load_replay_rows(REPLAY_CSV)[:5]
    engine = ReplayEngine(rows, loop=True)
    assert len(list(engine.iter_alerts(12))) == 12


@needs_data
def test_replay_stops_when_not_looping() -> None:
    rows = load_replay_rows(REPLAY_CSV)[:5]
    engine = ReplayEngine(rows, loop=False)
    assert len(list(engine.iter_alerts(12))) == 5
    assert engine.exhausted is True


# ---------------------------------------------------------------------------
# bounded queues
# ---------------------------------------------------------------------------


async def test_queue_drops_and_counts_rather_than_growing() -> None:
    """PLAN §4.1 — bounded, drop-newest, counted. Never unbounded growth."""
    queue: BoundedQueue[int] = BoundedQueue("triage", maxsize=3)

    for value in range(3):
        queue.put_nowait(value)

    assert queue.qsize() == 3
    assert queue.accepted == 3
    assert queue.dropped == 0

    for _ in range(5):
        with pytest.raises(QueueFullError):
            queue.put_nowait(99)

    assert queue.qsize() == 3, "the queue never grows past maxsize"
    assert queue.dropped == 5, "every drop is counted"
    assert queue.accepted == 3, "a dropped item is not counted as accepted"


async def test_queue_full_raises_rather_than_hanging() -> None:
    """A full queue must raise immediately, not block the producer."""
    queue: BoundedQueue[int] = BoundedQueue("enrich", maxsize=1)
    queue.put_nowait(1)

    async def attempt() -> None:
        with pytest.raises(QueueFullError):
            queue.put_nowait(2)

    # 0.5s is generous for a call that must not block at all.
    await asyncio.wait_for(attempt(), timeout=0.5)


async def test_queue_error_names_the_queue_for_the_503() -> None:
    queue: BoundedQueue[int] = BoundedQueue("triage", maxsize=1)
    queue.put_nowait(1)
    with pytest.raises(QueueFullError) as excinfo:
        queue.put_nowait(2)
    assert excinfo.value.name == "triage"
    assert excinfo.value.maxsize == 1


async def test_queue_drains_after_get() -> None:
    queue: BoundedQueue[int] = BoundedQueue("triage", maxsize=2)
    queue.put_nowait(1)
    queue.put_nowait(2)
    with pytest.raises(QueueFullError):
        queue.put_nowait(3)

    assert await queue.get() == 1
    queue.task_done()
    queue.put_nowait(3)  # room again
    assert queue.qsize() == 2
