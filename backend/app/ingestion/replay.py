"""Replay engine.

PLAN §6.4:
  * deterministic ordering — the same seed replays the same sequence
  * configurable rate
  * timestamps ordered, no backwards jitter that desyncs arrival order from
    timestamp order
  * NO severity upgrading to make the feed look busier
  * no random pairing of a label with an unrelated signature

Only `replay.csv` is ever read here. PLAN I15: train and eval rows must never
reach the demo feed, and loading a different partition is refused rather than
trusted to be correct at the call site.
"""

from __future__ import annotations

import asyncio
import csv
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.ingestion.normalize import NormalizedAlert, parse_cicids_row

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPLAY_CSV = REPO_ROOT / "data" / "splits" / "replay.csv"


class WrongPartitionError(ValueError):
    """A non-replay partition was handed to the replay engine (PLAN I15)."""


def load_replay_rows(path: Path = DEFAULT_REPLAY_CSV) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} missing. Run:\n"
            "  python -m scripts.fetch_dataset --glf-hf --attack-days-only\n"
            "  python -m scripts.build_partitions"
        )

    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    # PLAN I15 — every row id is partition-stamped, so a train or eval row
    # reaching the demo feed is caught here rather than discovered on screen.
    for row in rows:
        row_id = str(row.get("row_id", ""))
        if not row_id.startswith("replay-"):
            raise WrongPartitionError(
                f"{path.name} contains a non-replay row id: {row_id!r}. "
                "The demo feed must never play train or eval rows."
            )
    return rows


class ReplayEngine:
    """Deterministic replay of the held-out replay partition.

    Ordering is the file's own order — stable, reproducible, and requiring no
    seed because nothing is shuffled.

    `NormalizedAlert.timestamp` is the ARRIVAL time: the moment the alert
    entered the feed. GeneratedLabelledFlows does carry the real capture time
    and it is kept, on `captured_at` — but the frozen UI renders relative age
    and buckets event velocity off `timestamp`, and a July 2017 date there
    would show every alert as nine years old. Arrival time is what those
    widgets measure and "this alert arrived now" is simply true.
    """

    def __init__(
        self,
        rows: list[dict[str, Any]],
        *,
        alerts_per_minute: float = 30.0,
        loop: bool = True,
    ) -> None:
        if alerts_per_minute <= 0:
            raise ValueError("alerts_per_minute must be positive")
        self._rows = rows
        self._loop = loop
        self._cursor = 0
        self._last_timestamp: datetime | None = None
        self.alerts_per_minute = alerts_per_minute

    @property
    def interval_seconds(self) -> float:
        return 60.0 / self.alerts_per_minute

    @property
    def exhausted(self) -> bool:
        return not self._loop and self._cursor >= len(self._rows)

    def _next_timestamp(self) -> datetime:
        """Monotonic non-decreasing arrival time.

        Two alerts emitted inside the same clock tick would otherwise share a
        timestamp and could sort backwards against arrival order, which is
        exactly the desync PLAN §6.4 forbids.
        """
        now = datetime.now(UTC)
        if self._last_timestamp is not None and now <= self._last_timestamp:
            now = self._last_timestamp + timedelta(milliseconds=1)
        self._last_timestamp = now
        return now

    def next_alert(self) -> NormalizedAlert | None:
        if self._cursor >= len(self._rows):
            if not self._loop:
                return None
            self._cursor = 0

        row = self._rows[self._cursor]
        self._cursor += 1

        # The severity comes from the row's own class through the documented
        # class->severity map. It is never raised to make the feed look busier.
        return parse_cicids_row(
            row,
            timestamp=self._next_timestamp(),
            source="cicids_replay",
        )

    def iter_alerts(self, limit: int) -> Iterator[NormalizedAlert]:
        """Synchronous burst, used for hydration and tests. No sleeping."""
        for _ in range(limit):
            alert = self.next_alert()
            if alert is None:
                return
            yield alert

    async def run(self, emit: Any, stop: asyncio.Event) -> None:
        """Emit alerts at the configured rate until stopped.

        `asyncio.sleep`, never time.sleep — PLAN T5: a blocking sleep on the
        event loop freezes the entire server for the duration.
        """
        while not stop.is_set():
            alert = self.next_alert()
            if alert is None:
                return
            await emit(alert)
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.interval_seconds)
            except TimeoutError:
                continue
