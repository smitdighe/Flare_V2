"""Live staged-attack injection. PLAN D23 / §4.4a / Phase 4a.

**THIS IS ADDITIVE AND IT IS ISOLATED. I19 IS THE WHOLE DESIGN CONSTRAINT.**
Replay is the rehearsed, load-bearing path; this is a toggle on top of it. The
ingest endpoint, this service and the forwarder can all fail, hang or be
switched off with zero effect on replay, the eval, or any screen.

Isolation is STRUCTURAL, not a promise:

  * **Its own queue.** Live events do NOT go through `FeedService.triage_queue`.
    A burst of injected events cannot consume the replay loop's slots and make
    replay start dropping — which is exactly what sharing one bounded queue
    would produce, and it would look like the demo feed dying under load.
  * **Its own worker task.** One task, started with the toggle and stopped with
    it. An unhandled exception in it is caught, counted and logged; it does not
    propagate into the replay task because it is not in the replay task.
  * **Its own bounded capacity, dropping with a counter.** Same rule as
    everywhere else (PLAN §4.1, T13): a drop is counted and reported, never
    silent.
  * **Off by default.** `live_ingest_enabled` is False, and with it off the
    route is not mounted at all.

**D25 ROUTING — the demo dynamic, and the reason this phase exists.** Live
events are Suricata EVE records: a signature and a 5-tuple, and none of the 77
CICIDS flow features. `parse_eve_record` leaves `features` empty, which FORCES
the D25 path — the LightGBM tier emits a `skipped` trace entry naming the reason
and the alert routes straight to the LLM. Replay showcases the fast tier; live
injection showcases the LLM tier. Feeding the model a zero vector would be a
fabricated feature vector scored as a real prediction, which is I14's failure
mode wearing a different hat.

**NO GROUND TRUTH, EVER (I15 as extended by D24).** Every alert from here is
tagged `source="live_demo"` at the ingestion boundary and carries
`ground_truth_class=None`. It buys realism, not eval credibility.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from app.ingestion.normalize import NormalizedAlert
from app.workers.queue import BoundedQueue, QueueFullError

logger = logging.getLogger("flare.live")

#: Deliberately far smaller than TRIAGE_QUEUE_SIZE. The live path is a demo
#: beat of a few dozen alerts, not a firehose, and a small queue means an
#: over-eager forwarder is refused with a countable drop instead of building a
#: backlog the presenter watches drain for a minute.
LIVE_QUEUE_SIZE = 200


class LiveIngestService:
    """The live-demo lane. One queue, one worker, its own counters."""

    def __init__(self, *, maxsize: int = LIVE_QUEUE_SIZE) -> None:
        self.queue: BoundedQueue[NormalizedAlert] = BoundedQueue("live", maxsize)
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self.accepted = 0
        self.processed = 0
        self.failures = 0
        #: Non-alert EVE records (flow, dns, http, stats). COUNTED, not
        #: silently discarded — PLAN T13. The endpoint reports them as
        #: `dropped` so the forwarder's operator can see the ratio.
        self.non_alert_records = 0
        self.malformed_records = 0

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="flare-live-ingest")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, TimeoutError):
                await asyncio.wait_for(self._task, timeout=5)
            self._task = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    # -- submission --------------------------------------------------------

    def submit(self, alert: NormalizedAlert) -> bool:
        """Accept one alert onto the live lane, or refuse it countably.

        Returns True when queued. Returns False when the lane is full, which
        the endpoint reports as a dropped event rather than a 503 — a full live
        lane is not a service failure, it is the live lane doing its job while
        replay carries on untouched (I19).
        """
        try:
            self.queue.put_nowait(alert)
        except QueueFullError:
            return False
        self.accepted += 1
        return True

    # -- the worker --------------------------------------------------------

    async def _run(self) -> None:
        """Drain the live lane. NOTHING here may escape into another task.

        Every exception is caught, counted and logged. A live event that blows
        up in the graph costs one counter increment; it does not cancel this
        task, and this task is not the replay task in the first place.
        """
        while not self._stop.is_set():
            try:
                alert = await self.queue.get()
            except asyncio.CancelledError:
                raise
            try:
                await self._process(alert)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.failures += 1
                logger.exception(
                    "live-demo alert failed; replay is unaffected",
                    extra={"request_id": "-"},
                )
            finally:
                self.queue.task_done()

    async def _process(self, alert: NormalizedAlert) -> None:
        """The SAME normalizer output through the SAME graph as replay.

        Deliberately reuses `FeedService`'s triage, persistence and fan-out
        rather than re-implementing them: a live alert that took a different
        code path to the screen would be a second pipeline pretending to be the
        first, which is the thing PLAN §4.4a's diagram says it is not. What is
        NOT shared is the queue and the task — see the module docstring.
        """
        from app.ingestion.feed import get_feed

        feed = get_feed()
        await feed.triage_live(alert)
        payload = await feed.persist_and_publish(alert)
        if payload is not None:
            self.processed += 1

    # -- reporting ---------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        queue = self.queue.stats()
        return {
            "running": self.running,
            "accepted": self.accepted,
            "processed": self.processed,
            "failures": self.failures,
            "non_alert_records": self.non_alert_records,
            "malformed_records": self.malformed_records,
            "queue": {
                "name": queue.name,
                "maxsize": queue.maxsize,
                "depth": queue.depth,
                "accepted": queue.accepted,
                "dropped": queue.dropped,
            },
        }


_live: LiveIngestService | None = None


def get_live_ingest() -> LiveIngestService:
    global _live
    if _live is None:
        _live = LiveIngestService()
    return _live


def reset_live_ingest() -> None:
    """Test seam, matching `reset_feed`."""
    global _live
    _live = None
