"""The single replay loop and its subscriber fan-out.

PLAN §10 / T4: ONE stream loop per server, not one per connection. The prior
codebase ran an independent loop per WebSocket, so every open browser tab
multiplied real API spend and halved time-to-429.

PLAN §4.1: the event bus is bounded and drops per subscriber with a counter. A
slow or wedged client must never apply backpressure to the producer or grow
memory without limit.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from app.config import get_settings
from app.ingestion.normalize import NormalizedAlert
from app.ingestion.replay import ReplayEngine, load_replay_rows
from app.store.repositories import upsert_alert
from app.store.session import get_sessionmaker
from app.workers.queue import TRIAGE_QUEUE_SIZE, BoundedQueue, QueueFullError

logger = logging.getLogger("flare.feed")

SUBSCRIBER_BUFFER = 200


class Subscriber:
    """One connected client.

    Drop-OLDEST here, unlike the triage queue's drop-newest: a live feed wants
    the most recent alerts, and a client that fell behind is better served the
    newest ones than a stale backlog. Drops are counted and surfaced.
    """

    def __init__(self, maxsize: int = SUBSCRIBER_BUFFER) -> None:
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0
        self.paused = False
        # FE-2 presence. Recorded here in Phase 2; PLAN §8's dispatcher acts on
        # it in Phase 5.
        self.presence = "active"

    def offer(self, payload: dict[str, Any]) -> None:
        if self.paused:
            return
        try:
            self.queue.put_nowait(payload)
        except asyncio.QueueFull:
            with contextlib.suppress(asyncio.QueueEmpty):
                self.queue.get_nowait()
            self.dropped += 1
            with contextlib.suppress(asyncio.QueueFull):
                self.queue.put_nowait(payload)


class FeedService:
    def __init__(self) -> None:
        self._subscribers: set[Subscriber] = set()
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._engine: ReplayEngine | None = None
        self.triage_queue: BoundedQueue[NormalizedAlert] = BoundedQueue(
            "triage", TRIAGE_QUEUE_SIZE
        )
        self.emitted = 0
        self.persist_failures = 0
        self.triage_failures = 0
        self.playbooks_triggered = 0
        self.playbook_failures = 0

    # -- subscribers -------------------------------------------------------

    def subscribe(self) -> Subscriber:
        subscriber = Subscriber()
        self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: Subscriber) -> None:
        self._subscribers.discard(subscriber)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    # -- lifecycle ---------------------------------------------------------

    def _build_engine(self) -> ReplayEngine:
        settings = get_settings()
        rows = load_replay_rows()
        return ReplayEngine(
            rows,
            alerts_per_minute=settings.replay_alerts_per_minute,
            loop=True,
        )

    @property
    def engine(self) -> ReplayEngine:
        if self._engine is None:
            self._engine = self._build_engine()
        return self._engine

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="flare-replay")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            with contextlib.suppress(asyncio.CancelledError, TimeoutError):
                await asyncio.wait_for(self._task, timeout=5)
            self._task = None

    def set_rate(self, alerts_per_minute: float) -> None:
        self.engine.alerts_per_minute = alerts_per_minute

    # -- the loop ----------------------------------------------------------

    async def _run(self) -> None:
        try:
            await self.engine.run(self._emit, self._stop)
        except FileNotFoundError as exc:
            # No partitions on disk. Say so once and stop; the API stays up and
            # every other screen keeps working.
            logger.error("replay disabled: %s", exc, extra={"request_id": "-"})
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("replay loop failed", extra={"request_id": "-"})
            raise

    async def _emit(self, alert: NormalizedAlert) -> None:
        try:
            self.triage_queue.put_nowait(alert)
        except QueueFullError:
            # Counted inside the queue. The producer keeps going; the drop is
            # visible rather than silently absorbed.
            return

        try:
            # PLAN Phase 3 — the graph is what produces a verdict now. Before
            # this the parser stamped the dataset's severity on the alert;
            # nothing downstream may treat that as a prediction, so it is gone.
            await self._triage(alert)
        finally:
            # The slot is reserved by put_nowait above and returned HERE, so
            # `depth` means "in flight" rather than "ever accepted". Without the
            # release the queue only fills, reaches maxsize, and from then on
            # every alert is dropped — a feed that stops dead after exactly
            # TRIAGE_QUEUE_SIZE alerts.
            self.triage_queue.release()

        await self.persist_and_publish(alert)

    # -- the live lane's entry points (PLAN D23 / §4.4a) --------------------
    #
    # Live-demo alerts reach the SAME graph, the SAME persistence and the SAME
    # fan-out as replay — the pipeline is one pipeline, which is what §4.4a's
    # diagram asserts. What they do NOT share is the triage queue or the task:
    # `app/ingestion/live.py` owns both, so live pressure cannot consume replay
    # slots and a live failure cannot reach the replay task (I19).

    async def triage_live(self, alert: NormalizedAlert) -> None:
        """Run the graph on an injected alert. Same function as replay's."""
        await self._triage(alert)

    async def persist_and_publish(self, alert: NormalizedAlert) -> dict[str, Any] | None:
        """Store, notify and fan out. Shared by replay and the live lane."""
        payload = await self._persist(alert)
        if payload is None:
            return None

        self.emitted += 1

        # PLAN §8 — a bounded, non-blocking hand-off. Everything the dispatcher
        # does (the preference query, the presence check, the SMTP round trip
        # and its retries) happens on its own worker, so a black-holed mail
        # host cannot stall this loop.
        from app.notifications.dispatcher import get_dispatcher

        get_dispatcher().submit(payload)

        for subscriber in list(self._subscribers):
            subscriber.offer(payload)
        return payload

    async def _triage(self, alert: NormalizedAlert) -> None:
        """Run the graph. A graph failure must not take the feed down.

        `run_pipeline` already returns partial state on a wall-clock expiry and
        already traces a failed node, so reaching this except means something
        outside the graph broke — a model that did not load, for instance. The
        alert still emits, with the failure recorded on it, because a feed that
        stops on one bad alert is a worse failure than one bad alert.
        """
        from app.agent.apply import apply_to_alert
        from app.agent.graph import run_pipeline

        try:
            state = await run_pipeline(alert)
        except Exception as exc:
            self.triage_failures += 1
            logger.exception("triage failed", extra={"request_id": "-"})
            alert.severity = "unknown"
            alert.attack_type = "unknown"
            alert.degraded = True
            alert.trace = [
                {
                    "node": "classify",
                    "status": "failed",
                    "provider": None,
                    "model": None,
                    "model_version": None,
                    "duration_ms": 0.0,
                    "tokens": None,
                    "note": f"the pipeline did not start: {type(exc).__name__}: {exc}",
                    "key_id": None,
                }
            ]
            return
        apply_to_alert(alert, state)

    async def _persist(self, alert: NormalizedAlert) -> dict[str, Any] | None:
        """Store the alert and everything the triage produced ALONGSIDE it.

        Three writes in ONE transaction, deliberately:

          * the alert itself;
          * `match_count` for every rule that fired on it (PLAN I2 — the
            counter and the alerts that produced it cannot disagree if they
            commit together);
          * a playbook execution for every enabled playbook whose scope this
            alert satisfies (PLAN §4.1 — what makes `alert_type` and
            `severity_threshold` load-bearing instead of decorative).

        A failure in the playbook half must not lose the alert, so it is caught
        separately and counted: an alert that reaches the screen without its
        automation is a smaller failure than a feed that stops.
        """
        from app.playbooks.engine import autotrigger
        from app.rules.store import bump_match_counts
        from app.store.repositories import alert_to_dict

        try:
            async with get_sessionmaker()() as session:
                stored = await upsert_alert(session, alert)

                fired = [
                    str(entry.get("rule_id"))
                    for entry in (alert.rule_trace or [])
                    if entry.get("fired")
                ]
                await bump_match_counts(session, fired)

                if get_settings().playbook_autotrigger_enabled:
                    try:
                        started = await autotrigger(
                            session,
                            alert_id=stored.id,
                            attack_type=stored.attack_type,
                            severity=stored.severity,
                        )
                        self.playbooks_triggered += len(started)
                    except Exception:
                        await session.rollback()
                        self.playbook_failures += 1
                        logger.exception(
                            "playbook autotrigger failed",
                            extra={"request_id": "-"},
                        )
                        # The alert is worth more than the automation. The
                        # rollback discarded the alert AND the rule counters
                        # along with the failed executions, so both are re-done
                        # on the clean session — dropping the counters here
                        # would leave `match_count` quietly under-reporting the
                        # alerts a rule actually fired on, which is the kind of
                        # drift PLAN I2 exists to prevent.
                        stored = await upsert_alert(session, alert)
                        await bump_match_counts(session, fired)

                await session.commit()
                return alert_to_dict(stored)
        except Exception:
            self.persist_failures += 1
            logger.exception("alert persist failed", extra={"request_id": "-"})
            return None

    def stats(self) -> dict[str, Any]:
        queue = self.triage_queue.stats()
        return {
            "running": self._task is not None and not self._task.done(),
            "emitted": self.emitted,
            "persist_failures": self.persist_failures,
            "triage_failures": self.triage_failures,
            "playbooks_triggered": self.playbooks_triggered,
            "playbook_failures": self.playbook_failures,
            "subscribers": len(self._subscribers),
            "subscriber_dropped": sum(s.dropped for s in self._subscribers),
            "queue": {
                "name": queue.name,
                "maxsize": queue.maxsize,
                "depth": queue.depth,
                "accepted": queue.accepted,
                "dropped": queue.dropped,
            },
        }


_feed: FeedService | None = None


def get_feed() -> FeedService:
    global _feed
    if _feed is None:
        _feed = FeedService()
    return _feed


def reset_feed() -> None:
    global _feed
    _feed = None
