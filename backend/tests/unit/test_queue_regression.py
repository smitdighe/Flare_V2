"""The triage queue returns its slots. PLAN Phase 3 regression / Phase 4 item 0.4.

**THE BUG THIS EXISTS TO CATCH.** `put_nowait` reserves a slot and nothing
consumed it, so `qsize()` climbed monotonically to `maxsize` and from that point
every further alert was dropped. The feed stopped dead after exactly
TRIAGE_QUEUE_SIZE alerts.

**WHY THE TIMING MATTERS MORE THAN THE COUNT.** At the configured 30 alerts a
minute, 1000 alerts is about 33 minutes. That is *after* most rehearsals end and
*before* a long judging session does — the worst possible place for a failure to
hide. A test that stops at ten alerts would pass against the broken code, so
both tests here deliberately run PAST the queue depth.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.workers.queue import TRIAGE_QUEUE_SIZE, BoundedQueue, QueueFullError


def test_the_queue_keeps_accepting_past_its_own_depth() -> None:
    """Depth means IN FLIGHT, not EVER ACCEPTED."""
    queue: BoundedQueue[int] = BoundedQueue("triage", 4)

    for item in range(40):
        queue.put_nowait(item)
        queue.release()

    stats = queue.stats()
    assert stats.accepted == 40
    assert stats.dropped == 0
    assert stats.depth == 0, "every slot was returned"


def test_the_real_queue_depth_is_survivable() -> None:
    """The same property at the shipped size, so the constant is covered too."""
    queue: BoundedQueue[int] = BoundedQueue("triage", TRIAGE_QUEUE_SIZE)

    for item in range(TRIAGE_QUEUE_SIZE + 500):
        queue.put_nowait(item)
        queue.release()

    assert queue.stats().dropped == 0
    assert queue.stats().depth == 0


def test_without_release_the_queue_fills_and_then_drops() -> None:
    """The broken behaviour, pinned.

    If someone removes the `release()` call in `FeedService._emit` this is what
    the queue does, and this test says so explicitly so the next reader knows
    the drop is a symptom rather than the design.
    """
    queue: BoundedQueue[int] = BoundedQueue("triage", 3)
    for item in range(3):
        queue.put_nowait(item)
    with pytest.raises(QueueFullError):
        queue.put_nowait(99)
    assert queue.stats().dropped == 1


async def test_the_feed_keeps_emitting_past_the_queue_depth() -> None:
    """The regression, through `FeedService._emit` itself.

    Triage and persistence are stubbed — this is about the slot bookkeeping in
    the emit path, and running 60 real alerts through LangGraph would test the
    graph instead. The queue is shrunk so the test crosses the depth quickly;
    the shipped depth is covered by the test above.
    """
    from app.ingestion.feed import FeedService

    feed = FeedService()
    feed.triage_queue = BoundedQueue("triage", 5)

    delivered: list[str] = []

    async def _no_triage(alert: Any) -> None:
        return None

    async def _fake_persist(alert: Any) -> dict[str, Any]:
        return {"id": alert.id}

    feed._triage = _no_triage  # type: ignore[method-assign]
    feed._persist = _fake_persist  # type: ignore[method-assign]

    subscriber = feed.subscribe()

    class _Alert:
        def __init__(self, index: int) -> None:
            self.id = f"ALT-{index:06X}"

    for index in range(60):
        await feed._emit(_Alert(index))

    while not subscriber.queue.empty():
        delivered.append(subscriber.queue.get_nowait()["id"])

    assert feed.emitted == 60, "the feed kept flowing well past the queue depth"
    assert feed.triage_queue.stats().dropped == 0
    assert feed.triage_queue.stats().depth == 0
    # The subscriber buffer is 200, so all 60 survive; the last one is the last
    # one emitted, which is what a viewer would be looking at.
    assert delivered[-1] == "ALT-00003B"
