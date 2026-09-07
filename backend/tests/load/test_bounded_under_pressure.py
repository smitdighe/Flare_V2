"""Load. PLAN §12 — behind the `load` marker, run explicitly.

Three properties, and each of them is a claim the README makes about scaling:

  1. **Bounded queues drop and COUNT rather than growing.** The failure this
     prevents is not a crash — it is a process whose memory climbs for forty
     minutes and then dies in front of an audience, having reported nothing.
  2. **A 503 is returned rather than a hang.** Backpressure is only honest if
     the caller is told. A request that blocks until a slot frees is a request
     that looks like a slow network to the client and like a leak to us.
  3. **The single stream loop holds under multiple connected clients** (T4).
     One producer, N subscribers, per-subscriber buffers — a slow client drops
     its own frames and never slows the loop or any other client.

These run at real depth rather than at three items, because the bug class they
exist to catch only appears PAST the bound. A test that stops at ten items
passes against a queue that never returns a slot.
"""

from __future__ import annotations

import asyncio

import pytest

from app.ingestion.feed import SUBSCRIBER_BUFFER, Subscriber
from app.workers.queue import TRIAGE_QUEUE_SIZE, BoundedQueue, QueueFullError

pytestmark = pytest.mark.load


# ---------------------------------------------------------------------------
# 1. bounded — drops and counts, never grows
# ---------------------------------------------------------------------------


def test_the_triage_queue_never_exceeds_its_bound_under_sustained_overload() -> None:
    """10x the depth, offered with nothing consuming. Memory must not follow."""
    queue: BoundedQueue[int] = BoundedQueue("triage", TRIAGE_QUEUE_SIZE)

    offered = TRIAGE_QUEUE_SIZE * 10
    rejected = 0
    for item in range(offered):
        try:
            queue.put_nowait(item)
        except QueueFullError:
            rejected += 1

    stats = queue.stats()
    assert stats.depth == TRIAGE_QUEUE_SIZE, "the bound held at exactly maxsize"
    assert stats.accepted == TRIAGE_QUEUE_SIZE
    assert stats.dropped == rejected == offered - TRIAGE_QUEUE_SIZE
    assert stats.accepted + stats.dropped == offered, (
        "every offer is accounted for — nothing vanished between the two counters"
    )


def test_a_draining_consumer_keeps_the_queue_at_zero_depth_forever() -> None:
    """The shipped shape: put, process, release. Depth is IN FLIGHT."""
    queue: BoundedQueue[int] = BoundedQueue("triage", TRIAGE_QUEUE_SIZE)

    for item in range(TRIAGE_QUEUE_SIZE * 5):
        queue.put_nowait(item)
        queue.release()

    stats = queue.stats()
    assert stats.dropped == 0, "five times the depth, and not one drop"
    assert stats.depth == 0


def test_a_subscriber_buffer_drops_the_OLDEST_and_counts_it() -> None:
    """A live feed wants the newest frames; a lagging client gets the newest.

    Drop-oldest here is deliberately the opposite of the triage queue's
    drop-newest, and the difference is the point: a backlog served to a client
    that fell behind is stale by the time it arrives.
    """
    subscriber = Subscriber(maxsize=8)

    for index in range(100):
        subscriber.offer({"id": f"ALT-{index:06d}"})

    assert subscriber.queue.qsize() == 8, "bounded"
    assert subscriber.dropped == 92, "and every dropped frame is counted"

    drained = [subscriber.queue.get_nowait() for _ in range(8)]
    assert drained[-1]["id"] == "ALT-000099", "the NEWEST frame survived"
    assert drained[0]["id"] == "ALT-000092", "the oldest were the ones dropped"


def test_a_paused_subscriber_costs_nothing_and_drops_nothing() -> None:
    """`pause` is a control frame, not a slow consumer. It must not count drops."""
    subscriber = Subscriber(maxsize=4)
    subscriber.paused = True

    for index in range(500):
        subscriber.offer({"id": f"ALT-{index:06d}"})

    assert subscriber.queue.qsize() == 0
    assert subscriber.dropped == 0, (
        "a paused client asked not to receive; that is not a dropped frame and "
        "counting it would make the health screen report a problem that is a "
        "user preference"
    )


# ---------------------------------------------------------------------------
# 2. a 503, not a hang
# ---------------------------------------------------------------------------


async def test_offering_to_a_full_queue_returns_immediately_rather_than_blocking() -> (
    None
):
    """`put_nowait` must never await. A blocking put on the replay loop stalls
    every subscriber behind whatever is slow."""
    queue: BoundedQueue[int] = BoundedQueue("triage", 2)
    queue.put_nowait(1)
    queue.put_nowait(2)

    async def offer_once() -> str:
        try:
            queue.put_nowait(3)
        except QueueFullError:
            return "rejected"
        return "accepted"

    # If `put_nowait` ever awaits a free slot, this wait_for times out and the
    # test fails with the exact symptom the property forbids.
    outcome = await asyncio.wait_for(offer_once(), timeout=1.0)
    assert outcome == "rejected"


async def test_an_unavailable_dependency_is_a_503_and_answers_immediately(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dependency that cannot serve answers 503 — it does not hold the request.

    `/eval` is used because it is the one route in this build that can genuinely
    be unable to serve (its ground-truth partition or its committed model
    metrics can be missing) and it is the route most likely to be hit while
    something else is loading. The two assertions are the whole property: the
    status says "temporarily unable" rather than "your request was wrong", and
    the answer arrives inside a bounded time rather than blocking on the
    unavailable thing.
    """
    import app.api.routes.eval as eval_mod
    from app.eval.harness import EvalDataError
    from tests.conftest import auth_header, login, make_user

    await make_user("load503@example.com", role="analyst")
    token = await login(client, "load503@example.com")

    class _Unavailable:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def run(self) -> dict[str, object]:
            raise EvalDataError("models/classifier/metrics.json missing")

    monkeypatch.setattr(eval_mod, "EvalHarness", _Unavailable)
    monkeypatch.setattr(eval_mod.cache, "read", lambda *a, **k: None)

    response = await asyncio.wait_for(
        client.get("/api/v1/eval?force=true", headers=auth_header(token)),
        timeout=10.0,
    )

    assert response.status_code == 503, response.text
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "eval_unavailable"


async def test_a_cooling_key_pool_raises_rather_than_blocking_the_caller() -> None:
    """PLAN §10.3 — all keys cooling is an honest error, immediately.

    The alternative implementations both fail: sleeping until the cooldown
    expires turns a rate limit into a hung request, and returning template text
    turns it into a fabricated answer.
    """
    from app.providers.keypool import AllKeysCoolingError, KeyPool

    key_pool = KeyPool("groq", {"dev": "k1"}, default_cooldown_seconds=3600.0)
    key_pool.mark_rate_limited("groq-dev", 3600.0)

    async def acquire() -> str:
        try:
            key_pool.acquire()
        except AllKeysCoolingError as exc:
            return f"raised:{exc.retry_after_seconds:.0f}"
        return "acquired"

    outcome = await asyncio.wait_for(acquire(), timeout=1.0)
    assert outcome.startswith("raised:"), "it raised rather than waiting out an hour"
    assert outcome != "raised:0", "and it reported how long the caller should wait"


# ---------------------------------------------------------------------------
# 3. one loop, many clients (T4)
# ---------------------------------------------------------------------------


def test_one_slow_client_does_not_slow_or_starve_the_others() -> None:
    """The property that makes ONE loop safe for N clients.

    Each subscriber owns its buffer, so a client that stopped reading fills and
    drops its own frames. If the fan-out were a single shared queue, or if
    `offer` awaited, the slow client would hold the producer and every other
    client would stall behind it.
    """
    fast_a = Subscriber(maxsize=SUBSCRIBER_BUFFER)
    fast_b = Subscriber(maxsize=SUBSCRIBER_BUFFER)
    slow = Subscriber(maxsize=4)
    subscribers = [fast_a, fast_b, slow]

    for index in range(SUBSCRIBER_BUFFER):
        payload = {"id": f"ALT-{index:06d}"}
        for subscriber in subscribers:
            subscriber.offer(payload)
        # The fast clients read as they go; the slow one never does.
        fast_a.queue.get_nowait()
        fast_b.queue.get_nowait()

    assert fast_a.dropped == 0, "a reading client loses nothing"
    assert fast_b.dropped == 0
    assert slow.queue.qsize() == 4, "the slow client is bounded at ITS size"
    assert slow.dropped == SUBSCRIBER_BUFFER - 4, "and only IT dropped"


async def test_the_fan_out_stays_bounded_with_many_connected_clients() -> None:
    """Fifty clients, none reading. Total memory is N x buffer, not N x offered."""
    from app.ingestion.feed import FeedService

    feed = FeedService()
    subscribers = [feed.subscribe() for _ in range(50)]
    try:
        assert feed.subscriber_count == 50

        offered = SUBSCRIBER_BUFFER * 3
        for index in range(offered):
            payload = {"id": f"ALT-{index:06d}"}
            for subscriber in subscribers:
                subscriber.offer(payload)

        for subscriber in subscribers:
            assert subscriber.queue.qsize() == SUBSCRIBER_BUFFER
            assert subscriber.dropped == offered - SUBSCRIBER_BUFFER

        total_dropped = sum(s.dropped for s in subscribers)
        assert total_dropped == 50 * (offered - SUBSCRIBER_BUFFER)
    finally:
        for subscriber in subscribers:
            feed.unsubscribe(subscriber)
    assert feed.subscriber_count == 0, "disconnects release their buffers"


async def test_a_disconnected_client_is_dropped_from_the_fan_out() -> None:
    """A leaked subscriber is an unbounded memory leak with a long fuse."""
    from app.ingestion.feed import FeedService

    feed = FeedService()
    for _ in range(200):
        subscriber = feed.subscribe()
        feed.unsubscribe(subscriber)

    assert feed.subscriber_count == 0
    assert feed.stats()["subscribers"] == 0


async def test_many_concurrent_stream_clients_share_one_loop(client) -> None:
    """T4 end to end: five authenticated WebSocket clients at once.

    The property is ONE producer for N consumers. Five connections must produce
    five subscribers on the SAME feed and exactly one replay task — not five
    loops racing each other to write the same alerts, which is what a
    connection-scoped loop would do.
    """
    import time

    from starlette.testclient import TestClient

    from app.ingestion.feed import get_feed
    from app.main import create_app
    from tests.conftest import login, make_user

    await make_user("load@example.com")
    token = await login(client, "load@example.com")

    feed = get_feed()
    app = create_app()
    opened: list[object] = []
    with TestClient(app) as http:
        try:
            loop_tasks: list[object] = []
            for index in range(5):
                socket = http.websocket_connect("/api/v1/ws/stream")
                socket.__enter__()
                socket.send_json({"type": "auth", "token": token})
                opened.append(socket)

                # There is no ack frame after auth (CONTRACT §3.1), so the only
                # honest synchronisation point is the registration itself.
                # Bounded, so a genuine failure to register fails the test
                # rather than hanging it.
                deadline = time.monotonic() + 5.0
                # ASYNC110 wants an asyncio.Event here, and there is none to
                # wait on: the condition lives in a singleton the SERVER
                # mutates from TestClient's own portal thread. Adding an
                # event to production code so a test could await it would
                # be the test dictating the design. Bounded, so a genuine
                # failure to register fails rather than hangs.
                while (  # noqa: ASYNC110
                    feed.subscriber_count < index + 1
                    and time.monotonic() < deadline
                ):
                    # `await`, not `time.sleep`: TestClient drives its sockets
                    # on its own portal thread, and blocking THIS loop is the
                    # I6 mistake the app is not allowed to make either.
                    await asyncio.sleep(0.02)
                loop_tasks.append(feed._task)

            assert feed.subscriber_count == 5, (
                "five clients, ONE feed — the fan-out is per-subscriber and the "
                "producer is shared, which is what makes T4 safe"
            )
            assert all(task is loop_tasks[0] for task in loop_tasks), (
                "T4 — the replay task is the SAME object across all five "
                "connections. A connection-scoped loop would give five tasks "
                "racing each other to write the same alerts"
            )
            assert loop_tasks[0] is not None, "and the one loop is actually running"
        finally:
            for socket in opened:
                socket.__exit__(None, None, None)  # type: ignore[attr-defined]

    deadline = time.monotonic() + 5.0
    while feed.subscriber_count and time.monotonic() < deadline:  # noqa: ASYNC110
        await asyncio.sleep(0.02)
    assert feed.subscriber_count == 0, "all five released on disconnect"
