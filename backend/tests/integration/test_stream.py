"""WebSocket first-message auth handshake and the single replay loop.

CONTRACT §3.0 (FE-2): the token travels in the first frame, never a query
string. PLAN §10 / T4: one replay loop per server, not one per connection.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.ingestion.feed import reset_feed
from tests.conftest import make_user

SPLITS = Path(__file__).resolve().parents[2] / "data" / "splits"

needs_data = pytest.mark.skipif(
    not (SPLITS / "replay.csv").exists(),
    reason="partitions not built — run scripts.fetch_dataset then scripts.build_partitions",
)

WS_URL = "/api/v1/ws/stream"
CLOSE_INVALID_TOKEN = 4001
CLOSE_FORBIDDEN = 4003


def _make_user_and_token(email: str, role: str = "viewer") -> str:
    """Create a user and mint an access token, then release the engine.

    TestClient drives the app on its OWN event loop. An async engine created on
    the pytest loop cannot be used from that one — the connection pool's
    futures belong to the wrong loop and every query hangs forever. So this
    helper runs its own loop and disposes the engine afterwards, leaving the
    TestClient's loop to build a fresh one.
    """
    import asyncio

    from sqlalchemy import select

    from app.security.tokens import create_token
    from app.store.models import User
    from app.store.session import dispose_engine, get_sessionmaker

    async def _run() -> str:
        await make_user(email, role=role)
        async with get_sessionmaker()() as session:
            user = (
                await session.execute(select(User).where(User.email == email))
            ).scalar_one()
            token = create_token(user.id, "access", user.role, user.token_version)
        await dispose_engine()
        return token

    return asyncio.run(_run())


@pytest.fixture
def sync_client() -> Iterator[TestClient]:
    """Starlette's TestClient — httpx's ASGI transport has no WebSocket support."""
    import asyncio

    from app.main import create_app
    from app.store.session import dispose_engine

    reset_feed()
    with TestClient(create_app()) as client:
        yield client
    reset_feed()
    asyncio.run(dispose_engine())


def test_first_frame_is_not_an_auth_frame_closes_4001(
    sync_client: TestClient,
) -> None:
    """An unauthenticated socket is never held open."""
    with (
        sync_client.websocket_connect(WS_URL) as socket,
        pytest.raises(WebSocketDisconnect) as excinfo,
    ):
        socket.send_text(json.dumps({"type": "pause"}))  # not an auth frame
        socket.receive_text()

    assert excinfo.value.code == CLOSE_INVALID_TOKEN


def test_invalid_token_closes_4001(sync_client: TestClient) -> None:
    with (
        sync_client.websocket_connect(WS_URL) as socket,
        pytest.raises(WebSocketDisconnect) as excinfo,
    ):
        socket.send_text(json.dumps({"type": "auth", "token": "not-a-jwt"}))
        socket.receive_text()

    assert excinfo.value.code == CLOSE_INVALID_TOKEN


def test_every_real_role_is_admitted_to_the_feed() -> None:
    """The alert stream IS the product view; `/alerts` has no role guard either.

    Asserted rather than assumed, because the 4003 branch below is one edit away
    from locking out an ordinary analyst mid-demo. This is a statement about the
    admitted SET, checked directly: the live handshake for an admitted role is
    already covered by `test_valid_handshake_streams_bare_alerts`, and opening a
    socket per role here only re-exercises that path while churning the
    TestClient's connection pool.
    """
    from app.api.deps import ROLES
    from app.api.routes.stream import STREAM_ROLES

    assert STREAM_ROLES == frozenset(ROLES), (
        "every role the app defines watches the feed; a role missing here is "
        "an analyst locked out of the main screen"
    )
    assert "decommissioned" not in STREAM_ROLES, "the 4003 branch stays reachable"


def test_a_role_that_is_not_a_role_closes_4003_not_4001(
    sync_client: TestClient,
) -> None:
    """CONTRACT §3.0 step 5 — the second close code, and it has to be reachable.

    `User.role` is a plain String(20) with no database-level constraint, so a
    hand-edited row, a bad seed or a future migration can put a value there that
    no `require_role` list contains. PLAN §9 says that fails CLOSED: an
    unrecognised role gets nothing, rather than getting everything because no
    branch matched it.

    4003 and not 4001: the token is perfectly valid and re-authenticating cannot
    help, and the frozen client renders the two differently
    (useAlertStream.js:37).
    """
    token = _make_user_and_token("ghost-role@flare.dev", role="decommissioned")

    with (
        sync_client.websocket_connect(WS_URL) as socket,
        pytest.raises(WebSocketDisconnect) as excinfo,
    ):
        socket.send_text(json.dumps({"type": "auth", "token": token}))
        socket.receive_text()

    assert excinfo.value.code == CLOSE_FORBIDDEN
    assert excinfo.value.code != CLOSE_INVALID_TOKEN


def test_query_string_token_does_not_authenticate(
    sync_client: TestClient,
) -> None:
    """PLAN §9 — a token in a query string must not work.

    It lands in access logs, browser history and proxy logs, which is why FE-2
    moved it into the first frame.
    """
    token = _make_user_and_token("qs@example.com")

    with (
        sync_client.websocket_connect(f"{WS_URL}?token={token}") as socket,
        pytest.raises(WebSocketDisconnect) as excinfo,
    ):
        # No auth frame sent: the query parameter must be ignored entirely.
        socket.receive_text()

    assert excinfo.value.code == CLOSE_INVALID_TOKEN


@needs_data
def test_valid_handshake_streams_bare_alerts(sync_client: TestClient) -> None:
    """CONTRACT §3.1 — one bare Alert object per message, not enveloped."""
    token = _make_user_and_token("ws@example.com")

    with sync_client.websocket_connect(WS_URL) as socket:
        socket.send_text(json.dumps({"type": "auth", "token": token}))
        socket.send_text(json.dumps({"type": "presence", "state": "active"}))

        payload = json.loads(socket.receive_text())

    assert "ok" not in payload, "the WS message must NOT be enveloped"
    assert "data" not in payload
    assert payload["id"].startswith("ALT-"), (
        "a frame without a top-level id is silently dropped by the frozen client"
    )
    assert payload["source"] == "cicids_replay"
    assert payload["severity"] in {"critical", "high", "medium", "low", "unknown"}
    assert "ground_truth_class" not in payload  # PLAN I4


@needs_data
def test_one_replay_loop_serves_many_subscribers(
    sync_client: TestClient,
) -> None:
    """PLAN §10 / T4 — every extra tab must not spawn another loop."""
    from app.ingestion.feed import get_feed

    token = _make_user_and_token("multi@example.com")

    with sync_client.websocket_connect(WS_URL) as first:
        first.send_text(json.dumps({"type": "auth", "token": token}))
        first.receive_text()

        with sync_client.websocket_connect(WS_URL) as second:
            second.send_text(json.dumps({"type": "auth", "token": token}))
            second.receive_text()

            feed = get_feed()
            assert feed.subscriber_count == 2
            assert feed.stats()["running"] is True


# ---------------------------------------------------------------------------
# PART E — one loop per SERVER, and the inbound control frames
# ---------------------------------------------------------------------------


@needs_data
def test_two_clients_share_one_loop_and_do_not_start_a_second(
    sync_client: TestClient,
) -> None:
    """PLAN §10 / T4 — the identity of the task, not just the count.

    The prior codebase ran an independent replay loop per socket, so every open
    browser tab multiplied real API spend and halved time-to-429. With a 15 RPM
    Gemini tier that is the difference between working and 429ing on stage.

    Counting subscribers is not enough to prove it: two loops would also report
    two subscribers. What proves it is that the SAME task object is serving
    both connections, and that exactly one replay task exists in the loop.
    """
    import asyncio

    from app.ingestion.feed import get_feed

    token = _make_user_and_token("oneloop@example.com")
    feed = get_feed()

    with sync_client.websocket_connect(WS_URL) as first:
        first.send_text(json.dumps({"type": "auth", "token": token}))
        first.receive_text()
        task_after_first = feed._task

        with sync_client.websocket_connect(WS_URL) as second:
            second.send_text(json.dumps({"type": "auth", "token": token}))
            second.receive_text()

            assert feed.subscriber_count == 2
            assert feed._task is task_after_first, (
                "the second connection reused the running loop"
            )

            replay_tasks = [
                task
                for task in asyncio.all_tasks(feed._task.get_loop())
                if task.get_name() == "flare-replay" and not task.done()
            ]
            assert len(replay_tasks) == 1, (
                f"exactly one replay loop per server, found {len(replay_tasks)}"
            )


@needs_data
def test_pause_stops_delivery_and_resume_restarts_it(
    sync_client: TestClient,
) -> None:
    """CONTRACT §3.2 — inbound control frames.

    Pause is per SUBSCRIBER, not per server: one analyst pausing their view
    must not stop the feed for everyone else, and must not stop the producer
    (which would also stop persistence).
    """
    from app.ingestion.feed import get_feed

    token = _make_user_and_token("pause@example.com")

    with sync_client.websocket_connect(WS_URL) as socket:
        socket.send_text(json.dumps({"type": "auth", "token": token}))
        socket.receive_text()

        feed = get_feed()
        subscriber = next(iter(feed._subscribers))

        socket.send_text(json.dumps({"type": "pause"}))
        _wait_for(lambda: subscriber.paused is True)
        assert subscriber.paused is True

        socket.send_text(json.dumps({"type": "resume"}))
        _wait_for(lambda: subscriber.paused is False)
        assert subscriber.paused is False


@needs_data
def test_a_config_frame_retunes_the_shared_replay_rate(
    sync_client: TestClient,
) -> None:
    """`{"type":"config","speed":n}` — exposed by the hook, never called by the
    frozen UI, and wired anyway because the contract documents it."""
    from app.ingestion.feed import get_feed

    token = _make_user_and_token("speed@example.com")

    with sync_client.websocket_connect(WS_URL) as socket:
        socket.send_text(json.dumps({"type": "auth", "token": token}))
        socket.receive_text()

        feed = get_feed()
        before = feed.engine.alerts_per_minute
        socket.send_text(json.dumps({"type": "config", "speed": 90}))
        _wait_for(lambda: feed.engine.alerts_per_minute == 90.0)

        assert feed.engine.alerts_per_minute == 90.0
        assert before != 90.0


@needs_data
def test_a_presence_frame_is_received_and_tracked(
    sync_client: TestClient,
) -> None:
    """FE-2. Phase 4 RECEIVES and tracks it; PLAN §8's dispatcher is Phase 5.

    Nothing acts on this yet, and nothing here pretends otherwise — the value
    is stored on the subscriber and that is the whole claim.
    """
    from app.ingestion.feed import get_feed

    token = _make_user_and_token("presence@example.com")

    with sync_client.websocket_connect(WS_URL) as socket:
        socket.send_text(json.dumps({"type": "auth", "token": token}))
        socket.receive_text()

        subscriber = next(iter(get_feed()._subscribers))
        socket.send_text(json.dumps({"type": "presence", "state": "backgrounded"}))
        _wait_for(lambda: subscriber.presence == "backgrounded")
        assert subscriber.presence == "backgrounded"


@needs_data
def test_an_unknown_control_frame_is_ignored_not_fatal(
    sync_client: TestClient,
) -> None:
    """A malformed frame from a future frontend must not drop the socket."""
    token = _make_user_and_token("junk@example.com")

    with sync_client.websocket_connect(WS_URL) as socket:
        socket.send_text(json.dumps({"type": "auth", "token": token}))
        socket.receive_text()

        socket.send_text("not json at all")
        socket.send_text(json.dumps({"type": "nonsense"}))

        payload = json.loads(socket.receive_text())
        assert payload["id"].startswith("ALT-"), "the stream survived both"


def _wait_for(predicate, timeout: float = 5.0) -> None:
    """Poll a condition the server applies on its own event loop.

    The control frame is handled by a task the TestClient does not await, so
    the assertion has to wait for it rather than assume it has already run.
    """
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
