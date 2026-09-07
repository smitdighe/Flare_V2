"""Live alert WebSocket.

CONTRACT §3.0 — FIRST-MESSAGE AUTH HANDSHAKE (FE-2). The token is NOT read from
the query string: PLAN §9 forbids that because it lands in access logs, browser
history and proxy logs.

  1. Client opens /api/v1/ws/stream with no query string.
  2. Server accepts, starts an auth timer, sends and streams NOTHING.
  3. Client's onopen sends {"type":"auth","token":"<jwt>"} then
     {"type":"presence","state":"active"}.
  4. Server validates and begins streaming. NO success ack — the frozen
     onmessage handler drops any frame without a top-level `id`
     (useAlertStream.js:30), so an ack would be silently discarded.
  5. On failure or timer expiry: close 4001 (invalid/expired token) or 4003
     (valid token, insufficient role). The client does not reconnect on either.

Server -> client is ONE BARE ALERT OBJECT per message. Not enveloped, not
tagged, not batched (CONTRACT §3.1).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.ingestion.feed import Subscriber, get_feed
from app.notifications.presence import get_presence
from app.security.tokens import TokenError, decode_token
from app.store.models import User
from app.store.session import get_sessionmaker

logger = logging.getLogger("flare.stream")

router = APIRouter(tags=["stream"])

AUTH_TIMEOUT_SECONDS = 10.0

CLOSE_INVALID_TOKEN = 4001
CLOSE_FORBIDDEN = 4003


async def _resolve_user(session: AsyncSession, token: str) -> User | None:
    try:
        payload = decode_token(token, "access")
    except TokenError:
        return None
    user = await session.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        return None
    if int(payload.get("tv", 0)) != user.token_version:
        return None
    return user


async def _authenticate(websocket: WebSocket) -> User | None:
    """Wait for the first frame and validate it.

    The timer is what stops an unauthenticated socket being held open. Any
    frame arriving before a successful auth is discarded.
    """
    try:
        raw = await asyncio.wait_for(
            websocket.receive_text(), timeout=AUTH_TIMEOUT_SECONDS
        )
    except (TimeoutError, WebSocketDisconnect):
        return None

    try:
        message = json.loads(raw)
    except json.JSONDecodeError:
        return None

    if not isinstance(message, dict) or message.get("type") != "auth":
        return None

    token = message.get("token")
    if not isinstance(token, str) or not token:
        return None

    async with get_sessionmaker()() as session:
        return await _resolve_user(session, token)


async def _read_commands(
    websocket: WebSocket, subscriber: Subscriber, connection_id: int
) -> None:
    """Inbound control frames: pause / resume / config / presence.

    EVERY frame refreshes the presence registry's staleness timer, not only the
    presence ones. A pause or a config frame came from a browser that is still
    running, which is what the timer is asking about; visibility is a separate
    question and only the presence frames answer it (PLAN §8.2).
    """
    feed = get_feed()
    presence = get_presence()
    while True:
        raw = await websocket.receive_text()
        presence.touch(connection_id)
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue

        kind = message.get("type")
        if kind == "pause":
            subscriber.paused = True
        elif kind == "resume":
            subscriber.paused = False
        elif kind == "config":
            speed = message.get("speed")
            if isinstance(speed, (int, float)) and speed > 0:
                feed.set_rate(float(speed))
        elif kind == "presence":
            state = message.get("state")
            if state in ("active", "backgrounded"):
                subscriber.presence = state
                presence.set_state(connection_id, state)


async def _write_alerts(websocket: WebSocket, subscriber: Subscriber) -> None:
    while True:
        payload: dict[str, Any] = await subscriber.queue.get()
        await websocket.send_text(json.dumps(payload))


@router.websocket("/ws/stream")
async def stream(websocket: WebSocket) -> None:
    await websocket.accept()

    user = await _authenticate(websocket)
    if user is None:
        await websocket.close(code=CLOSE_INVALID_TOKEN, reason="authentication failed")
        return

    feed = get_feed()
    subscriber = feed.subscribe()
    await feed.start()

    # PLAN §8.2. The connection is registered as `active` because that is what
    # the client's own handshake asserts a beat later (FE-2 sends `auth` then
    # `presence`); registering it as away would open a gap in which a watching
    # analyst could be emailed. The frame that follows corrects it if the tab
    # opened hidden.
    presence = get_presence()
    connection_id = presence.connect(user.id)

    reader = asyncio.create_task(_read_commands(websocket, subscriber, connection_id))
    writer = asyncio.create_task(_write_alerts(websocket, subscriber))

    try:
        done, pending = await asyncio.wait(
            {reader, writer}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        for task in done:
            with contextlib.suppress(WebSocketDisconnect, asyncio.CancelledError):
                task.result()
    except WebSocketDisconnect:
        pass
    finally:
        for task in (reader, writer):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        feed.unsubscribe(subscriber)
        # PLAN §8.2 — the socket closing is the PRIMARY away signal; the stale
        # guard is only the backstop for a connection that neither closes nor
        # speaks. Zero remaining connections means away.
        presence.disconnect(connection_id)
