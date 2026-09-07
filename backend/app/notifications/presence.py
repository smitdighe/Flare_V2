"""Who is actually looking at the dashboard right now. PLAN §8.2, D12.

**CONNECTION STATE ALONE IS NOT PRESENCE.** A backgrounded tab keeps its
WebSocket open, so a registry that only counted sockets would suppress exactly
the emails this feature exists to send (D12). The frontend therefore reports
tab visibility over the existing socket (FE-2) and the state that matters is
`active`, not `connected`.

**ANY ACTIVE CONNECTION WINS.** A user with a backgrounded tab on one monitor
and a focused one on another is watching. Taking the last frame received, or
the newest connection, would flip that answer on an unrelated tab switch.

**IN-MEMORY AND PER-PROCESS**, matching the one-stream-loop-per-server rule
(PLAN §10 / T4). There is one replay loop and one dispatcher per server, and
presence is read by that dispatcher in the same process that received the
frames. Sharing it across processes would need a broker this build does not
have, and pretending otherwise would be a claim with nothing behind it.

**THE STALE GUARD FAILS OPEN, DELIBERATELY.** A connection whose last frame is
older than the window stops counting as watching, so a crashed tab that never
closed its socket cannot suppress a user's alerts forever. Failing open here
means an extra email; failing closed would mean silence, and silence is the
failure mode that matters for an alerting system.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Any

PresenceState = str  # "active" | "backgrounded"

ACTIVE: PresenceState = "active"
BACKGROUNDED: PresenceState = "backgrounded"
VALID_STATES: frozenset[str] = frozenset({ACTIVE, BACKGROUNDED})


@dataclass
class Connection:
    connection_id: int
    user_id: int
    state: PresenceState = ACTIVE
    # Monotonic: a wall clock that steps backwards (NTP, DST on a naive
    # timestamp) would make a live connection look stale or an old one fresh.
    last_seen: float = field(default_factory=time.monotonic)


class PresenceRegistry:
    def __init__(self, stale_seconds: float) -> None:
        self.stale_seconds = stale_seconds
        self._connections: dict[int, Connection] = {}
        self._by_user: dict[int, set[int]] = {}
        self._ids = itertools.count(1)

    # -- lifecycle ---------------------------------------------------------

    def connect(self, user_id: int, state: PresenceState = ACTIVE) -> int:
        """Register a socket. Returns the handle used to update or drop it."""
        connection_id = next(self._ids)
        self._connections[connection_id] = Connection(
            connection_id=connection_id, user_id=user_id, state=state
        )
        self._by_user.setdefault(user_id, set()).add(connection_id)
        return connection_id

    def disconnect(self, connection_id: int) -> None:
        connection = self._connections.pop(connection_id, None)
        if connection is None:
            return
        peers = self._by_user.get(connection.user_id)
        if peers is not None:
            peers.discard(connection_id)
            if not peers:
                # Zero remaining connections means away, and an empty set left
                # behind would keep the user in every snapshot forever.
                del self._by_user[connection.user_id]

    def set_state(self, connection_id: int, state: PresenceState) -> None:
        """Apply a presence frame. An unknown state is ignored, not guessed at."""
        connection = self._connections.get(connection_id)
        if connection is None or state not in VALID_STATES:
            return
        connection.state = state
        connection.last_seen = time.monotonic()

    def touch(self, connection_id: int) -> None:
        """Any inbound frame is evidence the tab is alive.

        Pause, resume and config frames all come from a browser that is still
        running, so they refresh the stale timer even though they say nothing
        about visibility.
        """
        connection = self._connections.get(connection_id)
        if connection is not None:
            connection.last_seen = time.monotonic()

    # -- reads -------------------------------------------------------------

    def _fresh(self, connection: Connection, now: float) -> bool:
        return (now - connection.last_seen) < self.stale_seconds

    def is_watching(self, user_id: int) -> bool:
        """PLAN §8.2 — any connection reporting `active` and not stale."""
        now = time.monotonic()
        return any(
            connection.state == ACTIVE and self._fresh(connection, now)
            for connection_id in self._by_user.get(user_id, ())
            if (connection := self._connections.get(connection_id)) is not None
        )

    def snapshot(self, user_id: int) -> dict[str, Any]:
        """PLAN §8.2's `{state, last_seen, connection_count}`, per user.

        `state` is `active` if any live connection says so, `backgrounded` if
        connections exist but none is active and unstale, and `away` when there
        are none — which is also what a wholly stale set reports, because a
        connection nobody has heard from is not evidence of anything.
        """
        now = time.monotonic()
        connections = [
            connection
            for connection_id in self._by_user.get(user_id, ())
            if (connection := self._connections.get(connection_id)) is not None
        ]
        if not connections:
            return {"state": "away", "last_seen": None, "connection_count": 0}

        fresh = [c for c in connections if self._fresh(c, now)]
        if any(c.state == ACTIVE for c in fresh):
            state = ACTIVE
        elif fresh:
            state = BACKGROUNDED
        else:
            state = "away"
        newest = max(c.last_seen for c in connections)
        return {
            "state": state,
            # Seconds ago, not an absolute time: `last_seen` is monotonic and
            # has no meaning outside this process.
            "last_seen": round(now - newest, 3),
            "connection_count": len(connections),
            "stale_connections": len(connections) - len(fresh),
        }

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    @property
    def user_count(self) -> int:
        return len(self._by_user)


_registry: PresenceRegistry | None = None


def get_presence() -> PresenceRegistry:
    global _registry
    if _registry is None:
        from app.config import get_settings

        _registry = PresenceRegistry(get_settings().presence_stale_seconds)
    return _registry


def reset_presence() -> None:
    global _registry
    _registry = None
