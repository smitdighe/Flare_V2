"""Presence registry. PLAN §8.2 / D12."""

import asyncio

from app.notifications.presence import ACTIVE, BACKGROUNDED, PresenceRegistry


def test_connect_defaults_to_active_and_counts():
    registry = PresenceRegistry(stale_seconds=60)
    registry.connect(user_id=1)

    assert registry.is_watching(1) is True
    snapshot = registry.snapshot(1)
    assert snapshot["state"] == ACTIVE
    assert snapshot["connection_count"] == 1


def test_backgrounded_tab_is_not_watching():
    """PLAN D12 — the whole reason presence is not connection state.

    A backgrounded tab keeps its socket open. Counting sockets would suppress
    exactly the emails the feature exists to send.
    """
    registry = PresenceRegistry(stale_seconds=60)
    connection = registry.connect(user_id=1)
    registry.set_state(connection, BACKGROUNDED)

    assert registry.is_watching(1) is False
    assert registry.snapshot(1)["state"] == BACKGROUNDED
    assert registry.snapshot(1)["connection_count"] == 1


def test_any_active_connection_wins():
    """PLAN §8.2 — multi-tab. One focused monitor is watching."""
    registry = PresenceRegistry(stale_seconds=60)
    first = registry.connect(user_id=1)
    second = registry.connect(user_id=1)

    registry.set_state(first, BACKGROUNDED)
    assert registry.is_watching(1) is True

    registry.set_state(second, BACKGROUNDED)
    assert registry.is_watching(1) is False

    registry.set_state(first, ACTIVE)
    assert registry.is_watching(1) is True


def test_disconnect_drops_the_connection_and_zero_means_away():
    registry = PresenceRegistry(stale_seconds=60)
    first = registry.connect(user_id=1)
    second = registry.connect(user_id=1)

    registry.disconnect(first)
    assert registry.is_watching(1) is True
    assert registry.snapshot(1)["connection_count"] == 1

    registry.disconnect(second)
    assert registry.is_watching(1) is False
    assert registry.snapshot(1) == {
        "state": "away",
        "last_seen": None,
        "connection_count": 0,
    }
    assert registry.user_count == 0


def test_disconnect_is_idempotent():
    registry = PresenceRegistry(stale_seconds=60)
    connection = registry.connect(user_id=1)
    registry.disconnect(connection)
    registry.disconnect(connection)
    assert registry.connection_count == 0


async def test_stale_presence_expires():
    """PLAN §8.2 — a crashed tab must not suppress a user's alerts forever."""
    registry = PresenceRegistry(stale_seconds=0.05)
    registry.connect(user_id=1)
    assert registry.is_watching(1) is True

    await asyncio.sleep(0.08)

    assert registry.is_watching(1) is False
    snapshot = registry.snapshot(1)
    # The connection is still REGISTERED — nothing closed it — but it no longer
    # counts as evidence of anybody watching.
    assert snapshot["connection_count"] == 1
    assert snapshot["stale_connections"] == 1
    assert snapshot["state"] == "away"


async def test_a_frame_refreshes_the_stale_timer():
    registry = PresenceRegistry(stale_seconds=0.12)
    connection = registry.connect(user_id=1)

    await asyncio.sleep(0.08)
    registry.touch(connection)
    await asyncio.sleep(0.08)

    assert registry.is_watching(1) is True


def test_unknown_state_is_ignored_not_guessed():
    registry = PresenceRegistry(stale_seconds=60)
    connection = registry.connect(user_id=1)
    registry.set_state(connection, "asleep")
    assert registry.snapshot(1)["state"] == ACTIVE


def test_users_are_isolated():
    registry = PresenceRegistry(stale_seconds=60)
    registry.connect(user_id=1)
    assert registry.is_watching(1) is True
    assert registry.is_watching(2) is False
