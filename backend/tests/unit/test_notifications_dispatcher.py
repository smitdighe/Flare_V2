"""Dispatch policy. PLAN §8.1 / §8.3 / §8.5.

The core assertion of the phase is `test_no_email_for_a_user_who_is_watching`.
Everything else in this file is the surrounding machinery.
"""

import asyncio
from typing import Any

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.notifications.dispatcher import NotificationDispatcher
from app.notifications.email import Envelope, PermanentSendError, TransientSendError
from app.notifications.presence import BACKGROUNDED, PresenceRegistry
from app.store.models import AuditLog, NotificationLog, NotificationPreference
from app.store.session import get_sessionmaker
from tests.conftest import make_user

EVENT = "alert.high_severity"


class FakeTransport:
    """Records what would have been sent. Optionally fails first."""

    def __init__(self, failures: list[Exception] | None = None) -> None:
        self.sent: list[Envelope] = []
        self.attempts = 0
        self._failures = list(failures or [])

    async def send(self, envelope: Envelope) -> None:
        self.attempts += 1
        if self._failures:
            raise self._failures.pop(0)
        self.sent.append(envelope)


class HangingTransport:
    """Accepts the connection and then answers nothing, forever."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()

    async def send(self, envelope: Envelope) -> None:
        self.entered.set()
        await asyncio.sleep(3600)


def expire_send_windows(dispatcher: NotificationDispatcher) -> None:
    """Age every open debounce window out, without sleeping.

    `flush` drains a window once `monotonic() - last_sent >= debounce`, so
    rewinding `last_sent` past the debounce is exactly what the passage of time
    would have done — and it cannot lose a race with however long the test's own
    database writes happened to take.
    """
    for window in dispatcher._send_windows.values():
        window.last_sent -= dispatcher.settings.notification_debounce_seconds + 1.0
    for suppressed in dispatcher._suppress_windows.values():
        suppressed.opened_at -= dispatcher.settings.notification_debounce_seconds + 1.0


def alert(
    alert_id: str = "ALT-000001",
    severity: str = "critical",
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": alert_id,
        "severity": severity,
        "attack_type": "botnet",
        "src_ip": "192.168.10.15",
        "dest_ip": "205.174.165.73",
        "dest_port": 8080,
        "protocol": "TCP",
        "signature": "Botnet C2 beacon",
        "mitre_technique": "T1071.001",
        "rule_trace": [],
    }
    payload.update(overrides)
    return payload


def build(
    transport: Any,
    presence: PresenceRegistry | None = None,
    **overrides: Any,
) -> NotificationDispatcher:
    settings = get_settings().model_copy(
        update={
            "notifications_enabled": True,
            "smtp_host": "smtp.example.test",
            "smtp_from": "flare@example.com",
            "notification_retry_backoff_seconds": 0.01,
            **overrides,
        }
    )
    return NotificationDispatcher(
        settings,
        transport=transport,
        presence=presence or PresenceRegistry(stale_seconds=60),
    )


async def subscribe(email: str = "analyst@example.com", enabled: bool = True) -> int:
    user_id = await make_user(email, role="analyst")
    async with get_sessionmaker()() as session:
        session.add(
            NotificationPreference(
                user_id=user_id,
                channel="email",
                event_type=EVENT,
                is_enabled=enabled,
            )
        )
        await session.commit()
    return user_id


async def logs(outcome: str | None = None) -> list[NotificationLog]:
    async with get_sessionmaker()() as session:
        stmt = select(NotificationLog).order_by(NotificationLog.id)
        if outcome:
            stmt = stmt.where(NotificationLog.outcome == outcome)
        return list((await session.execute(stmt)).scalars().all())


async def audit_actions() -> list[str]:
    async with get_sessionmaker()() as session:
        return [
            row.action
            for row in (
                await session.execute(select(AuditLog).order_by(AuditLog.id))
            ).scalars()
        ]


# ---------------------------------------------------------------------------
# the core assertion
# ---------------------------------------------------------------------------


async def test_no_email_for_a_user_who_is_watching():
    """PLAN §8.5 — the assertion the whole phase exists to make."""
    user_id = await subscribe()
    presence = PresenceRegistry(stale_seconds=60)
    presence.connect(user_id)  # active by default
    transport = FakeTransport()
    dispatcher = build(transport, presence)

    await dispatcher.process(alert())

    assert transport.sent == []
    assert dispatcher.sent == 0


async def test_suppression_is_recorded_not_silently_skipped():
    user_id = await subscribe()
    presence = PresenceRegistry(stale_seconds=60)
    presence.connect(user_id)
    dispatcher = build(FakeTransport(), presence)

    await dispatcher.process(alert())

    rows = await logs("suppressed")
    assert len(rows) == 1
    assert rows[0].user_id == user_id
    assert rows[0].alert_id == "ALT-000001"
    assert rows[0].rollup_count == 1
    assert rows[0].reason and "watching" in rows[0].reason
    assert "notification.suppressed" in await audit_actions()


# ---------------------------------------------------------------------------
# presence transitions
# ---------------------------------------------------------------------------


async def test_backgrounded_tab_sends():
    user_id = await subscribe()
    presence = PresenceRegistry(stale_seconds=60)
    connection = presence.connect(user_id)
    presence.set_state(connection, BACKGROUNDED)
    transport = FakeTransport()
    dispatcher = build(transport, presence)

    await dispatcher.process(alert())

    assert len(transport.sent) == 1
    assert transport.sent[0].to == "analyst@example.com"
    assert (await logs("sent"))[0].rollup_count == 1


async def test_disconnected_user_sends():
    await subscribe()
    transport = FakeTransport()
    dispatcher = build(transport, PresenceRegistry(stale_seconds=60))

    await dispatcher.process(alert())

    assert len(transport.sent) == 1


async def test_multi_tab_any_active_suppresses():
    user_id = await subscribe()
    presence = PresenceRegistry(stale_seconds=60)
    first = presence.connect(user_id)
    presence.connect(user_id)
    presence.set_state(first, BACKGROUNDED)
    transport = FakeTransport()
    dispatcher = build(transport, presence)

    await dispatcher.process(alert())

    assert transport.sent == []


async def test_stale_presence_makes_the_user_eligible_again():
    """A crashed tab stops suppressing once its last frame ages out."""
    user_id = await subscribe()
    presence = PresenceRegistry(stale_seconds=0.05)
    presence.connect(user_id)
    transport = FakeTransport()
    dispatcher = build(transport, presence)

    await dispatcher.process(alert("ALT-000001"))
    assert transport.sent == []

    await asyncio.sleep(0.08)
    await dispatcher.process(alert("ALT-000002"))

    assert len(transport.sent) == 1


# ---------------------------------------------------------------------------
# debounce and digest
# ---------------------------------------------------------------------------


async def test_debounce_holds_inside_the_window():
    await subscribe()
    transport = FakeTransport()
    dispatcher = build(transport, notification_debounce_seconds=300.0)

    for index in range(5):
        await dispatcher.process(alert(f"ALT-00000{index}"))

    # One email, four held.
    assert len(transport.sent) == 1
    assert dispatcher.stats()["pending_alerts"] == 4


async def test_flush_rolls_the_window_up_into_one_email():
    await subscribe()
    transport = FakeTransport()
    dispatcher = build(
        transport, notification_debounce_seconds=0.05, notification_digest_threshold=10
    )

    await dispatcher.process(alert("ALT-000001"))
    await dispatcher.process(alert("ALT-000002"))
    await dispatcher.process(alert("ALT-000003"))
    await asyncio.sleep(0.08)
    result = await dispatcher.flush()

    assert result["sent"] == 1
    assert len(transport.sent) == 2
    rollup = transport.sent[1]
    assert "2 alerts in the last" in rollup.subject
    sent_rows = await logs("sent")
    assert [row.rollup_count for row in sent_rows] == [1, 2]


async def test_digest_lists_and_caps():
    """More than N in a window is ONE digest, not N emails."""
    await subscribe()
    transport = FakeTransport()
    dispatcher = build(
        transport,
        # Long enough that seven sequential `process` calls — each of which
        # writes to the database — cannot themselves outlast the window. With a
        # 0.05s debounce this test was a race: if the loop took longer than the
        # window, alert 5 or 6 opened a SECOND send window and sent a third
        # email, and the assertion below failed with 3 == 2. The window is
        # expired explicitly afterwards instead of by sleeping, so the behaviour
        # under test is the same and the clock is no longer a participant.
        notification_debounce_seconds=30.0,
        notification_digest_threshold=2,
        notification_digest_max_alerts=3,
    )

    for index in range(1, 8):
        await dispatcher.process(alert(f"ALT-00000{index}"))
    expire_send_windows(dispatcher)
    await dispatcher.flush()

    # Seven alerts, two emails: the immediate one and one digest for the rest.
    assert len(transport.sent) == 2
    digest = transport.sent[1]
    assert digest.subject.startswith("[Flare] 6 alerts in the last")
    assert "... and 3 more" in digest.text
    assert digest.text.count("ALT-") == 3


async def test_flush_suppresses_a_rollup_for_a_user_who_came_back():
    user_id = await subscribe()
    presence = PresenceRegistry(stale_seconds=60)
    transport = FakeTransport()
    dispatcher = build(transport, presence, notification_debounce_seconds=0.05)

    await dispatcher.process(alert("ALT-000001"))
    await dispatcher.process(alert("ALT-000002"))
    assert len(transport.sent) == 1

    presence.connect(user_id)  # analyst is back and watching
    await asyncio.sleep(0.08)
    result = await dispatcher.flush()

    assert result["sent"] == 0
    assert result["suppressed"] == 1
    assert len(transport.sent) == 1
    assert len(await logs("suppressed")) == 1


async def test_pending_buffer_is_bounded():
    await subscribe()
    dispatcher = build(
        FakeTransport(),
        notification_debounce_seconds=300.0,
        notification_pending_max=3,
    )

    for index in range(20):
        await dispatcher.process(alert(f"ALT-{index:06d}"))

    assert dispatcher.stats()["pending_alerts"] == 3


# ---------------------------------------------------------------------------
# preferences
# ---------------------------------------------------------------------------


async def test_disabled_preference_stops_sends_immediately():
    user_id = await subscribe()
    transport = FakeTransport()
    dispatcher = build(transport)

    await dispatcher.process(alert("ALT-000001"))
    assert len(transport.sent) == 1

    async with get_sessionmaker()() as session:
        row = (
            await session.execute(
                select(NotificationPreference).where(
                    NotificationPreference.user_id == user_id
                )
            )
        ).scalar_one()
        row.is_enabled = False
        await session.commit()

    await dispatcher.process(alert("ALT-000002"))

    assert len(transport.sent) == 1


async def test_disabling_during_a_window_stops_its_rollup():
    user_id = await subscribe()
    transport = FakeTransport()
    dispatcher = build(transport, notification_debounce_seconds=0.05)

    await dispatcher.process(alert("ALT-000001"))
    await dispatcher.process(alert("ALT-000002"))

    async with get_sessionmaker()() as session:
        row = (
            await session.execute(
                select(NotificationPreference).where(
                    NotificationPreference.user_id == user_id
                )
            )
        ).scalar_one()
        row.is_enabled = False
        await session.commit()

    await asyncio.sleep(0.08)
    result = await dispatcher.flush()

    assert result["sent"] == 0
    assert len(transport.sent) == 1


async def test_a_user_with_no_preference_is_not_emailed():
    await make_user("nobody@example.com")
    transport = FakeTransport()
    dispatcher = build(transport)

    await dispatcher.process(alert())

    assert transport.sent == []


# ---------------------------------------------------------------------------
# triggers
# ---------------------------------------------------------------------------


async def test_unknown_severity_never_triggers():
    """PLAN D27 / Q10 — fails closed on the pipeline's own failures."""
    await subscribe()
    transport = FakeTransport()
    dispatcher = build(transport)

    assert dispatcher.event_types(alert(severity="unknown")) == []
    await dispatcher.process(
        alert(severity="unknown", rule_trace=[{"rule_id": 1, "fired": True}])
    )

    assert transport.sent == []
    assert await logs() == []


async def test_severity_below_the_trigger_does_not_notify():
    await subscribe()
    transport = FakeTransport()
    dispatcher = build(transport)

    await dispatcher.process(alert(severity="low"))

    assert transport.sent == []


async def test_trigger_severities_are_configurable():
    await subscribe()
    transport = FakeTransport()
    dispatcher = build(transport, notify_severities=["low"])

    await dispatcher.process(alert(severity="low"))

    assert len(transport.sent) == 1


async def test_rule_match_is_its_own_event_type():
    user_id = await make_user("rules@example.com")
    async with get_sessionmaker()() as session:
        session.add(
            NotificationPreference(
                user_id=user_id,
                channel="email",
                event_type="rule.matched",
                is_enabled=True,
            )
        )
        await session.commit()
    transport = FakeTransport()
    dispatcher = build(transport)

    # Below the severity floor, so `alert.high_severity` does not fire — the
    # only reason this sends is that a rule matched.
    await dispatcher.process(
        alert(severity="medium", rule_trace=[{"rule_id": 3, "fired": True}])
    )

    assert len(transport.sent) == 1
    assert (await logs("sent"))[0].event_type == "rule.matched"


# ---------------------------------------------------------------------------
# retry and failure
# ---------------------------------------------------------------------------


async def test_transient_failure_is_retried_then_logged():
    await subscribe()
    transport = FakeTransport(
        failures=[
            TransientSendError("connection refused"),
            TransientSendError("connection refused"),
            TransientSendError("connection refused"),
        ]
    )
    dispatcher = build(transport, notification_max_attempts=3)

    await dispatcher.process(alert())

    assert transport.attempts == 3
    rows = await logs("failed")
    assert len(rows) == 1
    assert rows[0].attempts == 3
    assert rows[0].reason and "connection refused" in rows[0].reason
    assert "notification.failed" in await audit_actions()
    assert dispatcher.failed == 1


async def test_retry_backs_off_between_attempts():
    await subscribe()
    transport = FakeTransport(
        failures=[TransientSendError("down"), TransientSendError("down")]
    )
    dispatcher = build(
        transport, notification_max_attempts=3, notification_retry_backoff_seconds=0.05
    )

    started = asyncio.get_running_loop().time()
    await dispatcher.process(alert())
    elapsed = asyncio.get_running_loop().time() - started

    # 0.05 after the first failure, 0.10 after the second.
    assert transport.attempts == 3
    assert elapsed >= 0.15
    assert len(transport.sent) == 1


async def test_a_recovered_send_is_logged_as_sent():
    await subscribe()
    transport = FakeTransport(failures=[TransientSendError("blip")])
    dispatcher = build(transport, notification_max_attempts=3)

    await dispatcher.process(alert())

    assert len(transport.sent) == 1
    rows = await logs("sent")
    assert rows[0].attempts == 2


async def test_permanent_failure_is_not_retried():
    """A 5xx is the server rejecting the message. A retry reproduces it."""
    await subscribe()
    transport = FakeTransport(
        failures=[PermanentSendError("SMTP 550: mailbox unavailable")]
    )
    dispatcher = build(transport, notification_max_attempts=3)

    await dispatcher.process(alert())

    assert transport.attempts == 1
    rows = await logs("failed")
    assert rows[0].attempts == 1
    assert rows[0].reason and rows[0].reason.startswith("permanent:")


# ---------------------------------------------------------------------------
# the hand-off
# ---------------------------------------------------------------------------


async def test_submit_does_not_block_on_a_hanging_send():
    """PLAN §8.3 — the send is off the feed loop AND off the request path."""
    await subscribe()
    transport = HangingTransport()
    dispatcher = build(transport)
    await dispatcher.start()
    try:
        dispatcher.submit(alert("ALT-000001"))
        await asyncio.wait_for(transport.entered.wait(), timeout=2)

        # The worker is now wedged inside a send that never returns. Submitting
        # more must still be instant, which is what stops a black-holed relay
        # from stalling the replay loop.
        started = asyncio.get_running_loop().time()
        for index in range(2, 60):
            dispatcher.submit(alert(f"ALT-{index:06d}"))
        assert asyncio.get_running_loop().time() - started < 0.5
        assert dispatcher.submitted == 59
    finally:
        await dispatcher.stop()


async def test_submit_drops_and_counts_when_the_queue_is_full():
    await subscribe()
    dispatcher = build(HangingTransport(), notification_queue_size=4)

    for index in range(20):
        dispatcher.submit(alert(f"ALT-{index:06d}"))

    stats = dispatcher.stats()
    assert stats["queue"]["accepted"] == 4
    assert stats["queue"]["dropped"] == 16


async def test_a_disabled_dispatcher_does_nothing():
    await subscribe()
    settings = get_settings().model_copy(update={"notifications_enabled": False})
    transport = FakeTransport()
    dispatcher = NotificationDispatcher(settings, transport=transport)

    dispatcher.submit(alert())
    await dispatcher.start()
    result = await dispatcher.flush()

    assert result == {"sent": 0, "suppressed": 0, "windows": 0, "enabled": False}
    assert dispatcher.submitted == 0
    assert transport.sent == []


async def test_a_failing_dispatch_does_not_kill_the_worker():
    await subscribe()

    class Exploding:
        def __init__(self) -> None:
            self.calls = 0

        async def send(self, envelope: Envelope) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("not an SMTP error at all")

    async def wait_for(count: int) -> None:
        for _ in range(200):
            if transport.calls >= count:
                return
            await asyncio.sleep(0.01)
        raise AssertionError(f"transport never reached {count} calls")

    transport = Exploding()
    dispatcher = build(transport, notification_debounce_seconds=0.05)
    await dispatcher.start()
    try:
        dispatcher.submit(alert("ALT-000001"))
        await wait_for(1)

        # The first dispatch raised something that is not an SMTP error at all.
        # The worker must still be draining.
        await asyncio.sleep(0.08)
        dispatcher.submit(alert("ALT-000002"))
        await wait_for(2)

        # Stated here rather than left to `wait_for`'s timeout path, so the
        # claim the test is making is visible in the test.
        assert transport.calls == 2, (
            "the worker survived an exception that was not an SMTP error and "
            "went on to dispatch the next alert"
        )
        assert dispatcher.submitted == 2
    finally:
        await dispatcher.stop()


@pytest.mark.parametrize("severity", ["critical", "high"])
async def test_default_trigger_severities(severity: str):
    await subscribe()
    transport = FakeTransport()
    dispatcher = build(transport)

    await dispatcher.process(alert(severity=severity))

    assert len(transport.sent) == 1
