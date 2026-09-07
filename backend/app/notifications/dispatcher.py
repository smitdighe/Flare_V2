"""The dispatcher. PLAN §8.1 / §8.3 — presence, debounce, digest, retry, log.

**SUPPRESSION IS THE FEATURE.** An analyst watching the live feed can already
see the alert; emailing them about it is noise that trains people to ignore the
channel. Every other control here — the debounce, the digest, the retry — is
ordinary plumbing. The presence check is the reason the feature exists, so it
is the first question asked and the one with a test named after it.

**THE DEBOUNCE WINDOW GOVERNS THE WHOLE DECISION, NOT JUST THE SEND.** One
notification per user per event type per window, in both directions: sends roll
up into one email with a count, and suppressions roll up into one log row with
a count. Recording every suppressed alert separately would put twenty rows a
minute into the audit trail and make the screen useless during the exact demo
it exists to support — and it would describe a per-alert decision the mail side
does not make.

**FIRST ONE IS IMMEDIATE.** The window opens on a send, not before it. An
analyst who backgrounds the tab and then gets paged wants the mail now, not at
the end of a five-minute window; the debounce is there to stop the second
through the twentieth, which it does.

**PENDING ALERTS ARE RE-EXAMINED AT FLUSH.** A user who came back and is now
watching has seen them, so the held rollup is suppressed rather than sent, and
a preference disabled during the window stops its own rollup. Both are checked
again at flush rather than trusted from when the alert arrived.

**OFF THE REQUEST PATH AND OFF THE FEED LOOP.** The replay loop calls `submit`,
which is a bounded, non-blocking hand-off. Everything after it — the preference
query, the presence check, the SMTP round trip and its retries — happens on the
dispatcher's own worker. An SMTP host that accepts a connection and then
answers nothing cannot stall the alert feed.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.ingestion.labels import severity_rank
from app.notifications.email import (
    PermanentSendError,
    SmtpTransport,
    TransientSendError,
    Transport,
    render,
)
from app.notifications.presence import PresenceRegistry, get_presence
from app.store.models import NotificationLog, NotificationPreference, User
from app.store.repositories import write_audit
from app.store.session import get_sessionmaker
from app.workers.queue import BoundedQueue, QueueFullError

logger = logging.getLogger("flare.notifications")

CHANNEL = "email"

EVENT_HIGH_SEVERITY = "alert.high_severity"
EVENT_RULE_MATCHED = "rule.matched"

SUPPRESSED_REASON = (
    "the subscriber was watching the live feed when this fired, so the alert "
    "was already on their screen"
)


@dataclass
class SendWindow:
    """One (user, event type) debounce window on the SEND side."""

    last_sent: float
    pending: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SuppressWindow:
    """One (user, event type) debounce window on the SUPPRESSION side."""

    opened_at: float
    log_id: int
    count: int = 1


Key = tuple[int, str]


class NotificationDispatcher:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: Transport | None = None,
        presence: PresenceRegistry | None = None,
    ) -> None:
        self.settings = settings
        self.enabled = settings.notifications_enabled
        self._presence = presence
        self._transport = transport
        self._queue: BoundedQueue[dict[str, Any]] = BoundedQueue(
            "notifications", settings.notification_queue_size
        )
        self._worker: asyncio.Task[None] | None = None
        self._send_windows: dict[Key, SendWindow] = {}
        self._suppress_windows: dict[Key, SuppressWindow] = {}
        self.submitted = 0
        self.processed = 0
        self.sent = 0
        self.suppressed = 0
        self.failed = 0

    # -- collaborators -----------------------------------------------------

    @property
    def presence(self) -> PresenceRegistry:
        if self._presence is None:
            self._presence = get_presence()
        return self._presence

    @property
    def transport(self) -> Transport:
        if self._transport is None:
            self._transport = SmtpTransport(self.settings)
        return self._transport

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if not self.enabled or (self._worker is not None and not self._worker.done()):
            return
        self._worker = asyncio.create_task(self._run(), name="flare-notifications")

    async def stop(self) -> None:
        if self._worker is None:
            return
        self._worker.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._worker
        self._worker = None

    async def _run(self) -> None:
        while True:
            alert = await self._queue.get()
            try:
                await self.process(alert)
            except asyncio.CancelledError:
                raise
            except Exception:
                # A dispatcher that dies on one bad alert stops notifying about
                # every alert after it, silently. Log and keep draining.
                logger.exception("notification dispatch failed", extra={"request_id": "-"})
            finally:
                self._queue.release()

    # -- the hand-off ------------------------------------------------------

    def submit(self, alert: dict[str, Any]) -> None:
        """Called from the replay loop. Never blocks, never raises."""
        if not self.enabled or not self.event_types(alert):
            return
        try:
            self._queue.put_nowait(alert)
        except QueueFullError:
            # Counted inside the queue. A dropped notification is visible in
            # stats rather than silently absorbed.
            return
        self.submitted += 1

    # -- policy ------------------------------------------------------------

    def event_types(self, alert: dict[str, Any]) -> list[str]:
        """Which subscriptions this alert satisfies.

        PLAN D27 / Q10: `unknown` sits outside the severity order, so it
        satisfies nothing and returns early. An alert whose classification
        FAILED must never page anyone — that is the pipeline emailing about
        itself.
        """
        severity = str(alert.get("severity", "unknown"))
        if severity_rank(severity) < 0:
            return []

        events: list[str] = []
        if severity in self.settings.notify_severities:
            events.append(EVENT_HIGH_SEVERITY)
        if any(entry.get("fired") for entry in alert.get("rule_trace") or []):
            events.append(EVENT_RULE_MATCHED)
        return events

    async def process(self, alert: dict[str, Any]) -> None:
        events = self.event_types(alert)
        if not events:
            return
        self.processed += 1
        async with get_sessionmaker()() as session:
            for event_type in events:
                for user in await self._subscribers(session, event_type):
                    await self._route(session, user, event_type, alert)
            await session.commit()

    async def _subscribers(
        self, session: AsyncSession, event_type: str
    ) -> list[User]:
        """Enabled email preferences for this event, resolved to live users.

        Read on every dispatch rather than cached: PLAN §8.3 requires that
        disabling a preference stops sends immediately, and a cache is exactly
        how "immediately" becomes "within a minute".
        """
        rows = (
            await session.execute(
                select(User)
                .join(
                    NotificationPreference,
                    NotificationPreference.user_id == User.id,
                )
                .where(
                    NotificationPreference.channel == CHANNEL,
                    NotificationPreference.event_type == event_type,
                    NotificationPreference.is_enabled.is_(True),
                    User.is_active.is_(True),
                )
                .order_by(User.id)
            )
        ).scalars()
        return list(rows)

    async def _route(
        self,
        session: AsyncSession,
        user: User,
        event_type: str,
        alert: dict[str, Any],
    ) -> None:
        key: Key = (user.id, event_type)
        now = time.monotonic()

        if self.presence.is_watching(user.id):
            await self._record_suppression(session, user, event_type, alert, now)
            return

        debounce = self.settings.notification_debounce_seconds
        window = self._send_windows.get(key)
        if window is not None and (now - window.last_sent) < debounce:
            if len(window.pending) < self.settings.notification_pending_max:
                window.pending.append(alert)
            return

        self._send_windows[key] = SendWindow(last_sent=now)
        await self._deliver(session, user, event_type, [alert])

    async def _record_suppression(
        self,
        session: AsyncSession,
        user: User,
        event_type: str,
        alert: dict[str, Any],
        now: float,
    ) -> None:
        key: Key = (user.id, event_type)
        window = self._suppress_windows.get(key)
        if window is not None and (
            now - window.opened_at
        ) < self.settings.notification_debounce_seconds:
            window.count += 1
            row = await session.get(NotificationLog, window.log_id)
            if row is not None:
                row.rollup_count = window.count
                if severity_rank(str(alert.get("severity"))) > severity_rank(
                    str(row.severity)
                ):
                    row.severity = str(alert.get("severity"))
            self.suppressed += 1
            return

        row = NotificationLog(
            user_id=user.id,
            channel=CHANNEL,
            event_type=event_type,
            outcome="suppressed",
            reason=SUPPRESSED_REASON,
            alert_id=str(alert.get("id")) if alert.get("id") else None,
            severity=str(alert.get("severity")) if alert.get("severity") else None,
            rollup_count=1,
            recipient=user.email,
            attempts=0,
        )
        session.add(row)
        await session.flush()
        self._suppress_windows[key] = SuppressWindow(opened_at=now, log_id=row.id)
        self.suppressed += 1
        await write_audit(
            session,
            action="notification.suppressed",
            resource_type="notification",
            actor_id=None,
            resource_id=str(row.id),
            details={
                "event_type": event_type,
                "channel": CHANNEL,
                "presence": self.presence.snapshot(user.id),
                "alert_id": row.alert_id,
            },
        )

    # -- delivery ----------------------------------------------------------

    async def _deliver(
        self,
        session: AsyncSession,
        user: User,
        event_type: str,
        alerts: list[dict[str, Any]],
    ) -> None:
        total = len(alerts)
        ordered = sorted(
            alerts, key=lambda a: severity_rank(str(a.get("severity"))), reverse=True
        )
        top = ordered[0]
        envelope = render(
            to=user.email,
            event_type=event_type,
            alerts=ordered,
            total=total,
            window_minutes=self.settings.notification_debounce_seconds / 60,
            dashboard_url=f"{self.settings.dashboard_base_url.rstrip('/')}/dashboard",
            digest_max=self.settings.notification_digest_max_alerts,
        )

        attempts = 0
        error: str | None = None
        for attempt in range(1, self.settings.notification_max_attempts + 1):
            attempts = attempt
            try:
                await self.transport.send(envelope)
                error = None
                break
            except PermanentSendError as exc:
                # The server rejected THIS MESSAGE. A retry reproduces it.
                error = f"permanent: {exc}"
                break
            except TransientSendError as exc:
                error = f"transient: {exc}"
                if attempt == self.settings.notification_max_attempts:
                    break
                await asyncio.sleep(
                    self.settings.notification_retry_backoff_seconds
                    * (2 ** (attempt - 1))
                )

        outcome = "failed" if error else "sent"
        row = NotificationLog(
            user_id=user.id,
            channel=CHANNEL,
            event_type=event_type,
            outcome=outcome,
            reason=error,
            alert_id=str(top.get("id")) if top.get("id") else None,
            severity=str(top.get("severity")) if top.get("severity") else None,
            rollup_count=total,
            recipient=user.email,
            attempts=attempts,
        )
        session.add(row)
        await session.flush()

        if error:
            self.failed += 1
            logger.error(
                "notification send failed",
                extra={
                    "request_id": "-",
                    "event_type": event_type,
                    "attempts": attempts,
                    "error": error,
                },
            )
        else:
            self.sent += 1

        await write_audit(
            session,
            action="notification.sent" if outcome == "sent" else "notification.failed",
            resource_type="notification",
            actor_id=None,
            resource_id=str(row.id),
            details={
                "event_type": event_type,
                "channel": CHANNEL,
                "rollup_count": total,
                "attempts": attempts,
                "digest": total > self.settings.notification_digest_threshold,
                "error": error,
            },
        )

    # -- the flusher -------------------------------------------------------

    async def flush(self) -> dict[str, Any]:
        """Drain windows whose debounce has expired. PLAN §8.3 rollup / digest.

        Run by the scheduler. Without it a rollup held during a quiet period
        would wait for the next triggering alert, which in a quiet period is
        exactly what does not come.
        """
        if not self.enabled:
            return {"sent": 0, "suppressed": 0, "windows": 0, "enabled": False}

        now = time.monotonic()
        debounce = self.settings.notification_debounce_seconds

        for key, suppress_window in list(self._suppress_windows.items()):
            if (now - suppress_window.opened_at) >= debounce:
                del self._suppress_windows[key]

        due = [
            (key, send_window)
            for key, send_window in self._send_windows.items()
            if (now - send_window.last_sent) >= debounce
        ]
        sent = 0
        suppressed = 0
        async with get_sessionmaker()() as session:
            for key, window in due:
                user_id, event_type = key
                if not window.pending:
                    # Nothing accumulated: the window has simply expired and
                    # the next alert should send immediately.
                    del self._send_windows[key]
                    continue

                pending = window.pending
                window.pending = []
                window.last_sent = now

                user = await session.get(User, user_id)
                if user is None or not user.is_active:
                    del self._send_windows[key]
                    continue

                # Re-checked, not trusted: the preference may have been turned
                # off, and the analyst may have come back, while these were
                # held.
                if not await self._still_subscribed(session, user_id, event_type):
                    del self._send_windows[key]
                    continue
                if self.presence.is_watching(user_id):
                    for alert in pending:
                        await self._record_suppression(
                            session, user, event_type, alert, now
                        )
                    suppressed += len(pending)
                    continue

                await self._deliver(session, user, event_type, pending)
                sent += 1
            await session.commit()

        return {
            "sent": sent,
            "suppressed": suppressed,
            "windows": len(due),
            "enabled": True,
        }

    async def _still_subscribed(
        self, session: AsyncSession, user_id: int, event_type: str
    ) -> bool:
        row = (
            await session.execute(
                select(NotificationPreference.id).where(
                    NotificationPreference.user_id == user_id,
                    NotificationPreference.channel == CHANNEL,
                    NotificationPreference.event_type == event_type,
                    NotificationPreference.is_enabled.is_(True),
                )
            )
        ).scalar_one_or_none()
        return row is not None

    # -- observability -----------------------------------------------------

    def stats(self) -> dict[str, Any]:
        queue = self._queue.stats()
        return {
            "enabled": self.enabled,
            "running": self._worker is not None and not self._worker.done(),
            "submitted": self.submitted,
            "processed": self.processed,
            "sent": self.sent,
            "suppressed": self.suppressed,
            "failed": self.failed,
            "open_send_windows": len(self._send_windows),
            "pending_alerts": sum(
                len(w.pending) for w in self._send_windows.values()
            ),
            "presence_connections": self.presence.connection_count,
            "presence_users": self.presence.user_count,
            "queue": {
                "name": queue.name,
                "maxsize": queue.maxsize,
                "depth": queue.depth,
                "accepted": queue.accepted,
                "dropped": queue.dropped,
            },
        }


_dispatcher: NotificationDispatcher | None = None


def get_dispatcher() -> NotificationDispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = NotificationDispatcher(get_settings())
    return _dispatcher


def set_dispatcher(dispatcher: NotificationDispatcher) -> None:
    global _dispatcher
    _dispatcher = dispatcher


def reset_dispatcher() -> None:
    global _dispatcher
    _dispatcher = None
