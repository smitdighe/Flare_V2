"""Async SMTP and the message templates. PLAN §8.4.

**THE TIMEOUT IS THE POINT.** The prior codebase called `smtplib.SMTP()` with
no timeout on the request path. Against a host that accepts the TCP connection
and then answers nothing — a black-holed relay, a firewall that drops rather
than rejects — that call blocks a worker forever. `aiosmtplib` with an explicit
timeout, on a background worker, is the fix for both halves of that: the call
cannot outlive the timeout, and it was never on a request path to begin with.

**TRANSIENT AND PERMANENT FAILURES ARE DIFFERENT.** A connection refused, a
timeout or a 4xx is worth retrying. A 5xx is the server saying "not this
message, not ever" — bad mailbox, blocked sender, message rejected — and
retrying it spends the same quota to reproduce the same rejection. The
distinction is made here rather than in the dispatcher because it is a property
of SMTP, not of the policy.

**NO TRACKING PIXEL, NO EXTERNAL ASSET.** Plain text plus a minimal HTML
alternative, everything inline. A security tool that phones home when its own
alert email is opened would be an odd thing to demonstrate to a judge.

**EVERY INTERPOLATED FIELD IS ESCAPED.** A signature is attacker-influenced by
construction (PLAN §9) — the attacker chooses the traffic that generates it —
so it is HTML-escaped on the way into the HTML part, exactly like any other
untrusted input.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from email.headerregistry import Address
from email.message import EmailMessage
from html import escape
from typing import Any, Protocol

import aiosmtplib

from app.config import Settings

logger = logging.getLogger("flare.notifications.email")


class TransientSendError(RuntimeError):
    """The send failed in a way that a retry might fix."""


class PermanentSendError(RuntimeError):
    """The server rejected the message itself. Retrying reproduces it."""


@dataclass(frozen=True)
class Envelope:
    to: str
    subject: str
    text: str
    html: str


class Transport(Protocol):
    async def send(self, envelope: Envelope) -> None: ...


class SmtpTransport:
    """aiosmtplib, fully async, with a timeout on every call."""

    def __init__(self, settings: Settings) -> None:
        if not settings.smtp_host or not settings.smtp_from:
            # Unreachable through config validation, which fails closed at
            # startup. Kept because a transport built by hand in a test or a
            # script would otherwise post to nowhere and report success.
            raise ValueError("SmtpTransport requires smtp_host and smtp_from")
        self.host = settings.smtp_host
        self.port = settings.smtp_port
        self.username = settings.smtp_username
        self.password = settings.smtp_password
        self.sender = settings.smtp_from
        self.sender_name = settings.smtp_from_name
        self.use_tls = settings.smtp_use_tls
        self.start_tls = settings.smtp_start_tls
        self.timeout = settings.smtp_timeout_seconds

    def build(self, envelope: Envelope) -> EmailMessage:
        message = EmailMessage()
        local, _, domain = self.sender.partition("@")
        message["From"] = str(Address(self.sender_name, local, domain))
        message["To"] = envelope.to
        message["Subject"] = envelope.subject
        message.set_content(envelope.text)
        message.add_alternative(envelope.html, subtype="html")
        return message

    async def send(self, envelope: Envelope) -> None:
        try:
            await aiosmtplib.send(
                self.build(envelope),
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                use_tls=self.use_tls,
                start_tls=self.start_tls,
                timeout=self.timeout,
            )
        except aiosmtplib.SMTPResponseException as exc:
            # 4xx is "try again later"; 5xx is "no".
            if 400 <= exc.code < 500:
                raise TransientSendError(f"SMTP {exc.code}: {exc.message}") from exc
            raise PermanentSendError(f"SMTP {exc.code}: {exc.message}") from exc
        except aiosmtplib.SMTPRecipientsRefused as exc:
            raise PermanentSendError(f"recipient refused: {exc}") from exc
        except (TimeoutError, aiosmtplib.SMTPException, OSError) as exc:
            raise TransientSendError(f"{type(exc).__name__}: {exc}") from exc


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------


def _line(alert: dict[str, Any]) -> str:
    src = alert.get("src_ip") or "?"
    dest = alert.get("dest_ip") or "?"
    port = alert.get("dest_port")
    target = f"{dest}:{port}" if port is not None else dest
    return (
        f"[{str(alert.get('severity', 'unknown')).upper()}] "
        f"{alert.get('id', '?')}  {alert.get('attack_type', 'unknown')}  "
        f"{src} -> {target}"
    )


def _detail_rows(alert: dict[str, Any]) -> list[tuple[str, str]]:
    dest = alert.get("dest_ip") or "?"
    port = alert.get("dest_port")
    return [
        ("Alert", str(alert.get("id", "?"))),
        ("Severity", str(alert.get("severity", "unknown")).upper()),
        ("Attack type", str(alert.get("attack_type", "unknown"))),
        (
            "Flow",
            f"{alert.get('src_ip', '?')} -> {dest}{f':{port}' if port is not None else ''}"
            f" / {alert.get('protocol', '?')}",
        ),
        ("Signature", str(alert.get("signature", "") or "-")),
        ("MITRE", str(alert.get("mitre_technique") or "not mapped")),
    ]


def render(
    *,
    to: str,
    event_type: str,
    alerts: list[dict[str, Any]],
    total: int,
    window_minutes: float,
    dashboard_url: str,
    digest_max: int,
) -> Envelope:
    """One email for one dispatch window.

    `total` is how many alerts the window covered; `alerts` is what is being
    listed, which is fewer once the digest cap bites. The two are reported
    separately rather than collapsed, so the email never implies it is showing
    everything it counted.
    """
    top = alerts[0] if alerts else {}
    severity = str(top.get("severity", "unknown")).upper()
    whole = window_minutes == int(window_minutes)
    minutes = int(window_minutes) if whole else round(window_minutes, 1)

    if total == 1:
        attack = top.get("attack_type", "alert")
        subject = f"[Flare] {severity} - {attack} {top.get('id', '')}".strip()
        headline = f"1 {severity.lower()} alert"
    else:
        subject = f"[Flare] {total} alerts in the last {minutes} minutes"
        headline = f"{total} alerts in the last {minutes} minutes"

    shown = alerts[:digest_max]
    hidden = total - len(shown)

    text_parts = [headline, "", *[_line(a) for a in shown]]
    if hidden > 0:
        text_parts.append(f"... and {hidden} more")
    if total == 1 and top:
        text_parts += ["", *[f"{label}: {value}" for label, value in _detail_rows(top)]]
        explanation = top.get("explanation")
        if explanation:
            text_parts += ["", str(explanation)]
    text_parts += [
        "",
        f"Open the dashboard: {dashboard_url}",
        "",
        f"Sent because you subscribed to {event_type} and were not watching the "
        "live feed. Turn this off under Notifications in the dashboard.",
    ]

    rows = "".join(
        f"<tr><td style=\"padding:4px 12px 4px 0;font-family:monospace;\">"
        f"{escape(_line(a))}</td></tr>"
        for a in shown
    )
    detail = ""
    if total == 1 and top:
        detail = "".join(
            f"<tr><td style=\"padding:2px 12px 2px 0;color:#666;\">{escape(label)}</td>"
            f"<td style=\"padding:2px 0;font-family:monospace;\">{escape(value)}</td></tr>"
            for label, value in _detail_rows(top)
        )
        detail = f"<table style=\"border-collapse:collapse;margin-top:12px;\">{detail}</table>"

    more = f"<p style=\"color:#666;\">... and {hidden} more</p>" if hidden > 0 else ""
    html = (
        "<div style=\"font-family:system-ui,sans-serif;font-size:14px;color:#111;\">"
        f"<h2 style=\"margin:0 0 12px;font-size:16px;\">{escape(headline)}</h2>"
        f"<table style=\"border-collapse:collapse;\">{rows}</table>"
        f"{more}{detail}"
        f"<p style=\"margin-top:16px;\"><a href=\"{escape(dashboard_url)}\">"
        "Open the Flare dashboard</a></p>"
        "<p style=\"color:#666;font-size:12px;\">"
        f"Sent because you subscribed to {escape(event_type)} and were not "
        "watching the live feed. Turn this off under Notifications in the "
        "dashboard.</p></div>"
    )

    return Envelope(to=to, subject=subject, text="\n".join(text_parts), html=html)
