"""Send one real notification email through the configured relay.

PLAN §18 lists email deliverability as a Medium/Medium risk with the
mitigation "test with the real provider EARLY in Phase 5, not the night
before". This is that test. It builds the same envelope the dispatcher builds,
through the same transport, so what lands in the inbox is what a real critical
alert would send — not an approximation of it.

    python -m scripts.send_test_email you@example.com

Reads SMTP_* from the environment / .env exactly like the app does, so a run
that succeeds here is evidence the app's own configuration works. With no
recipient argument it sends to SMTP_FROM.

The alert in the message is clearly labelled as a transport test. Sending a
message that reads as a genuine critical alert to prove the mail path works is
the kind of thing that gets a real incident declared.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from app.config import get_settings
from app.notifications.email import (
    PermanentSendError,
    SmtpTransport,
    TransientSendError,
    render,
)

TEST_ALERT: dict[str, Any] = {
    "id": "ALT-TEST01",
    "severity": "critical",
    "attack_type": "botnet",
    "src_ip": "192.168.10.15",
    "dest_ip": "205.174.165.73",
    "dest_port": 8080,
    "protocol": "TCP",
    "signature": "TRANSPORT TEST - not a real detection",
    "mitre_technique": "T1071.001",
    "explanation": (
        "This message was sent by scripts/send_test_email.py to verify SMTP "
        "delivery and check whether Flare's mail lands in the inbox or the "
        "spam folder. No detection produced it."
    ),
}


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "recipient",
        nargs="?",
        help="Where to send. Defaults to SMTP_FROM.",
    )
    args = parser.parse_args()

    settings = get_settings()
    if not settings.smtp_host or not settings.smtp_from:
        print(
            "SMTP is not configured. Set SMTP_HOST, SMTP_FROM and (for an "
            "authenticated relay) SMTP_USERNAME + SMTP_PASSWORD in "
            "backend/.env, then run this again.",
            file=sys.stderr,
        )
        return 2

    recipient = args.recipient or settings.smtp_from
    envelope = render(
        to=recipient,
        event_type="alert.high_severity",
        alerts=[TEST_ALERT],
        total=1,
        window_minutes=settings.notification_debounce_seconds / 60,
        dashboard_url=f"{settings.dashboard_base_url.rstrip('/')}/dashboard",
        digest_max=settings.notification_digest_max_alerts,
    )

    # I16 — host, port and sender identity. Never the password.
    print(f"host      {settings.smtp_host}:{settings.smtp_port}")
    print(f"tls       start_tls={settings.smtp_start_tls} use_tls={settings.smtp_use_tls}")
    print(f"timeout   {settings.smtp_timeout_seconds}s")
    print(f"from      {settings.smtp_from_name} <{settings.smtp_from}>")
    print(f"to        {recipient}")
    print(f"subject   {envelope.subject}")

    transport = SmtpTransport(settings)
    try:
        await transport.send(envelope)
    except (TransientSendError, PermanentSendError) as exc:
        print(f"\nFAILED: {exc}", file=sys.stderr)
        return 1

    print("\nAccepted by the relay. Now check the recipient's INBOX and SPAM")
    print("folder and record which one it landed in — that is the half of")
    print("deliverability the SMTP response cannot tell you.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
