"""Send a real notification email through the configured relay.

PLAN §18 lists email deliverability as a Medium/Medium risk with the
mitigation "test with the real provider EARLY in Phase 5, not the night
before". This is that test. It builds the same envelope the dispatcher builds,
through the same transport, so what lands in the inbox is what a real alert
would send — not an approximation of it.

    python -m scripts.send_test_email you@example.com
    python -m scripts.send_test_email you@example.com --variant high
    python -m scripts.send_test_email you@example.com --variant rollup
    python -m scripts.send_test_email you@example.com --variant digest
    python -m scripts.send_test_email you@example.com --variant all

`--variant` selects which shape of the card to send: `critical` / `high` are
the single-alert card at each severity, `rollup` is a small multi-alert digest,
`digest` is a large one that exercises the "and N more" cap. `all` sends one of
each, in order, so a redesign can be eyeballed in an inbox in a single run.

Reads SMTP_* from the environment / .env exactly like the app does, so a run
that succeeds here is evidence the app's own configuration works. With no
recipient argument it sends to SMTP_FROM.

Every alert in these messages is clearly labelled as a transport test in its
signature. Sending a message that reads as a genuine critical detection to
prove the mail path works is the kind of thing that gets a real incident
declared.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from app.config import get_settings
from app.notifications.email import (
    Envelope,
    PermanentSendError,
    SmtpTransport,
    TransientSendError,
    render,
)

_TEST_SIGNATURE = "TRANSPORT TEST - not a real detection"

_CRITICAL: dict[str, Any] = {
    "id": "ALT-TEST01",
    "severity": "critical",
    "attack_type": "botnet",
    "src_ip": "192.168.10.15",
    "dest_ip": "205.174.165.73",
    "dest_port": 8080,
    "protocol": "TCP",
    "signature": _TEST_SIGNATURE,
    "mitre_technique": "T1071.001",
    "confidence": 0.87,
    "trace": [
        {"node": "classify", "provider": "groq", "model_version": "openai/gpt-oss-120b"}
    ],
    "explanation": (
        "This message was sent by scripts/send_test_email.py to verify SMTP "
        "delivery and check whether Flare's mail lands in the inbox or the "
        "spam folder. No detection produced it. The prose block is here so the "
        "redesigned analyst-note panel can be judged at a realistic length."
    ),
}

_HIGH: dict[str, Any] = {
    "id": "ALT-TEST02",
    "severity": "high",
    "attack_type": "port_scan",
    "src_ip": "172.16.0.1",
    "dest_ip": "192.168.10.50",
    "dest_port": 443,
    "protocol": "TCP",
    "signature": _TEST_SIGNATURE,
    "mitre_technique": "T1046",
    "confidence": 0.994,
    "trace": [{"node": "classify", "provider": "lightgbm", "model_version": "20260904"}],
    "explanation": (
        "Transport test for the HIGH-severity single-alert card. No detection "
        "produced this. The amber pill and the amber CTA should both read "
        "clearly against the dark card."
    ),
}


def _series(count: int) -> list[dict[str, Any]]:
    """`count` distinct transport-test alerts for the rollup / digest shapes."""
    kinds = [
        ("critical", "ddos", 80),
        ("high", "dos", 80),
        ("high", "web_attack", 443),
        ("high", "port_scan", 0),
    ]
    out: list[dict[str, Any]] = []
    for index in range(count):
        severity, attack, port = kinds[index % len(kinds)]
        out.append(
            {
                "id": f"ALT-TEST{index + 10:02d}",
                "severity": severity,
                "attack_type": attack,
                "src_ip": "172.16.0.1",
                "dest_ip": "192.168.10.50",
                "dest_port": port,
                "protocol": "TCP",
                "signature": _TEST_SIGNATURE,
                "mitre_technique": "T1498",
            }
        )
    return out


def _build(variant: str, *, to: str, settings: Any) -> Envelope:
    common = {
        "to": to,
        "event_type": "alert.high_severity",
        "window_minutes": settings.notification_debounce_seconds / 60,
        "dashboard_url": f"{settings.dashboard_base_url.rstrip('/')}/dashboard",
        "digest_max": settings.notification_digest_max_alerts,
    }
    if variant == "critical":
        return render(alerts=[_CRITICAL], total=1, **common)
    if variant == "high":
        return render(alerts=[_HIGH], total=1, **common)
    if variant == "rollup":
        alerts = _series(3)
        return render(alerts=alerts, total=len(alerts), **common)
    if variant == "digest":
        # Two past the digest_max so the "and N more" line is exercised.
        alerts = _series(settings.notification_digest_max_alerts + 2)
        return render(alerts=alerts, total=len(alerts), **common)
    raise ValueError(f"unknown variant {variant!r}")


_VARIANTS = ("critical", "high", "rollup", "digest")


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "recipient",
        nargs="?",
        help="Where to send. Defaults to SMTP_FROM.",
    )
    parser.add_argument(
        "--variant",
        choices=(*_VARIANTS, "all"),
        default="critical",
        help="Which card shape to send (default: critical). 'all' sends one of each.",
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
    variants = list(_VARIANTS) if args.variant == "all" else [args.variant]

    # I16 — host, port and sender identity. Never the password.
    print(f"host      {settings.smtp_host}:{settings.smtp_port}")
    print(f"tls       start_tls={settings.smtp_start_tls} use_tls={settings.smtp_use_tls}")
    print(f"timeout   {settings.smtp_timeout_seconds}s")
    print(f"from      {settings.smtp_from_name} <{settings.smtp_from}>")
    print(f"to        {recipient}")

    transport = SmtpTransport(settings)
    failures = 0
    for variant in variants:
        envelope = _build(variant, to=recipient, settings=settings)
        print(f"\n[{variant}] subject   {envelope.subject}")
        try:
            await transport.send(envelope)
        except (TransientSendError, PermanentSendError) as exc:
            print(f"[{variant}] FAILED: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[{variant}] accepted by the relay")

    if failures:
        return 1

    print(
        "\nAll accepted by the relay. Now check the recipient's INBOX and SPAM "
        "folder and record which one each landed in — that is the half of "
        "deliverability the SMTP response cannot tell you."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
