"""Phase 5 end to end — transport, presence over the real socket, the log API.

The unit suite drives the dispatcher directly. This one exercises the parts
that only exist once the app is assembled: the SMTP call's arguments, the
WebSocket registering presence in the registry the dispatcher reads, and the
receipt endpoint an operator uses to check any of it happened.
"""

import asyncio
from typing import Any

import pytest
from httpx import AsyncClient
from starlette.testclient import TestClient

from app.config import get_settings
from app.notifications.email import (
    Envelope,
    PermanentSendError,
    SmtpTransport,
    TransientSendError,
    render,
)
from app.notifications.presence import get_presence
from app.store.models import NotificationLog, NotificationPreference
from app.store.session import get_sessionmaker
from tests.conftest import auth_header, login, make_user

ENVELOPE = Envelope(
    to="analyst@example.com",
    subject="[Flare] CRITICAL - botnet ALT-000001",
    text="body",
    html="<p>body</p>",
)


def smtp_settings(**overrides: Any):
    return get_settings().model_copy(
        update={
            "notifications_enabled": True,
            "smtp_host": "smtp.example.test",
            "smtp_from": "flare@example.com",
            **overrides,
        }
    )


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------


async def test_smtp_send_carries_the_configured_timeout(monkeypatch):
    """PLAN §8.3 — the defect being fixed.

    The prior build called blocking `smtplib.SMTP()` with no timeout, so a host
    that accepted the connection and then answered nothing held a worker
    forever. The claim "with a timeout" is only true if the value reaches the
    call, so this asserts the argument rather than the intent.
    """
    captured: dict[str, Any] = {}

    async def fake_send(message, **kwargs):
        captured.update(kwargs)
        captured["message"] = message

    monkeypatch.setattr("aiosmtplib.send", fake_send)
    transport = SmtpTransport(smtp_settings(smtp_timeout_seconds=7.5))

    await transport.send(ENVELOPE)

    assert captured["timeout"] == 7.5
    assert captured["hostname"] == "smtp.example.test"
    assert captured["port"] == 587
    assert captured["start_tls"] is True
    assert captured["use_tls"] is False


async def test_smtp_message_is_multipart_text_and_html():
    transport = SmtpTransport(smtp_settings(smtp_from_name="Flare SOC"))
    message = transport.build(ENVELOPE)

    assert message["To"] == "analyst@example.com"
    assert message["From"] == "Flare SOC <flare@example.com>"
    assert message.is_multipart()
    subtypes = {part.get_content_subtype() for part in message.iter_parts()}
    assert subtypes == {"plain", "html"}


@pytest.mark.parametrize(
    ("code", "expected"),
    [(451, TransientSendError), (550, PermanentSendError)],
)
async def test_smtp_response_codes_split_transient_from_permanent(
    monkeypatch, code: int, expected: type[Exception]
):
    import aiosmtplib

    async def fake_send(message, **kwargs):
        raise aiosmtplib.SMTPResponseException(code, "nope")

    monkeypatch.setattr("aiosmtplib.send", fake_send)
    transport = SmtpTransport(smtp_settings())

    with pytest.raises(expected):
        await transport.send(ENVELOPE)


async def test_a_timeout_is_transient(monkeypatch):
    async def fake_send(message, **kwargs):
        raise TimeoutError("no answer")

    monkeypatch.setattr("aiosmtplib.send", fake_send)
    transport = SmtpTransport(smtp_settings())

    with pytest.raises(TransientSendError):
        await transport.send(ENVELOPE)


def test_transport_refuses_to_build_without_credentials():
    with pytest.raises(ValueError, match="smtp_host"):
        SmtpTransport(get_settings().model_copy(update={"smtp_host": None}))


def test_notifications_enabled_without_credentials_fails_closed():
    """PLAN §8.4 — the feature refuses to start rather than silently not send."""
    with pytest.raises(ValueError, match="fails closed"):
        get_settings().model_copy(
            update={"notifications_enabled": True}
        ).model_validate(
            {
                **get_settings().model_dump(),
                "notifications_enabled": True,
                "smtp_host": None,
                "smtp_from": None,
            }
        )


def test_unknown_is_rejected_as_a_trigger_severity():
    """PLAN D27 / Q10 — not merely absent from the default, refused outright."""
    with pytest.raises(ValueError, match="unknown"):
        type(get_settings()).model_validate(
            {**get_settings().model_dump(), "notify_severities": ["critical", "unknown"]}
        )


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------


def test_the_email_carries_the_fields_plan_84_lists():
    envelope = render(
        to="analyst@example.com",
        event_type="alert.high_severity",
        alerts=[
            {
                "id": "ALT-00ABCD",
                "severity": "critical",
                "attack_type": "botnet",
                "src_ip": "192.168.10.15",
                "dest_ip": "205.174.165.73",
                "dest_port": 8080,
                "protocol": "TCP",
                "signature": "Botnet C2 beacon",
                "mitre_technique": "T1071.001",
            }
        ],
        total=1,
        window_minutes=5,
        dashboard_url="http://localhost:5174/dashboard",
        digest_max=10,
    )

    for needle in (
        "ALT-00ABCD",
        "CRITICAL",
        "botnet",
        "192.168.10.15",
        "205.174.165.73",
        "Botnet C2 beacon",
        "T1071.001",
        "http://localhost:5174/dashboard",
    ):
        assert needle in envelope.text, needle
    assert "http://localhost:5174/dashboard" in envelope.html


def test_the_email_has_no_external_asset_and_no_tracking_pixel():
    envelope = render(
        to="a@b.test",
        event_type="alert.high_severity",
        alerts=[{"id": "ALT-1", "severity": "high"}],
        total=1,
        window_minutes=5,
        dashboard_url="http://localhost:5174/dashboard",
        digest_max=10,
    )

    assert "<img" not in envelope.html
    assert "<script" not in envelope.html
    # One link, to the dashboard, and nothing else fetched on open.
    assert envelope.html.count("http") == 1


def test_an_attacker_controlled_signature_is_escaped():
    """PLAN §9 — a signature is attacker-influenced by construction."""
    envelope = render(
        to="a@b.test",
        event_type="alert.high_severity",
        alerts=[
            {
                "id": "ALT-1",
                "severity": "high",
                "attack_type": "<script>alert(1)</script>",
                "signature": "<img src=x onerror=alert(1)>",
            }
        ],
        total=1,
        window_minutes=5,
        dashboard_url="http://localhost:5174/dashboard",
        digest_max=10,
    )

    assert "<script>" not in envelope.html
    assert "<img src=x" not in envelope.html
    assert "&lt;script&gt;" in envelope.html


# ---------------------------------------------------------------------------
# presence over the real socket
# ---------------------------------------------------------------------------


def _ws_client() -> TestClient:
    from app.main import create_app

    return TestClient(create_app())


async def test_the_websocket_registers_and_drops_presence(client: AsyncClient):
    user_id = await make_user("ws@example.com")
    token = await login(client, "ws@example.com")
    presence = get_presence()

    assert presence.is_watching(user_id) is False

    with _ws_client() as test_client:
        with test_client.websocket_connect("/api/v1/ws/stream") as socket:
            socket.send_json({"type": "auth", "token": token})
            socket.send_json({"type": "presence", "state": "active"})
            for _ in range(100):
                if presence.is_watching(user_id):
                    break
                await asyncio.sleep(0.01)
            assert presence.is_watching(user_id) is True

            socket.send_json({"type": "presence", "state": "backgrounded"})
            for _ in range(100):
                if not presence.is_watching(user_id):
                    break
                await asyncio.sleep(0.01)
            assert presence.is_watching(user_id) is False

    # Socket closed: zero connections, and the user is away.
    for _ in range(100):
        if presence.snapshot(user_id)["connection_count"] == 0:
            break
        await asyncio.sleep(0.01)
    assert presence.snapshot(user_id)["connection_count"] == 0


# ---------------------------------------------------------------------------
# the receipt endpoint
# ---------------------------------------------------------------------------


async def seed_log(user_id: int, outcome: str, alert_id: str) -> None:
    async with get_sessionmaker()() as session:
        session.add(
            NotificationLog(
                user_id=user_id,
                channel="email",
                event_type="alert.high_severity",
                outcome=outcome,
                reason="because",
                alert_id=alert_id,
                severity="critical",
                rollup_count=1,
                recipient="x@example.com",
                attempts=1,
            )
        )
        await session.commit()


async def test_log_endpoint_returns_the_owners_rows_only(client: AsyncClient):
    mine = await make_user("mine@example.com")
    theirs = await make_user("theirs@example.com")
    await seed_log(mine, "sent", "ALT-000001")
    await seed_log(mine, "suppressed", "ALT-000002")
    await seed_log(theirs, "sent", "ALT-000003")

    token = await login(client, "mine@example.com")
    response = await client.get("/api/v1/notifications/log", headers=auth_header(token))

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    entries = body["data"]["entries"]
    assert body["data"]["total"] == 2
    assert {entry["alert_id"] for entry in entries} == {"ALT-000001", "ALT-000002"}
    assert {entry["outcome"] for entry in entries} == {"sent", "suppressed"}


async def test_log_endpoint_filters_by_outcome(client: AsyncClient):
    user_id = await make_user("filter@example.com")
    await seed_log(user_id, "sent", "ALT-000001")
    await seed_log(user_id, "suppressed", "ALT-000002")

    token = await login(client, "filter@example.com")
    response = await client.get(
        "/api/v1/notifications/log?outcome=suppressed", headers=auth_header(token)
    )

    assert response.status_code == 200
    entries = response.json()["data"]["entries"]
    assert len(entries) == 1
    assert entries[0]["outcome"] == "suppressed"


async def test_log_endpoint_rejects_an_unknown_outcome(client: AsyncClient):
    await make_user("bad@example.com")
    token = await login(client, "bad@example.com")

    response = await client.get(
        "/api/v1/notifications/log?outcome=maybe", headers=auth_header(token)
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


async def test_log_endpoint_requires_auth(client: AsyncClient):
    response = await client.get("/api/v1/notifications/log")
    assert response.status_code == 401


async def test_preference_toggle_still_upserts(client: AsyncClient):
    """Phase 4 behaviour, re-asserted because Phase 5 now reads these rows."""
    await make_user("pref@example.com")
    token = await login(client, "pref@example.com")
    body = {
        "channel": "email",
        "event_type": "alert.high_severity",
        "is_enabled": True,
    }

    first = await client.post(
        "/api/v1/notifications/preferences", json=body, headers=auth_header(token)
    )
    second = await client.post(
        "/api/v1/notifications/preferences",
        json={**body, "is_enabled": False},
        headers=auth_header(token),
    )

    assert first.status_code == 200
    assert second.status_code == 200
    async with get_sessionmaker()() as session:
        from sqlalchemy import select

        rows = list(
            (await session.execute(select(NotificationPreference))).scalars().all()
        )
    assert len(rows) == 1
    assert rows[0].is_enabled is False
