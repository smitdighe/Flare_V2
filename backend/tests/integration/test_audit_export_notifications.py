"""Audit, export and notification preferences.

CONTRACT §2.3 / §2.5 / §2.8 / §8.6 / §9.7 · PLAN §4.1 / §9 / §17.

Three screens whose backing endpoints all had to exist before the sidebar item
could render anything real.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any

from httpx import AsyncClient

from app.store.models import Alert
from app.store.session import get_sessionmaker
from tests.conftest import auth_header, login, make_user

RULE_BODY: dict[str, Any] = {
    "name": "audited rule",
    "description": "",
    "conditions": {
        "logic": "AND",
        "conditions": [
            {"field": "attack_type", "operator": "equals", "value": "dos"}
        ],
    },
    "actions": [{"type": "set_severity", "value": "high"}],
}

FORMULA = "=cmd|'/c calc'!A1"


async def _token(client: AsyncClient, email: str, role: str = "analyst") -> str:
    await make_user(email, role=role)
    return await login(client, email)


async def _seed_alert(**overrides: Any) -> str:
    base: dict[str, Any] = {
        "id": "ALT-CCC333",
        "timestamp": datetime.now(UTC),
        "source": "cicids_replay",
        "severity": "high",
        "attack_type": "dos",
        "src_ip": "118.25.6.39",
        "dest_ip": "192.168.10.50",
        "dest_port": 80,
        "protocol": "TCP",
        "signature": "Flow to TCP/80 — SYN-heavy",
        "trace": [],
        "tags": [],
        "rule_trace": [],
    }
    base.update(overrides)
    async with get_sessionmaker()() as session:
        session.add(Alert(**base))
        await session.commit()
    return str(base["id"])


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


async def test_a_non_admin_gets_403_so_the_my_logs_fallback_appears(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.3 — the frontend branches on EXACTLY 403.

    200-with-filtered-rows would mean a non-admin never sees the "my logs"
    view: the screen would silently show them the wrong thing and look like it
    worked.
    """
    token = await _token(client, "audit-viewer@example.com", role="viewer")
    response = await client.get("/api/v1/audit/logs", headers=auth_header(token))
    assert response.status_code == 403

    mine = await client.get("/api/v1/audit/logs/me", headers=auth_header(token))
    assert mine.status_code == 200


async def test_state_changing_operations_are_audited(client: AsyncClient) -> None:
    token = await _token(client, "audit-actor@example.com")
    admin = await _token(client, "audit-admin@example.com", role="admin")

    created = (
        await client.post("/api/v1/rules", json=RULE_BODY, headers=auth_header(token))
    ).json()["data"]
    await client.delete(f"/api/v1/rules/{created['id']}", headers=auth_header(token))
    await client.post(
        "/api/v1/notifications/preferences",
        json={
            "channel": "email",
            "event_type": "alert.high_severity",
            "is_enabled": True,
        },
        headers=auth_header(token),
    )
    await _seed_alert()
    await client.get("/api/v1/export/alerts/csv", headers=auth_header(token))

    logs = (
        await client.get(
            "/api/v1/audit/logs?limit=50", headers=auth_header(admin)
        )
    ).json()["data"]["logs"]
    actions = {entry["action"] for entry in logs}

    assert {"rule.create", "rule.delete", "notification.create", "export.alerts"} <= actions


async def test_a_failed_login_is_audited(client: AsyncClient) -> None:
    """PLAN §4.1 names failed logins explicitly."""
    admin = await _token(client, "audit-fail@example.com", role="admin")
    await client.post(
        "/api/v1/auth/login",
        json={"email": "audit-fail@example.com", "password": "wrong-password"},
    )

    logs = (
        await client.get("/api/v1/audit/logs?limit=50", headers=auth_header(admin))
    ).json()["data"]["logs"]
    assert any("login" in entry["action"] and "fail" in entry["action"] for entry in logs)


async def test_total_is_the_post_filter_count(client: AsyncClient) -> None:
    """CONTRACT §9.7 — pagination is Math.ceil(total / 25).

    A pre-filter count produces a page count that does not match the pages.
    """
    admin = await _token(client, "audit-total@example.com", role="admin")
    for _ in range(3):
        created = (
            await client.post(
                "/api/v1/rules", json=RULE_BODY, headers=auth_header(admin)
            )
        ).json()["data"]
        await client.delete(
            f"/api/v1/rules/{created['id']}", headers=auth_header(admin)
        )

    unfiltered = (
        await client.get("/api/v1/audit/logs", headers=auth_header(admin))
    ).json()["data"]
    filtered = (
        await client.get(
            "/api/v1/audit/logs?action=rule.create", headers=auth_header(admin)
        )
    ).json()["data"]

    assert unfiltered["total"] >= 6
    assert filtered["total"] == 3, "the count follows the filter"
    assert filtered["total"] < unfiltered["total"]
    assert all(entry["action"] == "rule.create" for entry in filtered["logs"])

    by_resource = (
        await client.get(
            "/api/v1/audit/logs?resource_type=rule", headers=auth_header(admin)
        )
    ).json()["data"]
    assert by_resource["total"] == 6


async def test_my_logs_is_scoped_to_the_caller(client: AsyncClient) -> None:
    first = await _token(client, "audit-mine-a@example.com")
    second = await _token(client, "audit-mine-b@example.com")
    await client.post("/api/v1/rules", json=RULE_BODY, headers=auth_header(first))

    mine = (
        await client.get("/api/v1/audit/logs/me", headers=auth_header(second))
    ).json()["data"]
    theirs = (
        await client.get("/api/v1/audit/logs/me", headers=auth_header(first))
    ).json()["data"]

    # The second user has their own login row; what they must NOT have is the
    # first user's rule creation.
    assert "rule.create" not in {entry["action"] for entry in mine["logs"]}
    assert "rule.create" in {entry["action"] for entry in theirs["logs"]}


async def test_created_at_is_iso_8601_the_frontend_can_slice(
    client: AsyncClient,
) -> None:
    """Rendered as created_at.replace('T',' ').slice(0,19)."""
    admin = await _token(client, "audit-iso@example.com", role="admin")
    await client.post("/api/v1/rules", json=RULE_BODY, headers=auth_header(admin))

    logs = (
        await client.get("/api/v1/audit/logs", headers=auth_header(admin))
    ).json()["data"]["logs"]
    assert logs[0]["created_at"][10] == "T"


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


async def test_csv_export_escapes_a_formula_injection_payload(
    client: AsyncClient,
) -> None:
    """PLAN §9. The signature is attacker-influenced text.

    Unescaped, opening this export runs the payload on the analyst's
    workstation — the export we handed them is the delivery mechanism.
    """
    token = await _token(client, "export-csv@example.com")
    await _seed_alert(signature=FORMULA)

    response = await client.get(
        "/api/v1/export/alerts/csv", headers=auth_header(token)
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "flare_alerts.csv" in response.headers["content-disposition"]

    text = response.content.decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["signature"] == f"'{FORMULA}"
    assert rows[0]["signature"].startswith("'"), "neutralised, not deleted"


async def test_csv_export_emits_headers_on_an_empty_set(client: AsyncClient) -> None:
    """A zero-byte file is indistinguishable from a failed download, and the
    frozen frontend swallows export errors to console.error."""
    token = await _token(client, "export-empty@example.com")
    response = await client.get(
        "/api/v1/export/alerts/csv?severity=critical", headers=auth_header(token)
    )
    text = response.content.decode("utf-8-sig")
    assert text.splitlines()[0].startswith("id,timestamp,source,severity")
    assert len(text.splitlines()) == 1


async def test_the_export_applies_the_same_filters_as_the_list(
    client: AsyncClient,
) -> None:
    token = await _token(client, "export-filter@example.com")
    await _seed_alert(id="ALT-HIG001", severity="high")
    await _seed_alert(id="ALT-LOW001", severity="low", attack_type="benign")

    response = await client.get(
        "/api/v1/export/alerts/csv?severity=high", headers=auth_header(token)
    )
    rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert [row["id"] for row in rows] == ["ALT-HIG001"]
    assert response.headers["x-flare-export-rows"] == "1"


async def test_pdf_export_is_a_real_pdf(client: AsyncClient) -> None:
    token = await _token(client, "export-pdf@example.com")
    await _seed_alert()
    response = await client.get(
        "/api/v1/export/alerts/pdf", headers=auth_header(token)
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")


async def test_an_unknown_format_is_rejected(client: AsyncClient) -> None:
    token = await _token(client, "export-format@example.com")
    response = await client.get(
        "/api/v1/export/alerts/xlsx", headers=auth_header(token)
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# notifications
# ---------------------------------------------------------------------------


async def test_preferences_list_is_raw(client: AsyncClient) -> None:
    token = await _token(client, "pref-list@example.com")
    body = (
        await client.get(
            "/api/v1/notifications/preferences", headers=auth_header(token)
        )
    ).json()
    assert "ok" not in body
    assert body == {"preferences": []}


async def test_post_upserts_rather_than_duplicating(client: AsyncClient) -> None:
    """CONTRACT §2.8 — both Add and the toggle POST to the same URL.

    A plain insert would create a duplicate row on every toggle instead of
    flipping the existing one.
    """
    token = await _token(client, "pref-upsert@example.com")
    payload = {
        "channel": "email",
        "event_type": "alert.high_severity",
        "is_enabled": True,
    }
    first = await client.post(
        "/api/v1/notifications/preferences", json=payload, headers=auth_header(token)
    )
    second = await client.post(
        "/api/v1/notifications/preferences",
        json={**payload, "is_enabled": False},
        headers=auth_header(token),
    )

    assert first.json()["data"]["id"] == second.json()["data"]["id"], "same row"
    assert second.json()["data"]["is_enabled"] is False

    listed = (
        await client.get(
            "/api/v1/notifications/preferences", headers=auth_header(token)
        )
    ).json()["preferences"]
    assert len(listed) == 1


async def test_slack_is_refused_with_a_reason_the_ui_renders(
    client: AsyncClient,
) -> None:
    """CONTRACT §8.6 / PLAN §17.

    The frozen dropdown offers Slack as an equal choice with no disabled state.
    Accepting the row means a judge creates a Slack preference and watches
    nothing happen — the exact failure §17 exists to pre-empt.
    """
    token = await _token(client, "pref-slack@example.com")
    response = await client.post(
        "/api/v1/notifications/preferences",
        json={"channel": "slack", "event_type": "rule.matched", "is_enabled": True},
        headers=auth_header(token),
    )
    assert response.status_code == 400
    assert "not wired in this build" in response.json()["detail"]

    listed = (
        await client.get(
            "/api/v1/notifications/preferences", headers=auth_header(token)
        )
    ).json()["preferences"]
    assert listed == [], "a refused preference is not stored"


async def test_channel_is_never_null(client: AsyncClient) -> None:
    """WorkspacePanel.jsx:1085 renders it with .toUpperCase() and no guard."""
    token = await _token(client, "pref-null@example.com")
    await client.post(
        "/api/v1/notifications/preferences",
        json={
            "channel": "email",
            "event_type": "export.ready",
            "is_enabled": True,
        },
        headers=auth_header(token),
    )
    listed = (
        await client.get(
            "/api/v1/notifications/preferences", headers=auth_header(token)
        )
    ).json()["preferences"]
    assert listed[0]["channel"] == "email"


async def test_another_users_preference_cannot_be_deleted(
    client: AsyncClient,
) -> None:
    owner = await _token(client, "pref-owner@example.com")
    intruder = await _token(client, "pref-intruder@example.com")
    created = (
        await client.post(
            "/api/v1/notifications/preferences",
            json={
                "channel": "email",
                "event_type": "rule.matched",
                "is_enabled": True,
            },
            headers=auth_header(owner),
        )
    ).json()["data"]

    response = await client.delete(
        f"/api/v1/notifications/preferences/{created['id']}",
        headers=auth_header(intruder),
    )
    assert response.status_code == 404

    still = (
        await client.get(
            "/api/v1/notifications/preferences", headers=auth_header(owner)
        )
    ).json()["preferences"]
    assert len(still) == 1
