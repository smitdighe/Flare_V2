"""Field-by-field contract tests. CONTRACT §1.3 / §2 / PLAN §12.

**WHAT THIS FILE IS FOR.** The frontend is frozen. Every field named in
CONTRACT §2 is read by a line of JSX that cannot be changed to accommodate a
rename, so an endpoint that returns `dst_ip` where the screen reads `dest_ip`
does not fail — it renders `undefined`, silently, forever. Status codes and key
presence do not catch that class of defect; the assertions here check the exact
key, at the exact nesting depth, with a value of the right type and shape.

`test_contract.py` next door asserts the ENVELOPE — which operations are wrapped
and which are the pinned raw exceptions. This file asserts what is INSIDE, for
every operation the frozen frontend consumes, plus the nine no-consumer
endpoints the API and the README depend on.

Two rules followed throughout, both from PLAN §12:

  * assert VALUES and TYPES, not merely that a key exists;
  * no `assert a or b` where both branches are plausible — where a field is
    legitimately nullable, the test says which condition makes it null and
    asserts THAT.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient

from tests.conftest import auth_header, login, make_user

pytestmark = pytest.mark.contract

ISO_T_INDEX = 10


def assert_iso8601(value: Any, field: str) -> None:
    """CONTRACT §2.2 / §2.3 — the frontend slices these by INDEX.

    `time.slice(11,16)` and `created_at.replace('T',' ').slice(0,19)` both assume
    a literal `T` at index 10. A format the browser would still parse but that
    puts the separator elsewhere renders garbage rather than failing.
    """
    assert isinstance(value, str), f"{field} must be a string, got {type(value)}"
    assert len(value) > 19, f"{field} is too short to slice: {value!r}"
    assert value[ISO_T_INDEX] == "T", (
        f"{field} must be ISO-8601 with T at index 10 — the frozen frontend "
        f"slices it positionally: {value!r}"
    )


SPLITS = __import__("pathlib").Path(__file__).resolve().parents[2] / "data" / "splits"
REPLAY_CSV = SPLITS / "replay.csv"

needs_data = pytest.mark.skipif(
    not REPLAY_CSV.exists(),
    reason="partitions not built — run scripts.build_partitions",
)


async def seed_alerts(count: int = 3) -> list[str]:
    """Persist `count` REAL replay rows through the production parser.

    Not a hand-built dict: the shape a contract test asserts has to be the shape
    the pipeline actually produces, or the test is checking a fixture rather
    than the system.
    """
    import csv
    from datetime import UTC, datetime, timedelta

    from app.ingestion.normalize import parse_cicids_row
    from app.store.repositories import upsert_alert
    from app.store.session import get_sessionmaker

    with REPLAY_CSV.open(encoding="utf-8", newline="") as handle:
        rows = [r for _, r in zip(range(count), csv.DictReader(handle), strict=False)]

    base = datetime.now(UTC) - timedelta(seconds=count)
    ids: list[str] = []
    async with get_sessionmaker()() as session:
        for index, row in enumerate(rows):
            alert = parse_cicids_row(row, timestamp=base + timedelta(seconds=index))
            await upsert_alert(session, alert)
            ids.append(alert.id)
        await session.commit()
    return ids


async def analyst(client: AsyncClient, email: str) -> str:
    await make_user(email, role="analyst")
    return await login(client, email)


async def admin(client: AsyncClient, email: str) -> str:
    await make_user(email, role="admin")
    return await login(client, email)


# ---------------------------------------------------------------------------
# §2.1 auth — operations 1-6
# ---------------------------------------------------------------------------


async def test_op1_login_returns_raw_tokens_and_a_user_object(
    client: AsyncClient,
) -> None:
    """AuthContext.jsx:119 reads `data.access_token` off the RAW body."""
    await make_user("c-login@example.com", name="Contract User")

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "c-login@example.com", "password": "Password123!"},
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert "ok" not in body, "pinned exception #1 — wrapping breaks the read"
    assert isinstance(body["access_token"], str) and body["access_token"].count(".") == 2
    assert isinstance(body["refresh_token"], str) and body["refresh_token"].count(".") == 2
    assert body["access_token"] != body["refresh_token"]

    user = body["user"]
    # SettingsPage.jsx:15-16 renders exactly these two.
    assert user["name"] == "Contract User"
    assert user["email"] == "c-login@example.com"
    assert "password" not in user and "password_hash" not in user


async def test_op2_register_returns_the_same_shape_as_login(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "c-reg@example.com",
            "name": "New Analyst",
            "password": "Password123!",
        },
    )
    assert response.status_code in (200, 201), response.text
    body = response.json()

    assert "ok" not in body
    assert set(("access_token", "refresh_token", "user")) <= set(body)
    assert body["user"]["email"] == "c-reg@example.com"
    assert body["user"]["role"] == "viewer", (
        "CONTRACT §2.1 — the register form's role selector is decorative and the "
        "default is viewer; honouring a client-supplied role would be PLAN §9's "
        "one-call self-promotion"
    )


async def test_op2_register_ignores_a_client_supplied_role(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "c-escalate@example.com",
            "name": "Sneaky",
            "password": "Password123!",
            "role": "admin",
        },
    )
    if response.status_code in (200, 201):
        assert response.json()["user"]["role"] == "viewer"
    else:
        assert response.status_code == 422, response.text


async def test_op3_refresh_returns_both_tokens_raw(client: AsyncClient) -> None:
    await make_user("c-refresh@example.com")
    login_body = (
        await client.post(
            "/api/v1/auth/login",
            json={"email": "c-refresh@example.com", "password": "Password123!"},
        )
    ).json()

    response = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": login_body["refresh_token"]}
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert "ok" not in body, "pinned exception #3"
    assert isinstance(body["access_token"], str)
    assert isinstance(body["refresh_token"], str)


async def test_op4_me_is_the_whole_body(client: AsyncClient) -> None:
    """AuthContext.jsx:85 does `setUser(data)` on the whole response."""
    await make_user("c-me@example.com", name="Me User")
    token = await login(client, "c-me@example.com")

    body = (
        await client.get("/api/v1/auth/me", headers=auth_header(token))
    ).json()

    assert "ok" not in body and "data" not in body, "pinned exception #4"
    assert body["name"] == "Me User"
    assert body["email"] == "c-me@example.com"
    assert body["role"] == "viewer"
    assert "password_hash" not in body


# ---------------------------------------------------------------------------
# §2.2 health and stats — operations 7-8
# ---------------------------------------------------------------------------


async def test_op7_health_services_carry_every_rendered_field(
    client: AsyncClient,
) -> None:
    """WorkspacePanel.jsx:18 reads `.name`, `.status`, `.latency_ms`, `.message`."""
    token = await analyst(client, "c-health@example.com")
    body = (await client.get("/api/v1/health", headers=auth_header(token))).json()

    assert set(body) == {"ok", "data", "meta"}
    services = body["data"]["services"]
    assert isinstance(services, list) and services

    for service in services:
        assert isinstance(service["name"], str) and service["name"]
        # Branched three ways at WorkspacePanel.jsx:85 — 'ok', 'rate_limited',
        # anything else red. A status outside this set renders red, which is
        # survivable, but a MISSING status throws on `.toUpperCase()`.
        assert service["status"] in ("ok", "rate_limited", "error", "unknown")
        assert "latency_ms" in service
        assert "message" in service
        if service["status"] == "ok":
            assert isinstance(service["latency_ms"], (int, float))
            assert service["latency_ms"] > 0, "an ok service has a real measurement"
        if service["status"] == "unknown":
            assert service["latency_ms"] is None, (
                "never probed means no latency; WorkspacePanel.jsx:103 renders "
                "the status text when latency_ms is null"
            )


async def test_op8_stats_timeline_is_sliceable_and_unique(
    client: AsyncClient,
) -> None:
    """`time.slice(11,16)` for HH:MM, and `time` is also the React key."""
    token = await analyst(client, "c-stats@example.com")
    body = (await client.get("/api/v1/stats", headers=auth_header(token))).json()
    data = body["data"]

    timeline = data["timeline"]
    assert isinstance(timeline, list)
    for bucket in timeline:
        assert_iso8601(bucket["time"], "timeline[].time")
        assert isinstance(bucket["count"], int)
        assert bucket["count"] >= 0

    times = [b["time"] for b in timeline]
    assert len(times) == len(set(times)), (
        "timeline[].time is the React key — duplicates silently drop rows"
    )

    assert isinstance(data["alert_velocity"], (int, float))
    assert data["alert_velocity"] >= 0


# ---------------------------------------------------------------------------
# §2.3 audit — operations 9-10
# ---------------------------------------------------------------------------


async def test_op9_audit_logs_shape_and_the_403_that_reveals_op10(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.3 — a non-admin must get 403, NOT 200-with-filtered-rows.

    The frontend only ever calls `/audit/logs/me` after `/audit/logs` returns
    403. A permissive 200 means the "my logs" view is unreachable — and it would
    also be the privilege hole PLAN §9 names.
    """
    viewer_token = await analyst(client, "c-audit-viewer@example.com")
    denied = await client.get("/api/v1/audit/logs", headers=auth_header(viewer_token))
    assert denied.status_code == 403, (
        "a non-admin getting 200 here hides op #10 from the UI entirely"
    )

    admin_token = await admin(client, "c-audit-admin@example.com")
    body = (
        await client.get(
            "/api/v1/audit/logs?limit=25&offset=0", headers=auth_header(admin_token)
        )
    ).json()
    data = body["data"]

    assert isinstance(data["total"], int)
    assert isinstance(data["logs"], list)
    for row in data["logs"]:
        assert isinstance(row["id"], int)
        assert isinstance(row["action"], str) and row["action"]
        assert "resource_type" in row
        assert "resource_id" in row
        assert_iso8601(row["created_at"], "logs[].created_at")
        # JSON.stringify(details, null, 2) — any JSON value, including null.
        assert "details" in row


async def test_op10_audit_logs_me_is_reachable_by_a_non_admin(
    client: AsyncClient,
) -> None:
    token = await analyst(client, "c-audit-me@example.com")
    response = await client.get("/api/v1/audit/logs/me", headers=auth_header(token))

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert isinstance(data["logs"], list)
    assert isinstance(data["total"], int)


# ---------------------------------------------------------------------------
# §2.4 evaluation — operation 11
# ---------------------------------------------------------------------------


async def test_op11_eval_renders_every_field_the_screen_reads(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.4 lists thirteen fields with the JSX line that reads each."""
    from app.eval import cache

    if cache.read() is None:
        pytest.skip("no cached eval run on disk")

    token = await analyst(client, "c-eval@example.com")
    data = (
        await client.get("/api/v1/eval", headers=auth_header(token))
    ).json()["data"]

    assert isinstance(data["sample_size"], int) and data["sample_size"] > 0

    for field in (
        "severity_accuracy",
        "attack_type_accuracy",
        "high_severity_precision",
        "high_severity_recall",
        "high_severity_f1",
    ):
        value = data[field]
        assert isinstance(value, (int, float)), f"{field} is not a number"
        assert 0.0 <= value <= 1.0, f"{field}={value} is outside 0-1"

    assert isinstance(data["avg_latency_ms"], (int, float))
    assert data["avg_latency_ms"] > 0, "PLAN I2 — a measured latency, not 0.0"

    # CONTRACT §2.4 — the matrix is 4x4, exactly these labels, in this order.
    matrix = data["confusion_matrix"]
    assert matrix["labels"] == ["critical", "high", "medium", "low"]
    assert len(matrix["matrix"]) == 4
    for row in matrix["matrix"]:
        assert len(row) == 4
        assert all(isinstance(cell, int) for cell in row)
    assert sum(sum(row) for row in matrix["matrix"]) == (
        data["sample_size"] - data["unscored_count"]
    ), "every scored row lands in exactly one cell"

    breakdown = data["attack_type_breakdown"]
    assert isinstance(breakdown, dict) and breakdown
    for name, entry in breakdown.items():
        assert isinstance(name, str)
        assert isinstance(entry["correct"], int)
        assert isinstance(entry["true_count"], int)
        assert entry["true_count"] >= entry["correct"]
        assert 0.0 <= entry["accuracy"] <= 1.0

    # rows[] — the misclassified list. Five fields, all read at :484-486.
    for row in data["rows"]:
        for field in (
            "signature",
            "true_severity",
            "pred_severity",
            "true_attack_type",
            "pred_attack_type",
        ):
            assert isinstance(row[field], str), f"rows[].{field}"

    assert isinstance(data["misclassified_count"], int)
    assert isinstance(data["unscored_count"], int)


async def test_op11_the_header_count_agrees_with_the_client_side_filter(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.4 — the list is recomputed client-side, the count is a field.

    `misclassified_count` and `rows.filter(pred !== true)` are computed in two
    different places, and if their definitions differ the header and the list
    disagree on screen with nothing anywhere reporting it.
    """
    from app.eval import cache

    if cache.read() is None:
        pytest.skip("no cached eval run on disk")

    token = await analyst(client, "c-eval2@example.com")
    data = (
        await client.get("/api/v1/eval", headers=auth_header(token))
    ).json()["data"]

    client_side = [
        row
        for row in data["rows"]
        if row["pred_severity"] != row["true_severity"]
        or row["pred_attack_type"] != row["true_attack_type"]
    ]
    assert len(client_side) == data["misclassified_count"], (
        "WorkspacePanel.jsx:402 recomputes the list with this exact expression; "
        "a different backend definition puts a count on screen that does not "
        "match the rows under it"
    )


# ---------------------------------------------------------------------------
# §2.6 rules — operations 13-16
# ---------------------------------------------------------------------------

RULE_BODY: dict[str, Any] = {
    "name": "Contract rule",
    "description": "",
    "conditions": {
        "logic": "AND",
        "conditions": [
            {"field": "attack_type", "operator": "equals", "value": "port_scan"}
        ],
    },
    "actions": [{"type": "set_severity", "value": "high"}],
}


async def test_op13_rules_list_is_raw_with_the_five_rendered_fields(
    client: AsyncClient,
) -> None:
    """WorkspacePanel.jsx:670 does `.then(d => setRules(d.rules || []))`."""
    token = await analyst(client, "c-rules@example.com")
    await client.post("/api/v1/rules", json=RULE_BODY, headers=auth_header(token))

    body = (await client.get("/api/v1/rules", headers=auth_header(token))).json()

    assert "ok" not in body, (
        "pinned exception #5 — wrapping makes d.rules undefined and the screen "
        "renders 'No rules yet' forever with no error anywhere"
    )
    rule = body["rules"][0]
    assert isinstance(rule["id"], int)
    assert rule["name"] == "Contract rule"
    assert "description" in rule
    assert isinstance(rule["match_count"], int)
    assert isinstance(rule["is_enabled"], bool)


async def test_op14_rule_create_is_enveloped_and_returns_the_resource(
    client: AsyncClient,
) -> None:
    token = await analyst(client, "c-rules2@example.com")
    response = await client.post(
        "/api/v1/rules", json=RULE_BODY, headers=auth_header(token)
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert set(body) == {"ok", "data", "meta"}, "CONTRACT #14 is ENVELOPED"
    assert body["data"]["name"] == "Contract rule"
    assert body["data"]["conditions"]["logic"] == "AND"
    assert body["data"]["actions"] == [{"type": "set_severity", "value": "high"}]


async def test_op14_accepts_every_field_and_operator_the_ui_can_emit(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.6 pins four fields and four operators the form can produce.

    A backend that rejects one of them fails a form the user cannot work around,
    and the error surfaces as raw `e.detail` text in the panel.
    """
    token = await analyst(client, "c-rules3@example.com")

    for field, value in (
        ("severity", "high"),
        ("attack_type", "port_scan"),
        ("src_ip", "192.168.10.15"),
        ("dest_port", "80"),
    ):
        for operator in ("equals", "contains", "not_equals", "greater_than"):
            body = {
                **RULE_BODY,
                "name": f"{field}-{operator}",
                "conditions": {
                    "logic": "AND",
                    "conditions": [
                        {"field": field, "operator": operator, "value": value}
                    ],
                },
            }
            response = await client.post(
                "/api/v1/rules", json=body, headers=auth_header(token)
            )
            assert response.status_code == 201, (
                f"the UI can emit field={field} operator={operator} and the "
                f"backend refused it: {response.text}"
            )


async def test_op14_accepts_n_conditions_even_though_the_ui_sends_one(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.6 — 'the shape is a list, so the backend must accept N'."""
    token = await analyst(client, "c-rules4@example.com")
    body = {
        **RULE_BODY,
        "name": "three conditions",
        "conditions": {
            "logic": "AND",
            "conditions": [
                {"field": "severity", "operator": "equals", "value": "high"},
                {"field": "attack_type", "operator": "not_equals", "value": "benign"},
                {"field": "dest_port", "operator": "greater_than", "value": "1024"},
            ],
        },
    }
    response = await client.post(
        "/api/v1/rules", json=body, headers=auth_header(token)
    )
    assert response.status_code == 201, response.text
    assert len(response.json()["data"]["conditions"]["conditions"]) == 3


@needs_data
async def test_op16_explain_rules_returns_every_rule_evaluated_not_just_fired(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.6 — 'named `matched_rules` but must contain every rule
    evaluated, fired or not'. The non-firing rows are the demo beat.

    A rule that CANNOT match is created on purpose: the frozen drawer renders
    non-firing rules with a "no match" chip and its per-condition trace, so a
    response that only listed the rules that fired would leave the panel empty
    on exactly the alerts an analyst is trying to understand.
    """
    token = await analyst(client, "c-explain@example.com")

    # The endpoint serves the trace recorded AT TRIAGE TIME rather than
    # recomputing against today's rules — deliberately, because the drawer is
    # asking "why does this alert look the way it does", not "what would the
    # current rules say". So the fixture has to be a trace the REAL engine
    # produced, through `trace_to_payload`, exactly as the rules node stores it.
    import csv as csv_mod
    from datetime import UTC, datetime

    from app.ingestion.normalize import parse_cicids_row
    from app.rules.engine import Condition, Rule, RuleEngine
    from app.rules.store import trace_to_payload
    from app.store.repositories import upsert_alert
    from app.store.session import get_sessionmaker

    with REPLAY_CSV.open(encoding="utf-8", newline="") as handle:
        row = next(iter(csv_mod.DictReader(handle)))
    alert = parse_cicids_row(row, timestamp=datetime.now(UTC))

    engine = RuleEngine(
        [
            Rule(
                id="r-never",
                name="never matches",
                conditions=(Condition("dest_port", "eq", 65535),),
                action="set_severity",
                severity="critical",
            )
        ]
    )
    _, traces = engine.apply(
        {
            "severity": alert.severity,
            "attack_type": alert.attack_type,
            "src_ip": alert.src_ip,
            "dest_ip": alert.dest_ip,
            "dest_port": alert.dest_port,
            "signature": alert.signature,
        }
    )
    alert.trace = alert.trace or []
    alert.rule_trace = trace_to_payload(traces)

    async with get_sessionmaker()() as session:
        await upsert_alert(session, alert)
        await session.commit()
    alert_ids = [alert.id]

    response = await client.get(
        f"/api/v1/rules/alerts/{alert_ids[0]}/explain-rules",
        headers=auth_header(token),
    )
    assert response.status_code == 200, response.text

    body = response.json()
    assert "ok" not in body, "pinned exception #6 — the whole body is the state"
    assert isinstance(body["matched_rules"], list)
    assert body["matched_rules"], (
        "a rule was configured and evaluated, so it must appear here even "
        "though it did not fire"
    )

    entry = body["matched_rules"][0]
    assert entry["rule_id"] == "r-never", "the React key"
    assert entry["rule_name"] == "never matches"
    assert entry["fired"] is False, "and the non-firing row is the one under test"
    condition = entry["conditions"][0]
    assert set(("field", "operator", "expected", "actual", "result")) <= set(condition)
    assert condition["field"] == "dest_port"
    assert condition["result"] is False
    # `expected` and `actual` render through String(...), so any JSON scalar is
    # safe — but a MISSING one renders "undefined" in the chip.
    assert condition["expected"] is not None
    assert "actual" in condition


# ---------------------------------------------------------------------------
# §2.5 export — operation 12, the eleventh pinned exception and the only binary
# ---------------------------------------------------------------------------


@needs_data
@pytest.mark.parametrize(
    ("fmt", "media_type", "magic"),
    [("csv", "text/csv", b""), ("pdf", "application/pdf", b"%PDF")],
)
async def test_op12_export_is_a_binary_blob_with_the_download_filename(
    client: AsyncClient, fmt: str, media_type: str, magic: bytes
) -> None:
    """WorkspacePanel.jsx:618 calls `res.blob()` and saves `flare_alerts.{format}`.

    This is the one pinned exception that is not JSON at all, so wrapping it in
    an envelope would not merely break a read — it would hand the browser a JSON
    document named `.pdf`. The filename comes from `Content-Disposition`, and a
    failed export is swallowed to `console.error`, so a wrong content type is
    silent to the user.
    """
    token = await analyst(client, f"c-export-{fmt}@example.com")
    await seed_alerts(3)

    response = await client.get(
        f"/api/v1/export/alerts/{fmt}?limit=500", headers=auth_header(token)
    )

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith(media_type)
    assert (
        f'filename="flare_alerts.{fmt}"' in response.headers["content-disposition"]
    )
    assert response.content, "an empty body downloads as a zero-byte file"
    if magic:
        assert response.content.startswith(magic), (
            f"the body is not actually a {fmt.upper()}"
        )
    # NOT enveloped: the first bytes are the file, not `{"ok":`.
    assert not response.content.lstrip().startswith(b'{"ok"')


@needs_data
async def test_op12_csv_escapes_formula_injection(client: AsyncClient) -> None:
    """PLAN §9 — the export is the real downstream sink for injected content.

    A cell beginning `=`, `+`, `-` or `@` is executed by Excel and Sheets on
    open. The alert fields it lands in are attacker-influenced by construction.
    """
    token = await analyst(client, "c-export-inject@example.com")

    import csv as csv_mod
    from datetime import UTC, datetime

    from app.ingestion.normalize import parse_cicids_row
    from app.store.repositories import upsert_alert
    from app.store.session import get_sessionmaker

    with REPLAY_CSV.open(encoding="utf-8", newline="") as handle:
        row = next(iter(csv_mod.DictReader(handle)))
    alert = parse_cicids_row(row, timestamp=datetime.now(UTC))
    alert.signature = '=cmd|\' /C calc\'!A0'
    async with get_sessionmaker()() as session:
        await upsert_alert(session, alert)
        await session.commit()

    response = await client.get(
        "/api/v1/export/alerts/csv", headers=auth_header(token)
    )
    assert response.status_code == 200
    text = response.content.decode("utf-8", errors="replace")

    for line in text.splitlines():
        for cell in line.split(","):
            stripped = cell.strip().strip('"')
            assert stripped[:1] not in ("=", "+", "-", "@"), (
                f"an unescaped formula cell reached the export: {cell!r}"
            )


# ---------------------------------------------------------------------------
# §2.7 playbooks — operations 17-23
# ---------------------------------------------------------------------------

PLAYBOOK_BODY: dict[str, Any] = {
    "name": "Contract playbook",
    "description": "walk it",
    "alert_type": "ddos",
    "severity_threshold": "high",
    "steps": [
        {"type": "manual", "title": "Confirm", "description": "confirm the flood"},
        {"type": "auto", "title": "Snapshot", "description": "record the alert"},
    ],
}


async def test_op17_playbooks_list_is_raw_with_the_eight_rendered_fields(
    client: AsyncClient,
) -> None:
    token = await analyst(client, "c-pb@example.com")
    await client.post(
        "/api/v1/playbooks", json=PLAYBOOK_BODY, headers=auth_header(token)
    )

    body = (await client.get("/api/v1/playbooks", headers=auth_header(token))).json()

    assert "ok" not in body, "pinned exception #7"
    playbook = body["playbooks"][0]
    assert isinstance(playbook["id"], int)
    assert playbook["name"] == "Contract playbook"
    assert playbook["description"] == "walk it"
    assert playbook["alert_type"] == "ddos"
    assert playbook["severity_threshold"] == "high"
    assert isinstance(playbook["steps"], list) and playbook["steps"]
    assert isinstance(playbook["execution_count"], int)
    assert isinstance(playbook["is_enabled"], bool)
    # CONTRACT §2.7 — `title` is canonical; the render path falls back to
    # `label`, so `title` being present is what stops the fallback firing.
    assert playbook["steps"][0]["title"] == "Confirm"
    assert playbook["steps"][0]["type"] == "manual"


async def test_op18_accepts_free_text_alert_type_and_an_empty_threshold(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.7 — `alert_type` is a free-text input, `""` is legal."""
    token = await analyst(client, "c-pb2@example.com")

    for alert_type, threshold in (("", ""), ("anything at all", "critical")):
        response = await client.post(
            "/api/v1/playbooks",
            json={
                **PLAYBOOK_BODY,
                "name": f"pb-{alert_type or 'blank'}-{threshold or 'blank'}",
                "alert_type": alert_type,
                "severity_threshold": threshold,
            },
            headers=auth_header(token),
        )
        assert response.status_code == 201, (
            f"alert_type={alert_type!r} threshold={threshold!r} refused: "
            f"{response.text}"
        )


async def test_op18_accepts_an_all_empty_playbook_with_no_steps(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.7 — 'an all-empty playbook posts steps: []'."""
    token = await analyst(client, "c-pb3@example.com")
    response = await client.post(
        "/api/v1/playbooks",
        json={**PLAYBOOK_BODY, "name": "empty", "steps": []},
        headers=auth_header(token),
    )
    assert response.status_code == 201, response.text
    assert response.json()["data"]["steps"] == []


async def test_op21_execute_returns_execution_id_raw(client: AsyncClient) -> None:
    """WorkspacePanel.jsx:864 reads `data.execution_id` and immediately GETs #22."""
    token = await analyst(client, "c-pb4@example.com")
    created = await client.post(
        "/api/v1/playbooks", json=PLAYBOOK_BODY, headers=auth_header(token)
    )
    playbook_id = created.json()["data"]["id"]

    response = await client.post(
        f"/api/v1/playbooks/{playbook_id}/execute", headers=auth_header(token)
    )
    assert response.status_code in (200, 201), response.text
    body = response.json()
    assert "ok" not in body, "pinned exception #8"
    assert isinstance(body["execution_id"], int)


async def test_op22_execution_is_the_whole_body_with_index_arrays(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.7 — `completed_steps` is `.includes(i)`, `current_step` is `===`."""
    token = await analyst(client, "c-pb5@example.com")
    created = await client.post(
        "/api/v1/playbooks", json=PLAYBOOK_BODY, headers=auth_header(token)
    )
    playbook_id = created.json()["data"]["id"]
    execution_id = (
        await client.post(
            f"/api/v1/playbooks/{playbook_id}/execute", headers=auth_header(token)
        )
    ).json()["execution_id"]

    body = (
        await client.get(
            f"/api/v1/playbooks/executions/{execution_id}", headers=auth_header(token)
        )
    ).json()

    assert "ok" not in body, "pinned exception #9"
    assert body["id"] == execution_id
    assert body["status"] in (
        "pending",
        "in_progress",
        "completed",
        "failed",
        "cancelled",
    )
    assert isinstance(body["steps"], list)
    assert isinstance(body["completed_steps"], list)
    assert all(isinstance(index, int) for index in body["completed_steps"]), (
        "integer INDICES — the UI calls completed_steps.includes(i)"
    )
    assert isinstance(body["current_step"], int), (
        "an integer index — the UI compares it with === against a loop counter"
    )
    assert "alert_id" in body


# ---------------------------------------------------------------------------
# §2.8 notifications — operations 24-26
# ---------------------------------------------------------------------------


async def test_op24_preferences_are_raw_with_four_rendered_fields(
    client: AsyncClient,
) -> None:
    token = await analyst(client, "c-notif@example.com")
    await client.post(
        "/api/v1/notifications/preferences",
        json={
            "channel": "email",
            "event_type": "alert.high_severity",
            "is_enabled": True,
        },
        headers=auth_header(token),
    )

    body = (
        await client.get(
            "/api/v1/notifications/preferences", headers=auth_header(token)
        )
    ).json()

    assert "ok" not in body, "pinned exception #10"
    preference = body["preferences"][0]
    assert isinstance(preference["id"], int)
    assert preference["channel"] == "email"
    assert preference["channel"] is not None, (
        "WorkspacePanel.jsx:1085 calls channel.toUpperCase() with no null guard"
    )
    assert preference["event_type"] == "alert.high_severity"
    assert isinstance(preference["is_enabled"], bool)


async def test_op25_is_an_upsert_not_an_insert(client: AsyncClient) -> None:
    """CONTRACT §2.8 — both Add and the Enable/Disable toggle POST here.

    If POST always inserts, toggling a preference creates a duplicate row rather
    than flipping it, and the list grows by one on every click.
    """
    token = await analyst(client, "c-notif2@example.com")
    payload = {
        "channel": "email",
        "event_type": "rule.matched",
        "is_enabled": True,
    }

    await client.post(
        "/api/v1/notifications/preferences", json=payload, headers=auth_header(token)
    )
    await client.post(
        "/api/v1/notifications/preferences",
        json={**payload, "is_enabled": False},
        headers=auth_header(token),
    )

    preferences = (
        await client.get(
            "/api/v1/notifications/preferences", headers=auth_header(token)
        )
    ).json()["preferences"]

    matching = [
        p
        for p in preferences
        if p["channel"] == "email" and p["event_type"] == "rule.matched"
    ]
    assert len(matching) == 1, (
        "uniqueness key is (user, channel, event_type) — a second row here is "
        "the duplicate the toggle would create on every click"
    )
    assert matching[0]["is_enabled"] is False, "and the flag actually flipped"


async def test_op25_accepts_every_channel_and_event_type_the_ui_offers(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.8 pins two channels and three event types in the dropdowns.

    `slack` is cut by PLAN §17 and `export.ready` has no producer (PLAN §21), but
    both are SELECTABLE in the frozen UI — so the POST must not 500. What the
    backend does with them afterwards is a separate question from whether the
    form can be submitted.
    """
    token = await analyst(client, "c-notif3@example.com")

    for channel in ("email", "slack"):
        for event_type in ("alert.high_severity", "rule.matched", "export.ready"):
            response = await client.post(
                "/api/v1/notifications/preferences",
                json={
                    "channel": channel,
                    "event_type": event_type,
                    "is_enabled": True,
                },
                headers=auth_header(token),
            )
            assert response.status_code < 500, (
                f"channel={channel} event_type={event_type} is offered by the "
                f"frozen dropdown and produced {response.status_code}: "
                f"{response.text[:200]}"
            )


# ---------------------------------------------------------------------------
# §2.10 no frozen consumer — operations 29, 32, 33, 34
# ---------------------------------------------------------------------------


async def test_op29_alerts_page_is_enveloped_and_paginated(
    client: AsyncClient,
) -> None:
    """FE-6 — hydrates the table on mount; merged with the WS by concat + dedupe
    on `id`, so `id` must be present on every row."""
    token = await analyst(client, "c-alerts@example.com")
    body = (
        await client.get(
            "/api/v1/alerts?limit=5&offset=0", headers=auth_header(token)
        )
    ).json()

    assert set(body) == {"ok", "data", "meta"}
    data = body["data"]
    assert isinstance(data["alerts"], list)
    assert isinstance(data["total"], int)
    for alert in data["alerts"]:
        assert isinstance(alert["id"], str) and alert["id"].startswith("ALT-"), (
            "CONTRACT §4 — the WS gate drops a frame without a top-level id, and "
            "the merge de-dupes on it"
        )


async def test_op32_clusters_carry_a_real_min_alerts_floor(
    client: AsyncClient,
) -> None:
    token = await analyst(client, "c-clusters@example.com")
    body = (
        await client.get(
            "/api/v1/alerts/clusters?min_alerts=3&limit=10", headers=auth_header(token)
        )
    ).json()

    data = body["data"]
    assert isinstance(data["clusters"], list)
    for cluster in data["clusters"]:
        assert isinstance(cluster["alert_count"], int)
        assert cluster["alert_count"] >= 3, (
            "min_alerts is a real floor over the whole table, not a client-side "
            "reduction of a 200-alert buffer"
        )


async def test_op33_rail_metrics_carry_all_four_panels(client: AsyncClient) -> None:
    """CONTRACT §6.1 lists all four right-rail panels as having no backing call."""
    token = await analyst(client, "c-rail@example.com")
    data = (
        await client.get("/api/v1/metrics/rail", headers=auth_header(token))
    ).json()["data"]

    for panel in (
        "signal_velocity",
        "threat_forecast",
        "attack_surface",
        "pipeline_activity",
    ):
        assert panel in data, f"the {panel} panel has no producer"
        assert data[panel] is not None

    # D9 — the pipeline card's rows are GRAPH NODES, not the invented agent
    # names (SENTINEL-ALPHA / CORTEX-03) the frozen screen used to render.
    nodes = {node["name"] for node in data["pipeline_activity"]["nodes"]}
    assert {"classify", "enrich", "retrieve", "reason"} <= nodes, (
        f"the pipeline card must name real graph nodes: {sorted(nodes)}"
    )


async def test_op34_overview_counters_respect_the_active_filter(
    client: AsyncClient,
) -> None:
    """CONTRACT §2.10 #34 — the counters use the SAME predicates as GET /alerts,
    so the header and the table cannot diverge under a filter."""
    token = await analyst(client, "c-overview@example.com")

    overview = (
        await client.get(
            "/api/v1/metrics/overview?severity=critical", headers=auth_header(token)
        )
    ).json()["data"]
    listing = (
        await client.get(
            "/api/v1/alerts?severity=critical&limit=1", headers=auth_header(token)
        )
    ).json()["data"]

    assert overview["total"] == listing["total"], (
        "the header counter and the table's total are computed from the same "
        "predicates; a mismatch is what the frozen frontend does today by "
        "counting its unfiltered buffer"
    )


# ---------------------------------------------------------------------------
# §1.4 errors — uniform everywhere, including on the pinned exceptions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/rules"),
        ("get", "/api/v1/playbooks"),
        ("get", "/api/v1/notifications/preferences"),
        ("get", "/api/v1/auth/me"),
        ("get", "/api/v1/health"),
        ("get", "/api/v1/alerts"),
    ],
)
async def test_error_bodies_are_uniform_even_on_pinned_exceptions(
    client: AsyncClient, method: str, path: str
) -> None:
    """CONTRACT §1.3.1 — 'Only the success body is exempt.'"""
    response = await getattr(client, method)(path)

    assert response.status_code == 401, response.text
    body = response.json()
    assert body["ok"] is False
    assert isinstance(body["detail"], str) and body["detail"]
    assert set(body["error"]) == {"code", "message", "detail"}
    assert body["error"]["message"] == body["detail"], (
        "the frozen frontend reads the flat `detail`; the nested `error` is for "
        "API consumers, and the two must not be able to disagree"
    )
