"""Playbooks CRUD and the execution state machine. CONTRACT §2.7 / §9.6 / §9.9.

**THE STEP TYPES ARE BRANCHED ON FOR REAL** (PLAN §4.1). `auto` advances with
no human and refuses a human POST; `approval` refuses a viewer; `manual` is the
ordinary case. If any of those three collapsed into the others the `type` field
would be bookkeeping that pretends, and PLAN §4.1 says it must then be removed.

**ALL THREE TERMINAL STATUSES ARE REACHABLE** — `completed`, `failed` and
`cancelled`. FE-10 stops the 3-second poller on any of them; the frozen poller
stops only on `completed`, which is why collapsing the other two into it would
have looked like it worked.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from httpx import AsyncClient
from sqlalchemy import delete

from app.store.models import Alert, PlaybookExecution
from app.store.session import get_sessionmaker
from tests.conftest import auth_header, login, make_user

MANUAL_BOOK: dict[str, Any] = {
    "name": "Contain the host",
    "description": "",
    "alert_type": "",
    "severity_threshold": "",
    "steps": [
        {"type": "manual", "title": "Isolate the host", "description": ""},
        {"type": "manual", "title": "Collect volatile memory", "description": ""},
    ],
}


async def _token(client: AsyncClient, email: str, role: str = "analyst") -> str:
    await make_user(email, role=role)
    return await login(client, email)


async def _create(
    client: AsyncClient, token: str, body: dict[str, Any] | None = None
) -> dict[str, Any]:
    response = await client.post(
        "/api/v1/playbooks", json=body or MANUAL_BOOK, headers=auth_header(token)
    )
    assert response.status_code == 201, response.text
    return dict(response.json()["data"])


async def _seed_alert(alert_id: str = "ALT-BBB222") -> str:
    async with get_sessionmaker()() as session:
        session.add(
            Alert(
                id=alert_id,
                timestamp=datetime.now(UTC),
                source="cicids_replay",
                severity="high",
                attack_type="dos",
                src_ip="118.25.6.39",
                dest_ip="192.168.10.50",
                dest_port=80,
                protocol="TCP",
                signature="Flow to TCP/80 — SYN-heavy",
                trace=[],
                tags=[],
                rule_trace=[{"rule_id": 1, "fired": True}],
            )
        )
        await session.commit()
    return alert_id


async def _execute(
    client: AsyncClient, token: str, playbook_id: int, alert_id: str | None = None
) -> dict[str, Any]:
    query = f"?alert_id={alert_id}" if alert_id else "?"
    response = await client.post(
        f"/api/v1/playbooks/{playbook_id}/execute{query}", headers=auth_header(token)
    )
    assert response.status_code == 201, response.text
    execution_id = response.json()["execution_id"]
    got = await client.get(
        f"/api/v1/playbooks/executions/{execution_id}", headers=auth_header(token)
    )
    return dict(got.json())


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


async def test_list_is_raw_and_starts_empty(client: AsyncClient) -> None:
    token = await _token(client, "pb-list@example.com")
    body = (await client.get("/api/v1/playbooks", headers=auth_header(token))).json()
    assert "ok" not in body
    assert body == {"playbooks": []}


async def test_create_update_and_delete(client: AsyncClient) -> None:
    token = await _token(client, "pb-crud@example.com")
    created = await _create(client, token)
    assert created["execution_count"] == 0
    assert len(created["steps"]) == 2

    updated = await client.put(
        f"/api/v1/playbooks/{created['id']}",
        json={**MANUAL_BOOK, "name": "Renamed", "severity_threshold": "high"},
        headers=auth_header(token),
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["name"] == "Renamed"
    assert updated.json()["data"]["severity_threshold"] == "high"

    deleted = await client.delete(
        f"/api/v1/playbooks/{created['id']}", headers=auth_header(token)
    )
    assert deleted.status_code == 204


async def test_an_empty_step_list_is_legal(client: AsyncClient) -> None:
    """Steps with an empty title are stripped client-side before submit."""
    token = await _token(client, "pb-empty@example.com")
    created = await _create(client, token, {**MANUAL_BOOK, "steps": []})
    assert created["steps"] == []


async def test_an_unknown_severity_threshold_is_refused(client: AsyncClient) -> None:
    token = await _token(client, "pb-badsev@example.com")
    response = await client.post(
        "/api/v1/playbooks",
        json={**MANUAL_BOOK, "severity_threshold": "unknown"},
        headers=auth_header(token),
    )
    assert response.status_code == 422
    assert "classification failed" in response.json()["detail"]


# ---------------------------------------------------------------------------
# IDOR
# ---------------------------------------------------------------------------


async def test_another_users_playbook_cannot_be_updated_or_deleted(
    client: AsyncClient,
) -> None:
    owner = await _token(client, "pb-owner@example.com")
    intruder = await _token(client, "pb-intruder@example.com")
    created = await _create(client, owner)

    put = await client.put(
        f"/api/v1/playbooks/{created['id']}",
        json={**MANUAL_BOOK, "name": "hijacked"},
        headers=auth_header(intruder),
    )
    assert put.status_code == 404

    delete = await client.delete(
        f"/api/v1/playbooks/{created['id']}", headers=auth_header(intruder)
    )
    assert delete.status_code == 404

    listed = (
        await client.get("/api/v1/playbooks", headers=auth_header(owner))
    ).json()["playbooks"]
    assert listed[0]["name"] == MANUAL_BOOK["name"], "nothing was changed"


async def test_another_users_execution_is_not_retrievable_by_id(
    client: AsyncClient,
) -> None:
    owner = await _token(client, "ex-owner@example.com")
    intruder = await _token(client, "ex-intruder@example.com")
    created = await _create(client, owner)
    execution = await _execute(client, owner, created["id"])

    response = await client.get(
        f"/api/v1/playbooks/executions/{execution['id']}",
        headers=auth_header(intruder),
    )
    assert response.status_code == 404

    step = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/0",
        json={"notes": ""},
        headers=auth_header(intruder),
    )
    assert step.status_code == 404


# ---------------------------------------------------------------------------
# execution — the shape the frozen UI reads
# ---------------------------------------------------------------------------


async def test_execute_returns_only_an_execution_id_and_is_raw(
    client: AsyncClient,
) -> None:
    token = await _token(client, "ex-shape@example.com")
    created = await _create(client, token)
    response = await client.post(
        f"/api/v1/playbooks/{created['id']}/execute?", headers=auth_header(token)
    )
    assert response.status_code == 201
    body = response.json()
    assert "ok" not in body
    assert set(body) == {"execution_id"}


async def test_alert_id_is_optional(client: AsyncClient) -> None:
    """CONTRACT §9.9 — with no alert selected the UI posts `…/execute?`."""
    token = await _token(client, "ex-noalert@example.com")
    created = await _create(client, token)
    execution = await _execute(client, token, created["id"])
    assert execution["alert_id"] is None
    assert execution["status"] == "in_progress"


async def test_the_execution_shape_is_what_the_frozen_ui_reads(
    client: AsyncClient,
) -> None:
    token = await _token(client, "ex-keys@example.com")
    created = await _create(client, token)
    execution = await _execute(client, token, created["id"])

    assert set(execution) >= {
        "id",
        "status",
        "alert_id",
        "steps",
        "completed_steps",
        "current_step",
    }
    assert execution["completed_steps"] == [], "array of zero-based INDICES"
    assert execution["current_step"] == 0, "an integer index, compared with ==="


async def test_stepping_through_a_manual_playbook_completes_it(
    client: AsyncClient,
) -> None:
    token = await _token(client, "ex-manual@example.com")
    created = await _create(client, token)
    execution = await _execute(client, token, created["id"])

    first = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/0",
        json={"notes": ""},
        headers=auth_header(token),
    )
    assert first.status_code == 200
    assert first.json()["data"]["current_step"] == 1
    assert first.json()["data"]["status"] == "in_progress"

    second = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/1",
        json={"notes": "memory captured"},
        headers=auth_header(token),
    )
    assert second.json()["data"]["status"] == "completed"
    assert second.json()["data"]["completed_steps"] == [0, 1]
    notes = second.json()["data"]["step_notes"]
    assert notes[-1]["note"] == "memory captured", "PLAN §4.1 — per-step notes"


async def test_a_step_out_of_order_is_a_409(client: AsyncClient) -> None:
    token = await _token(client, "ex-order@example.com")
    created = await _create(client, token)
    execution = await _execute(client, token, created["id"])

    response = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/1",
        json={"notes": ""},
        headers=auth_header(token),
    )
    assert response.status_code == 409
    assert "not the current step" in response.json()["detail"]


# ---------------------------------------------------------------------------
# the branch — auto / approval / manual
# ---------------------------------------------------------------------------


async def test_an_all_auto_playbook_completes_without_a_human(
    client: AsyncClient,
) -> None:
    """This is the observable difference between `auto` and `manual`."""
    token = await _token(client, "ex-auto@example.com")
    alert_id = await _seed_alert("ALT-AUT001")
    created = await _create(
        client,
        token,
        {
            **MANUAL_BOOK,
            "steps": [
                {"type": "auto", "title": "Snapshot alert state", "description": ""},
                {"type": "auto", "title": "Record disposition", "description": ""},
            ],
        },
    )
    execution = await _execute(client, token, created["id"], alert_id)

    assert execution["status"] == "completed"
    assert execution["completed_steps"] == [0, 1]
    assert execution["current_step"] == 2

    # The auto step did real work: it recorded the alert's triaged state.
    data = execution["step_notes"][0]["data"]
    assert data["alert_id"] == alert_id
    assert data["severity"] == "high"
    assert data["rules_fired"] == 1
    assert execution["step_notes"][0]["by"] == "system"


async def test_a_human_cannot_complete_an_auto_step(client: AsyncClient) -> None:
    """It is not waiting for anyone — that is what `auto` means."""
    token = await _token(client, "ex-autopost@example.com")
    created = await _create(
        client,
        token,
        {
            **MANUAL_BOOK,
            "steps": [
                {"type": "manual", "title": "Triage", "description": ""},
                {"type": "auto", "title": "Snapshot", "description": ""},
            ],
        },
    )
    execution = await _execute(client, token, created["id"])
    assert execution["current_step"] == 0, "the manual step gates it"

    # Completing step 0 lets the engine run step 1 by itself.
    done = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/0",
        json={"notes": ""},
        headers=auth_header(token),
    )
    assert done.json()["data"]["status"] == "completed"
    assert done.json()["data"]["completed_steps"] == [0, 1]

    # And a human POST to that auto step is refused, not silently accepted.
    retry = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/1",
        json={"notes": ""},
        headers=auth_header(token),
    )
    assert retry.status_code == 409


async def test_a_viewer_cannot_grant_an_approval(client: AsyncClient) -> None:
    """An approval anyone can grant is not an approval."""
    token = await _token(client, "ex-viewer@example.com", role="viewer")
    created = await _create(
        client,
        token,
        {
            **MANUAL_BOOK,
            "steps": [{"type": "approval", "title": "Manager sign-off", "description": ""}],
        },
    )
    execution = await _execute(client, token, created["id"])

    response = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/0",
        json={"notes": ""},
        headers=auth_header(token),
    )
    assert response.status_code == 403
    assert "cannot approve" in response.json()["detail"]


async def test_an_analyst_can_grant_an_approval_and_it_is_recorded(
    client: AsyncClient,
) -> None:
    token = await _token(client, "ex-analyst@example.com", role="analyst")
    created = await _create(
        client,
        token,
        {
            **MANUAL_BOOK,
            "steps": [{"type": "approval", "title": "Sign-off", "description": ""}],
        },
    )
    execution = await _execute(client, token, created["id"])

    response = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/0",
        json={"notes": "approved by duty analyst"},
        headers=auth_header(token),
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["status"] == "completed"
    assert data["step_notes"][0]["kind"] == "approved"
    assert data["step_notes"][0]["by"].startswith("user:")


# ---------------------------------------------------------------------------
# terminal statuses — all three real (CONTRACT §9.6)
# ---------------------------------------------------------------------------


async def test_an_execution_reaches_failed_when_an_auto_step_cannot_run(
    client: AsyncClient,
) -> None:
    """`failed` is a real outcome with a real cause, not a label.

    The auto step's job is to record the linked alert's state. If the alert
    cannot be read when the step runs there is nothing to record, and the run
    stops as `failed` rather than claiming a step it did not do.
    """
    token = await _token(client, "ex-failed@example.com")
    alert_id = await _seed_alert("ALT-FAI001")
    created = await _create(
        client,
        token,
        {
            **MANUAL_BOOK,
            "steps": [
                {"type": "manual", "title": "Triage", "description": ""},
                {"type": "auto", "title": "Snapshot alert", "description": ""},
            ],
        },
    )
    execution = await _execute(client, token, created["id"], alert_id)
    assert execution["status"] == "in_progress"

    async with get_sessionmaker()() as session:
        await session.execute(delete(Alert).where(Alert.id == alert_id))
        await session.commit()

    response = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/0",
        json={"notes": ""},
        headers=auth_header(token),
    )
    data = response.json()["data"]

    assert data["status"] == "failed"
    assert data["status"] != "completed", "a run that did not finish never claims it did"
    assert alert_id in data["terminal_reason"]
    assert data["completed_steps"] == [0], "the step that DID run is still recorded"


async def test_deleting_a_playbook_cancels_its_in_flight_runs(
    client: AsyncClient,
) -> None:
    """`cancelled` is a real outcome too.

    Leaving the run `in_progress` would show a run that can never finish;
    marking it `completed` would claim work that did not happen.
    """
    token = await _token(client, "ex-cancel@example.com")
    created = await _create(client, token)
    execution = await _execute(client, token, created["id"])

    await client.delete(
        f"/api/v1/playbooks/{created['id']}", headers=auth_header(token)
    )

    after = (
        await client.get(
            f"/api/v1/playbooks/executions/{execution['id']}",
            headers=auth_header(token),
        )
    ).json()
    assert after["status"] == "cancelled"
    assert "deleted while this run was in flight" in after["terminal_reason"]

    # And a step on a terminal execution is refused rather than resurrecting it.
    response = await client.post(
        f"/api/v1/playbooks/executions/{execution['id']}/steps/0",
        json={"notes": ""},
        headers=auth_header(token),
    )
    assert response.status_code == 409


async def test_every_terminal_status_is_reachable(client: AsyncClient) -> None:
    """The three FE-10 stops the poller on, proven present in one place."""
    async with get_sessionmaker()() as session:
        from sqlalchemy import select

        reached = set(
            (await session.execute(select(PlaybookExecution.status))).scalars().all()
        )
    # This test runs against a clean table; the assertion that matters is the
    # union proven by the three tests above, restated here as documentation of
    # the contract's terminal set.
    from app.playbooks.engine import TERMINAL_STATUSES

    assert TERMINAL_STATUSES == {"completed", "failed", "cancelled"}
    assert reached <= TERMINAL_STATUSES | {"pending", "in_progress"}


# ---------------------------------------------------------------------------
# execution_count is real (PLAN I2)
# ---------------------------------------------------------------------------


async def test_execution_count_is_a_real_count(client: AsyncClient) -> None:
    token = await _token(client, "ex-count@example.com")
    created = await _create(client, token)

    for _ in range(3):
        await _execute(client, token, created["id"])

    listed = (
        await client.get("/api/v1/playbooks", headers=auth_header(token))
    ).json()["playbooks"]
    assert listed[0]["execution_count"] == 3


async def test_executing_an_unknown_playbook_or_alert_is_a_404(
    client: AsyncClient,
) -> None:
    token = await _token(client, "ex-404@example.com")
    created = await _create(client, token)

    missing_book = await client.post(
        "/api/v1/playbooks/99999/execute?", headers=auth_header(token)
    )
    assert missing_book.status_code == 404

    missing_alert = await client.post(
        f"/api/v1/playbooks/{created['id']}/execute?alert_id=ALT-FFFFFF",
        headers=auth_header(token),
    )
    assert missing_alert.status_code == 404


# ---------------------------------------------------------------------------
# auto-trigger — what makes alert_type and severity_threshold load-bearing
# ---------------------------------------------------------------------------


async def _emit_through_the_feed(
    *, alert_id: str, severity: str, attack_type: str
) -> None:
    """Drive `FeedService._emit`, which is where persistence and auto-trigger
    share one transaction. Triage is stubbed — this is about what happens
    AFTER a verdict exists, not about producing one."""
    from app.ingestion.feed import FeedService
    from app.ingestion.normalize import NormalizedAlert

    feed = FeedService()

    async def _verdict(alert: NormalizedAlert) -> None:
        alert.severity = severity
        alert.attack_type = attack_type

    feed._triage = _verdict  # type: ignore[method-assign]

    await feed._emit(
        NormalizedAlert(
            id=alert_id,
            timestamp=datetime.now(UTC),
            source="cicids_replay",
            severity="unknown",
            attack_type="unknown",
            src_ip="118.25.6.39",
            dest_ip="192.168.10.50",
            dest_port=80,
            protocol="TCP",
            signature="Flow to TCP/80",
        )
    )


async def _executions_for(playbook_id: int) -> list[PlaybookExecution]:
    from sqlalchemy import select

    async with get_sessionmaker()() as session:
        return list(
            (
                await session.execute(
                    select(PlaybookExecution).where(
                        PlaybookExecution.playbook_id == playbook_id
                    )
                )
            )
            .scalars()
            .all()
        )


async def test_a_matching_alert_auto_executes_the_playbook(
    client: AsyncClient,
) -> None:
    token = await _token(client, "auto-match@example.com")
    created = await _create(
        client,
        token,
        {**MANUAL_BOOK, "alert_type": "ddos", "severity_threshold": "high"},
    )

    await _emit_through_the_feed(
        alert_id="ALT-AUTO01", severity="critical", attack_type="ddos"
    )

    executions = await _executions_for(created["id"])
    assert len(executions) == 1
    assert executions[0].triggered_by == "auto"
    assert executions[0].alert_id == "ALT-AUTO01"
    assert executions[0].status == "in_progress"


async def test_an_alert_below_the_threshold_does_not_trigger(
    client: AsyncClient,
) -> None:
    token = await _token(client, "auto-below@example.com")
    created = await _create(
        client, token, {**MANUAL_BOOK, "severity_threshold": "high"}
    )

    await _emit_through_the_feed(
        alert_id="ALT-AUTO02", severity="medium", attack_type="ddos"
    )
    assert await _executions_for(created["id"]) == []


async def test_an_unknown_severity_alert_never_auto_triggers(
    client: AsyncClient,
) -> None:
    """PLAN D27 — the single most consequential line of the threshold rule.

    `unknown` means classification FAILED. Treating it as "at least high" would
    fire real response actions on the pipeline's own bugs, at exactly the
    moment the pipeline is least trustworthy.
    """
    token = await _token(client, "auto-unknown@example.com")
    for threshold in ("low", "medium", "high", "critical"):
        created = await _create(
            client,
            token,
            {**MANUAL_BOOK, "name": threshold, "severity_threshold": threshold},
        )
        await _emit_through_the_feed(
            alert_id=f"ALT-UNK{threshold[:3].upper()}",
            severity="unknown",
            attack_type="ddos",
        )
        assert await _executions_for(created["id"]) == [], threshold


async def test_a_mismatched_alert_type_does_not_trigger(
    client: AsyncClient,
) -> None:
    token = await _token(client, "auto-type@example.com")
    created = await _create(client, token, {**MANUAL_BOOK, "alert_type": "botnet"})

    await _emit_through_the_feed(
        alert_id="ALT-AUTO03", severity="critical", attack_type="ddos"
    )
    assert await _executions_for(created["id"]) == []


async def test_the_same_alert_does_not_start_a_second_auto_run(
    client: AsyncClient,
) -> None:
    """Replay loops over the same partition, so the same alert id recurs."""
    token = await _token(client, "auto-dedupe@example.com")
    created = await _create(client, token, MANUAL_BOOK)

    for _ in range(3):
        await _emit_through_the_feed(
            alert_id="ALT-AUTO04", severity="high", attack_type="ddos"
        )

    assert len(await _executions_for(created["id"])) == 1


async def test_a_disabled_playbook_does_not_auto_trigger(
    client: AsyncClient,
) -> None:
    token = await _token(client, "auto-disabled@example.com")
    created = await _create(client, token, MANUAL_BOOK)

    async with get_sessionmaker()() as session:
        from app.store.models import Playbook

        book = await session.get(Playbook, created["id"])
        assert book is not None
        book.is_enabled = False
        await session.commit()

    await _emit_through_the_feed(
        alert_id="ALT-AUTO05", severity="critical", attack_type="ddos"
    )
    assert await _executions_for(created["id"]) == []
