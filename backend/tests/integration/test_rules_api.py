"""Rules CRUD, IDOR, and the actions actually mutating a persisted alert.

PLAN §4.1 / D33 / §9 / CONTRACT §2.6.

The centrepiece is `test_a_rule_action_mutates_the_persisted_alert` and
`test_a_rule_beats_both_the_model_and_intel_escalation`. In the prior codebase
the whole rules module was unreachable dead code: a rule could be created,
listed and deleted while changing nothing about any alert — an endpoint that
writes a row and executes nothing (T14). These two tests are what make "wired
live" a fact rather than a claim.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient

from app.agent.apply import apply_to_alert
from app.agent.graph import reset_graph, run_pipeline
from app.config import Settings
from app.ingestion.normalize import NormalizedAlert
from app.rag.retriever import Retrieved
from app.rules.store import bump_match_counts, refresh_rule_engine
from app.store.models import Alert
from app.store.models import Rule as RuleRow
from app.store.repositories import upsert_alert
from app.store.session import get_sessionmaker
from tests.conftest import auth_header, login, make_user
from tests.unit.conftest_graph import (
    StubAggregator,
    StubClassifier,
    StubIntelVerdict,
    StubRetriever,
    stub_registry,
)

RULE_BODY: dict[str, Any] = {
    "name": "Escalate scans from the lab range",
    "description": "",
    "conditions": {
        "logic": "AND",
        "conditions": [
            {"field": "attack_type", "operator": "equals", "value": "port_scan"}
        ],
    },
    "actions": [{"type": "set_severity", "value": "high"}],
}


async def _token(client: AsyncClient, email: str, role: str = "analyst") -> str:
    await make_user(email, role=role)
    return await login(client, email)


def _alert(**overrides: Any) -> NormalizedAlert:
    base: dict[str, Any] = {
        "id": "ALT-AAA111",
        "timestamp": datetime.now(UTC),
        "source": "cicids_replay",
        "severity": "unknown",
        "attack_type": "unknown",
        "src_ip": "118.25.6.39",
        "dest_ip": "192.168.10.50",
        "dest_port": 80,
        "protocol": "TCP",
        "signature": "Flow to TCP/80 — SYN-heavy, minimal payload",
        "features": {"Destination Port": 80.0},
    }
    base.update(overrides)
    return NormalizedAlert(**base)


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "jwt_secret": "t" * 40,
        "environment": "test",
        "offline_mode": False,
        # Keep the reasoning tier out of the way: these tests are about the
        # rules node, and a provider round trip would only add a stub.
        "reason_severity_floor": "critical",
        "escalation_confidence_threshold": 0.5,
    }
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def pipeline(monkeypatch: pytest.MonkeyPatch):
    """The real graph, with the network stubbed and the classifier pinned."""

    def _run(
        *,
        ml_attack_type: str = "port_scan",
        ml_severity: str = "medium",
        intel_score: int = 0,
        intel_malicious: bool = False,
    ):
        config = _settings()
        registry = stub_registry(config)
        for module in (
            "app.providers.registry",
            "app.agent.nodes.reason",
            "app.agent.nodes.classify",
        ):
            monkeypatch.setattr(f"{module}.get_registry", lambda: registry)
        monkeypatch.setattr(
            "app.agent.nodes.classify.get_classifier",
            lambda: StubClassifier(ml_attack_type, ml_severity, 1.0),
        )
        monkeypatch.setattr(
            "app.agent.nodes.enrich.get_aggregator",
            lambda: StubAggregator(
                StubIntelVerdict(
                    ip="118.25.6.39",
                    checked=True,
                    score=intel_score,
                    malicious=intel_malicious,
                )
            ),
        )
        monkeypatch.setattr(
            "app.agent.nodes.retrieve.get_retriever",
            lambda: StubRetriever(
                [Retrieved("T1046", "Network Service Discovery", "description", 0.6)]
            ),
        )
        reset_graph()
        return config

    return _run


async def _triage_and_store(alert: NormalizedAlert, config: Settings) -> Alert:
    """Run the graph, then persist exactly the way the feed does."""
    state = await run_pipeline(alert, config)
    apply_to_alert(alert, state)
    async with get_sessionmaker()() as session:
        stored = await upsert_alert(session, alert)
        fired = [
            str(entry["rule_id"])
            for entry in (alert.rule_trace or [])
            if entry.get("fired")
        ]
        await bump_match_counts(session, fired)
        await session.commit()
        return stored


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


async def test_list_is_raw_and_carries_the_key_the_frontend_reads(
    client: AsyncClient,
) -> None:
    """CONTRACT §1.3.1 — enveloping this makes `d.rules` undefined forever."""
    token = await _token(client, "rules-list@example.com")
    body = (await client.get("/api/v1/rules", headers=auth_header(token))).json()

    assert "ok" not in body
    assert body == {"rules": []}, "PLAN I9 — no seeded example rule, in any environment"


async def test_create_returns_the_created_resource_enveloped(
    client: AsyncClient,
) -> None:
    token = await _token(client, "rules-create@example.com")
    response = await client.post(
        "/api/v1/rules", json=RULE_BODY, headers=auth_header(token)
    )

    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"ok", "data", "meta"}
    assert body["data"]["name"] == RULE_BODY["name"]
    assert body["data"]["match_count"] == 0
    assert body["data"]["is_enabled"] is True


async def test_a_created_rule_appears_in_the_owner_s_list(client: AsyncClient) -> None:
    token = await _token(client, "rules-roundtrip@example.com")
    await client.post("/api/v1/rules", json=RULE_BODY, headers=auth_header(token))

    rules = (await client.get("/api/v1/rules", headers=auth_header(token))).json()[
        "rules"
    ]
    assert len(rules) == 1
    assert rules[0]["name"] == RULE_BODY["name"]


async def test_delete_removes_it(client: AsyncClient) -> None:
    token = await _token(client, "rules-delete@example.com")
    created = (
        await client.post("/api/v1/rules", json=RULE_BODY, headers=auth_header(token))
    ).json()["data"]

    response = await client.delete(
        f"/api/v1/rules/{created['id']}", headers=auth_header(token)
    )
    assert response.status_code == 204

    rules = (await client.get("/api/v1/rules", headers=auth_header(token))).json()[
        "rules"
    ]
    assert rules == []


# ---------------------------------------------------------------------------
# IDOR — PLAN §9
# ---------------------------------------------------------------------------


async def test_another_users_rule_is_not_retrievable_or_deletable_by_id(
    client: AsyncClient,
) -> None:
    """Owner-scoped on LOOKUP, not just on list.

    404 rather than 403 on purpose: a 403 confirms the id exists, which is the
    half of the answer an enumeration attack wants.
    """
    owner = await _token(client, "owner@example.com")
    intruder = await _token(client, "intruder@example.com")

    created = (
        await client.post("/api/v1/rules", json=RULE_BODY, headers=auth_header(owner))
    ).json()["data"]

    listed = (await client.get("/api/v1/rules", headers=auth_header(intruder))).json()
    assert listed["rules"] == [], "not in the list"

    response = await client.delete(
        f"/api/v1/rules/{created['id']}", headers=auth_header(intruder)
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Rule not found."

    still_there = (
        await client.get("/api/v1/rules", headers=auth_header(owner))
    ).json()["rules"]
    assert len(still_there) == 1, "the intruder's delete changed nothing"


# ---------------------------------------------------------------------------
# ReDoS — PLAN §9
# ---------------------------------------------------------------------------


async def test_a_pathological_regex_is_refused_at_create_time(
    client: AsyncClient,
) -> None:
    """The bound fires here, not on the alert that would have stalled the feed.

    The message lands in `detail`, which the frozen frontend renders verbatim
    (WorkspacePanel.jsx:685), so the operator is told what to change.
    """
    token = await _token(client, "redos@example.com")
    body = {
        **RULE_BODY,
        "conditions": {
            "logic": "AND",
            "conditions": [
                {"field": "signature", "operator": "contains", "value": "(a+)+$"}
            ],
        },
    }
    response = await client.post(
        "/api/v1/rules", json=body, headers=auth_header(token)
    )

    assert response.status_code == 422
    assert "nests one repetition" in response.json()["detail"]

    async with get_sessionmaker()() as session:
        from sqlalchemy import func, select

        count = (
            await session.execute(select(func.count()).select_from(RuleRow))
        ).scalar_one()
    assert count == 0, "a refused rule is not stored"


async def test_an_unassignable_severity_is_refused_with_a_readable_reason(
    client: AsyncClient,
) -> None:
    token = await _token(client, "badsev@example.com")
    body = {**RULE_BODY, "actions": [{"type": "set_severity", "value": "unknown"}]}
    response = await client.post(
        "/api/v1/rules", json=body, headers=auth_header(token)
    )

    assert response.status_code == 422
    assert "the pipeline failed" in response.json()["detail"]


# ---------------------------------------------------------------------------
# THE ACTIONS ARE LIVE — PLAN T14
# ---------------------------------------------------------------------------


async def test_a_rule_action_mutates_the_persisted_alert(
    client: AsyncClient, pipeline
) -> None:
    """All three actions, end to end, on a row that is actually in the database."""
    token = await _token(client, "live@example.com")
    body = {
        "name": "Contain the lab scanner",
        "description": "",
        "conditions": {
            "logic": "AND",
            "conditions": [
                {"field": "src_ip", "operator": "equals", "value": "118.25.6.39"}
            ],
        },
        "actions": [
            {"type": "set_severity", "value": "critical"},
            {"type": "add_tag", "value": "lab-scanner"},
            {"type": "set_attack_type", "value": "botnet"},
        ],
    }
    created = (
        await client.post("/api/v1/rules", json=body, headers=auth_header(token))
    ).json()["data"]

    config = pipeline(ml_attack_type="port_scan", ml_severity="medium")
    stored = await _triage_and_store(_alert(), config)

    assert stored.severity == "critical", "set_severity changed the stored row"
    assert stored.attack_type == "botnet", "set_attack_type changed the vector"
    assert stored.tags == ["lab-scanner"], "add_tag landed somewhere real"

    # The counter is a real count of alerts this rule fired on (PLAN I2).
    async with get_sessionmaker()() as session:
        rule = await session.get(RuleRow, created["id"])
        assert rule is not None
        assert rule.match_count == 1


async def test_a_rule_beats_both_the_model_and_intel_escalation(
    client: AsyncClient, pipeline
) -> None:
    """PRECEDENCE: model < intel escalation < rules.

    The rule DOWNGRADES here, which is the sharpest possible form of the
    assertion: intel had already pushed the alert to `high`, and the operator's
    written instruction about their own network overrides it anyway. An upgrade
    rule could be mistaken for intel's own escalation.
    """
    token = await _token(client, "precedence@example.com")
    body = {
        "name": "Our own scanner, not a threat",
        "description": "",
        "conditions": {
            "logic": "AND",
            "conditions": [
                {"field": "src_ip", "operator": "equals", "value": "118.25.6.39"}
            ],
        },
        "actions": [{"type": "set_severity", "value": "low"}],
    }
    await client.post("/api/v1/rules", json=body, headers=auth_header(token))

    config = pipeline(
        ml_attack_type="port_scan",
        ml_severity="medium",
        intel_score=92,
        intel_malicious=True,
    )
    alert = _alert()
    state = await run_pipeline(alert, config)

    assert state.ml_severity == "medium", "what the model said"
    assert state.intel_escalated is True, "what intel then did"
    assert state.severity == "low", "what the operator's rule did last"
    assert state.rules_overrode is True

    fired = [entry for entry in state.rule_trace if entry["fired"]]
    assert len(fired) == 1
    applied = fired[0]["actions_applied"][0]
    assert applied["from"] == "high", "the rule saw intel's post-upgrade severity"
    assert applied["to"] == "low"

    rules_entry = next(e for e in state.trace if e.node == "rules")
    assert "overriding intel escalation" in (rules_entry.note or "")


async def test_a_rule_that_does_not_match_changes_nothing(
    client: AsyncClient, pipeline
) -> None:
    token = await _token(client, "nomatch@example.com")
    body = {
        **RULE_BODY,
        "conditions": {
            "logic": "AND",
            "conditions": [
                {"field": "attack_type", "operator": "equals", "value": "ddos"}
            ],
        },
    }
    created = (
        await client.post("/api/v1/rules", json=body, headers=auth_header(token))
    ).json()["data"]

    config = pipeline(ml_attack_type="port_scan", ml_severity="medium")
    stored = await _triage_and_store(_alert(), config)

    assert stored.severity == "medium"
    async with get_sessionmaker()() as session:
        rule = await session.get(RuleRow, created["id"])
        assert rule is not None and rule.match_count == 0


# ---------------------------------------------------------------------------
# explain-rules
# ---------------------------------------------------------------------------


async def test_explain_rules_is_raw_and_carries_every_rule_evaluated(
    client: AsyncClient, pipeline
) -> None:
    """CONTRACT §2.6 #16 — non-firing rules are the drawer's best beat."""
    token = await _token(client, "explain@example.com")
    for name, value in (("fires", "118.25.6.39"), ("does not fire", "10.0.0.1")):
        await client.post(
            "/api/v1/rules",
            json={
                "name": name,
                "description": "",
                "conditions": {
                    "logic": "AND",
                    "conditions": [
                        {"field": "src_ip", "operator": "equals", "value": value}
                    ],
                },
                "actions": [{"type": "add_tag", "value": name.replace(" ", "-")}],
            },
            headers=auth_header(token),
        )

    config = pipeline()
    stored = await _triage_and_store(_alert(), config)

    response = await client.get(
        f"/api/v1/rules/alerts/{stored.id}/explain-rules", headers=auth_header(token)
    )
    body = response.json()

    assert "ok" not in body, "RAW — the whole body becomes the drawer's state"
    assert len(body["matched_rules"]) == 2, "every rule EVALUATED, not only fired"
    assert [entry["fired"] for entry in body["matched_rules"]] == [True, False]
    for entry in body["matched_rules"]:
        assert isinstance(entry["rule_id"], int), "the React key is an integer"
        for condition in entry["conditions"]:
            assert set(condition) >= {
                "field",
                "operator",
                "expected",
                "actual",
                "result",
            }


async def test_explain_rules_on_an_alert_triaged_before_any_rule_existed(
    client: AsyncClient, pipeline
) -> None:
    """An empty array is the honest answer, and the UI renders it as such.

    Recomputing against today's rules would answer a different question — "what
    would the current rules say" rather than "why does this alert look like
    this" — and the drawer is asking the second one.
    """
    token = await _token(client, "empty-explain@example.com")
    config = pipeline()
    stored = await _triage_and_store(_alert(), config)

    await client.post("/api/v1/rules", json=RULE_BODY, headers=auth_header(token))

    body = (
        await client.get(
            f"/api/v1/rules/alerts/{stored.id}/explain-rules",
            headers=auth_header(token),
        )
    ).json()
    assert body["matched_rules"] == []


async def test_explain_rules_404s_for_an_unknown_alert(client: AsyncClient) -> None:
    token = await _token(client, "explain404@example.com")
    response = await client.get(
        "/api/v1/rules/alerts/ALT-FFFFFF/explain-rules", headers=auth_header(token)
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# storage -> engine
# ---------------------------------------------------------------------------


async def test_a_stored_rule_survives_a_restart(client: AsyncClient) -> None:
    """The engine is rebuilt from the database, so rules are not process state."""
    token = await _token(client, "restart@example.com")
    await client.post("/api/v1/rules", json=RULE_BODY, headers=auth_header(token))

    from app.rules.engine import reset_rule_engine

    reset_rule_engine()  # as if the process had just started

    async with get_sessionmaker()() as session:
        engine = await refresh_rule_engine(session)
    assert len(engine) == 1
    assert engine.rules[0].name == RULE_BODY["name"]
