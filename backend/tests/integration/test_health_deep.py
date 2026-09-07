"""GET /health/deep. CONTRACT §9.5 / PLAN §10.4 / I8 / I16.

The suite runs in offline mode (see conftest), so the default assertions cover
the declared-offline path. The probing path is exercised with a stub registry so
no test can spend a metered quota unit.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient

from tests.conftest import auth_header, login, make_user


async def token(client: AsyncClient) -> str:
    await make_user("deep@flare.dev", role="analyst")
    return await login(client, "deep@flare.dev")


async def test_health_deep_requires_authentication(client: AsyncClient) -> None:
    """PLAN §9 / I8 — an anonymous deep probe would burn four quotas per hit."""
    response = await client.get("/api/v1/health/deep")
    assert response.status_code == 401


async def test_health_deep_reports_offline_without_probing(client: AsyncClient) -> None:
    """PLAN E9 — offline mode is DECLARED. Four errors would read as an outage."""
    body = (
        await client.get(
            "/api/v1/health/deep", headers=auth_header(await token(client))
        )
    ).json()
    data = body["data"]

    assert body["ok"] is True
    assert data["offline_mode"] is True
    assert {s["name"] for s in data["services"]} == {
        "groq",
        "gemini",
        "abuseipdb",
        "virustotal",
    }
    for service in data["services"]:
        assert service["status"] == "unknown"
        assert service["message"] == "offline mode: no probe issued"


async def test_health_deep_reports_queue_and_pipeline_state(client: AsyncClient) -> None:
    data = (
        await client.get(
            "/api/v1/health/deep", headers=auth_header(await token(client))
        )
    ).json()["data"]

    assert set(data) >= {
        "services",
        "queue_depth",
        "in_flight",
        "dropped",
        "degraded",
        "offline_mode",
        "providers",
        "reason_budget",
    }
    assert data["in_flight"] == 0
    assert "triage" in data["queue_depth"]
    assert data["reason_budget"]["calls_per_minute"] > 0


async def test_health_deep_never_returns_key_material(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PLAN I16 — labels and counters only, on every path."""
    import app.api.routes.health_deep as deep_mod
    from app.config import Settings
    from tests.unit.conftest_graph import stub_registry

    secret = "gsk-super-secret-value-0000"
    config = Settings(
        jwt_secret="t" * 40,
        environment="test",
        offline_mode=False,
        groq_api_key_dev=secret,
        gemini_api_key_dev=secret,
    )
    registry = stub_registry(config)
    monkeypatch.setattr(deep_mod, "get_registry", lambda: registry)

    async def fake_probe(name: str) -> dict[str, Any]:
        return {"status": "ok", "latency_ms": 1.0, "message": f"{name} stub"}

    monkeypatch.setattr(deep_mod, "_probe_intel", fake_probe)

    response = await client.get(
        "/api/v1/health/deep", headers=auth_header(await token(client))
    )
    assert response.status_code == 200
    assert secret not in response.text

    providers = response.json()["data"]["providers"]
    assert providers["groq"]["model"] == "openai/gpt-oss-120b"
    assert providers["gemini"]["model"] == "gemini-3.6-flash"
    assert providers["groq"]["keys"][0]["key_id"] == "groq-dev"


async def test_health_deep_surfaces_a_provider_failure_verbatim(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PLAN §11 — the operator needs the provider's own words, not a category."""
    import app.api.routes.health_deep as deep_mod
    from app.config import Settings
    from app.providers.base import ProviderHTTPError
    from tests.unit.conftest_graph import StubLLM, stub_registry

    config = Settings(
        jwt_secret="t" * 40,
        environment="test",
        offline_mode=False,
        groq_api_key_dev="k",
        gemini_api_key_dev="k",
    )
    registry = stub_registry(
        config,
        gemini=StubLLM(
            "gemini",
            "gemini-3.6-flash",
            error=ProviderHTTPError("gemini", 503, "The model is overloaded."),
        ),
    )
    monkeypatch.setattr(deep_mod, "get_registry", lambda: registry)

    async def fake_probe(name: str) -> dict[str, Any]:
        return {"status": "ok", "latency_ms": 1.0, "message": name}

    monkeypatch.setattr(deep_mod, "_probe_intel", fake_probe)

    data = (
        await client.get(
            "/api/v1/health/deep", headers=auth_header(await token(client))
        )
    ).json()["data"]

    gemini = next(s for s in data["services"] if s["name"] == "gemini")
    assert gemini["status"] == "error"
    assert "The model is overloaded." in gemini["message"]
    assert data["degraded"] is True


async def test_the_cheap_health_endpoint_never_probes(client: AsyncClient) -> None:
    """PLAN T4/§10 — this is the endpoint on the frontend's 30-second timer."""
    import inspect

    import app.api.routes.health as health_mod

    source = inspect.getsource(health_mod)
    assert "httpx" not in source
    assert "get_registry" not in source

    body = (
        await client.get("/api/v1/health", headers=auth_header(await token(client)))
    ).json()
    names = {s["name"] for s in body["data"]["services"]}
    assert names == {"groq", "gemini", "abuseipdb", "virustotal", "database"}


# ---------------------------------------------------------------------------
# CONTRACT §9.5 — the per-user budget on the deep probe
# ---------------------------------------------------------------------------


async def test_health_deep_is_rate_limited_per_user(client: AsyncClient) -> None:
    """The global limiter is not what the contract specifies.

    It allows 120 requests a minute, which is right for reading alerts and
    wrong for a route that spends FOUR metered provider quotas per call: at
    that rate one operator holding the refresh button draws 480 provider calls
    a minute and exhausts the free tier before the demo starts. This is a
    second budget, keyed by user, on this route only.
    """
    from app.config import get_settings

    await make_user("deep-limit@example.com")
    token = await login(client, "deep-limit@example.com")

    allowed = int(get_settings().health_deep_calls_per_minute)
    statuses = []
    for _ in range(allowed + 3):
        statuses.append(
            (
                await client.get("/api/v1/health/deep", headers=auth_header(token))
            ).status_code
        )

    assert statuses[0] == 200, "the first call goes through"
    assert 429 in statuses, "and the burst does not"

    refused = next(
        s for s in reversed(statuses) if s == 429
    )
    assert refused == 429

    body = (
        await client.get("/api/v1/health/deep", headers=auth_header(token))
    ).json()
    assert body["error"]["code"] == "rate_limited"
    assert "four metered providers" in body["detail"]
    assert body["error"]["detail"]["retry_after_seconds"] > 0


async def test_the_deep_budget_is_per_user_not_global(client: AsyncClient) -> None:
    """One operator exhausting their budget must not lock out another."""
    from app.config import get_settings

    await make_user("deep-a@example.com")
    await make_user("deep-b@example.com")
    first = await login(client, "deep-a@example.com")
    second = await login(client, "deep-b@example.com")

    for _ in range(int(get_settings().health_deep_calls_per_minute) + 3):
        await client.get("/api/v1/health/deep", headers=auth_header(first))

    assert (
        await client.get("/api/v1/health/deep", headers=auth_header(first))
    ).status_code == 429
    assert (
        await client.get("/api/v1/health/deep", headers=auth_header(second))
    ).status_code == 200


async def test_the_cheap_health_endpoint_is_not_budgeted(client: AsyncClient) -> None:
    """`/health` is the 30-second poll's target and calls no provider."""
    await make_user("deep-cheap@example.com")
    token = await login(client, "deep-cheap@example.com")

    for _ in range(20):
        assert (
            await client.get("/api/v1/health", headers=auth_header(token))
        ).status_code == 200


async def test_health_deep_reports_the_phase_4_surfaces(client: AsyncClient) -> None:
    """What an operator has to be able to check before a demo.

    `rules_loaded` is the count actually IN THE ENGINE, not the row count in
    the database. A rule that exists and did not load changes nothing about any
    alert, and that gap is exactly what this number makes visible.
    """
    await make_user("deep-phase4@example.com")
    tok = await login(client, "deep-phase4@example.com")

    data = (
        await client.get("/api/v1/health/deep", headers=auth_header(tok))
    ).json()["data"]

    assert data["rules_loaded"] == 0, "PLAN I9 — no seeded rule, in any environment"
    assert data["scheduler"]["running"] is False, "disabled in the test env"
    assert sorted(data["scheduler"]["jobs"]) == [
        "correlation.refresh",
        "metrics.sample",
        "notifications.flush",
    ]
    # KNOWN is not SCHEDULED. `notifications.flush` only goes on a timer when
    # notifications are enabled, so a build that lists it and never runs it
    # must say so rather than implying the timer exists.
    assert data["scheduler"]["scheduled"] == []
    assert data["scheduler"]["playbooks_triggered"] == 0
    assert data["scheduler"]["playbook_failures"] == 0
    # PLAN §8 — the notification worker's state, for the pre-demo check.
    assert data["notifications"]["enabled"] is False
    assert data["notifications"]["sent"] == 0
    assert data["notifications"]["suppressed"] == 0
    assert data["notifications"]["failed"] == 0
