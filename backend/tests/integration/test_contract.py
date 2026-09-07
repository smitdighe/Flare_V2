"""Contract shape tests.

CONTRACT §1.3.1 — the pinned envelope exception list is closed. These assert
both halves: enveloped endpoints carry {ok,data,meta}, exception endpoints
carry a raw body the frozen frontend can read.
"""

from httpx import AsyncClient

from app.api.envelope import ENVELOPE_EXCEPTIONS
from tests.conftest import auth_header, login, make_user


def test_exception_list_is_the_eleven_from_the_contract() -> None:
    assert len(ENVELOPE_EXCEPTIONS) == 11, "the list is closed at 11 (CONTRACT §1.3.1)"
    assert ENVELOPE_EXCEPTIONS == frozenset(
        {
            "POST /auth/login",
            "POST /auth/register",
            "POST /auth/refresh",
            "GET /auth/me",
            "GET /rules",
            "GET /rules/alerts/{alert_id}/explain-rules",
            "GET /playbooks",
            "POST /playbooks/{playbook_id}/execute",
            "GET /playbooks/executions/{execution_id}",
            "GET /notifications/preferences",
            "GET /export/alerts/{format}",
        }
    )


async def test_enveloped_endpoint_has_ok_data_meta(client: AsyncClient) -> None:
    await make_user("env@example.com")
    token = await login(client, "env@example.com")

    response = await client.get("/api/v1/health", headers=auth_header(token))

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"ok", "data", "meta"}
    assert body["ok"] is True
    assert "services" in body["data"]

    # PLAN §11 / I2: measured with perf_counter, never a hardcoded 0.0.
    latency = body["meta"]["latency_ms"]
    assert isinstance(latency, (int, float))
    assert latency > 0, "latency_ms must be a real measurement"


def test_an_unmeasured_latency_is_absent_rather_than_zero() -> None:
    """PLAN §11 / I2 — the field is OMITTED when it was not measured.

    `latency_ms` used to return a literal 0.0 on this path while its own
    comment claimed it reported nothing, so `meta.latency_ms` would have
    rendered as a measured zero milliseconds. Absent means "not measured" and
    cannot be misread as a number; this is the same convention `cost_usd`
    follows on the eval payload.

    Reachable only when the timing middleware did not run, which is why this is
    asserted against a bare request rather than over HTTP.
    """
    from types import SimpleNamespace

    from app.api.envelope import envelope, latency_ms

    unmeasured = SimpleNamespace(state=SimpleNamespace())

    assert latency_ms(unmeasured) is None
    body = envelope({"x": 1}, unmeasured)
    assert body["meta"] == {}, "no fabricated value, and no null to render"
    assert "latency_ms" not in body["meta"]
    assert body["ok"] is True and body["data"] == {"x": 1}


async def test_pinned_exception_endpoints_are_not_enveloped(
    client: AsyncClient,
) -> None:
    await make_user("raw@example.com")

    login_body = (
        await client.post(
            "/api/v1/auth/login",
            json={"email": "raw@example.com", "password": "Password123!"},
        )
    ).json()
    assert "ok" not in login_body
    assert "access_token" in login_body

    me_body = (
        await client.get(
            "/api/v1/auth/me", headers=auth_header(login_body["access_token"])
        )
    ).json()
    assert "ok" not in me_body
    assert "data" not in me_body
    assert "email" in me_body


async def test_error_body_carries_both_shapes(client: AsyncClient) -> None:
    """CONTRACT §1.4 — flat `detail` for the frozen frontend, plus `error`."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "absent@example.com", "password": "Password123!"},
    )
    body = response.json()
    assert body["ok"] is False
    assert isinstance(body["detail"], str) and body["detail"]
    assert set(body["error"]) == {"code", "message", "detail"}
    assert body["error"]["message"] == body["detail"]


async def test_health_reports_providers_as_never_probed(client: AsyncClient) -> None:
    """Cheap /health never calls a provider, so nothing may claim "ok"."""
    await make_user("probe@example.com")
    token = await login(client, "probe@example.com")

    body = (
        await client.get("/api/v1/health", headers=auth_header(token))
    ).json()
    services = {s["name"]: s for s in body["data"]["services"]}

    for name in ("groq", "gemini", "abuseipdb", "virustotal"):
        assert services[name]["status"] == "unknown", f"{name} was never probed"
        assert services[name]["latency_ms"] is None
        assert services[name]["checked_at"] is None

    # The database is local, so it IS genuinely checked.
    assert services["database"]["status"] == "ok"
    assert services["database"]["latency_ms"] > 0


async def test_request_id_is_echoed_when_safe(client: AsyncClient) -> None:
    await make_user("rid@example.com")
    token = await login(client, "rid@example.com")

    response = await client.get(
        "/api/v1/health",
        headers={**auth_header(token), "X-Request-ID": "abc-123_XYZ.4"},
    )
    assert response.headers["X-Request-ID"] == "abc-123_XYZ.4"


async def test_malicious_request_id_is_not_echoed(client: AsyncClient) -> None:
    """PLAN §9 — a client-supplied id reaches a log file; log injection."""
    await make_user("evil@example.com")
    token = await login(client, "evil@example.com")

    forged = 'x"}\n{"level":"CRITICAL","msg":"forged'
    response = await client.get(
        "/api/v1/health", headers={**auth_header(token), "X-Request-ID": forged}
    )
    echoed = response.headers["X-Request-ID"]
    assert echoed != forged
    assert "\n" not in echoed
    assert len(echoed) == 32, "replaced with a fresh uuid4 hex"
