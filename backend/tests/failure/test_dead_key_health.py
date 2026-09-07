"""`/health/deep` distinguishes a DEAD key from a COOLING key. PLAN D39.

The two states need opposite operator responses — cooling is fixed by waiting,
dead is fixed only by provisioning a credential — so a health screen that
renders them the same tells the operator to do the one thing that cannot work.
These assert the distinction survives all the way to the payload.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.providers.keypool import KeyPool
from tests.conftest import auth_header, login, make_user

pytestmark = pytest.mark.failure


def pool(*purposes: str) -> KeyPool:
    return KeyPool(
        "gemini",
        {purpose: f"key-{purpose}" for purpose in purposes},
        default_cooldown_seconds=60.0,
    )


def test_the_snapshot_reports_dead_and_cooling_as_separate_facts() -> None:
    key_pool = pool("dev", "reserved", "spare")
    key_pool.mark_dead("gemini-dev", "403 project has been denied")
    key_pool.mark_rate_limited("gemini-reserved", 45.0)

    rows = {row["key_id"]: row for row in key_pool.snapshot()}

    dead = rows["gemini-dev"]
    assert dead["dead"] is True
    assert dead["cooling"] is False, (
        "a dead key is NOT cooling — it is not waiting for a window to reopen, "
        "and an amber 'rate limited' chip would tell an operator to wait for "
        "something that will never arrive"
    )
    assert dead["cooling_for_seconds"] == 0.0
    assert "denied" in dead["dead_reason"]

    cooling = rows["gemini-reserved"]
    assert cooling["dead"] is False
    assert cooling["cooling"] is True
    assert cooling["cooling_for_seconds"] > 0

    healthy = rows["gemini-spare"]
    assert healthy["dead"] is False and healthy["cooling"] is False

    assert key_pool.live == 2
    assert key_pool.dead_keys == {"gemini-dev": "403 project has been denied"}


def test_a_dead_key_never_comes_back_no_matter_how_long_you_wait() -> None:
    """Permanent means for the process lifetime, and `acquire` honours it."""
    key_pool = pool("dev", "reserved")
    key_pool.mark_dead("gemini-dev", "401 unauthenticated")

    for _ in range(20):
        assert key_pool.acquire().key_id == "gemini-reserved"

    rows = {row["key_id"]: row for row in key_pool.snapshot()}
    assert rows["gemini-dev"]["calls"] == 0, "it was never handed out again"


def test_the_registry_snapshot_carries_live_and_dead_counts() -> None:
    from app.config import get_settings
    from app.providers.registry import build_registry

    settings = get_settings().model_copy(
        update={
            "offline_mode": False,
            "groq_api_key_dev": "g1",
            "groq_api_key_reserved": "g2",
            "groq_api_key_spare": None,
            "gemini_api_key_dev": "m1",
            "gemini_api_key_reserved": "m2",
            "gemini_api_key_spare": "m3",
        }
    )
    registry = build_registry(settings)
    registry.gemini_pool.mark_dead("gemini-dev", "403 forbidden")
    registry.groq_pool.mark_rate_limited("groq-dev", 30.0)

    snapshot = registry.snapshot()

    assert snapshot["gemini"]["live_keys"] == 2
    assert snapshot["gemini"]["dead_keys"] == {"gemini-dev": "403 forbidden"}
    assert snapshot["groq"]["live_keys"] == 2, "a cooling key is still LIVE"
    assert snapshot["groq"]["dead_keys"] == {}

    # PLAN I16 — labels and counters only, never material.
    import json

    rendered = json.dumps(snapshot)
    for secret in ("g1", "g2", "m1", "m2", "m3"):
        assert f'"{secret}"' not in rendered


async def test_health_deep_surfaces_a_dead_key_as_dead(client: AsyncClient) -> None:
    """End to end: the flag reaches the payload an operator actually reads.

    A registry with real key LABELS is installed for the duration, because the
    suite's own registry has no keys at all — asserting against an empty pool
    would be a test that passes by having nothing to look at. Offline mode stays
    on, so no probe is issued: the per-key state comes from the pool rather than
    from a probe result, and must therefore be visible even when nothing was
    probed.
    """
    from app.config import get_settings
    from app.providers.registry import build_registry, reset_registry, set_registry

    await make_user("deadkey@example.com", role="analyst")
    token = await login(client, "deadkey@example.com")

    settings = get_settings().model_copy(
        update={
            "groq_api_key_dev": "groq-planted-secret",
            "gemini_api_key_dev": "gemini-planted-secret",
            "gemini_api_key_reserved": "gemini-planted-reserve",
        }
    )
    registry = build_registry(settings)
    set_registry(registry)
    try:
        registry.gemini_pool.mark_dead(
            "gemini-dev", "403 project has been denied access"
        )
        registry.gemini_pool.mark_rate_limited("gemini-reserved", 45.0)

        response = await client.get("/api/v1/health/deep", headers=auth_header(token))
        assert response.status_code == 200, response.text
        body = response.text
        providers = response.json()["data"]["providers"]
    finally:
        reset_registry()

    rows = {row["key_id"]: row for row in providers["gemini"]["keys"]}

    assert rows["gemini-dev"]["dead"] is True
    assert rows["gemini-dev"]["cooling"] is False, (
        "the screen must not render a revoked credential as amber 'rate limited'"
    )
    assert "denied" in rows["gemini-dev"]["dead_reason"]

    assert rows["gemini-reserved"]["dead"] is False
    assert rows["gemini-reserved"]["cooling"] is True

    assert providers["gemini"]["dead_keys"] == {
        "gemini-dev": "403 project has been denied access"
    }
    assert providers["gemini"]["live_keys"] == 1

    # PLAN I16 — the payload carries labels, never material.
    for secret in ("groq-planted-secret", "gemini-planted-secret"):
        assert secret not in body
