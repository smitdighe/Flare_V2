"""RBAC negatives.

PLAN §9 / §12: no test here may codify a security hole as intended behaviour.
The prior codebase's suite asserted that a viewer *could* list users; these
assert the opposite, which is the point.
"""

from datetime import UTC

import pytest
from httpx import AsyncClient

from tests.conftest import auth_header, login, make_user


@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_non_admin_is_denied_admin_route(client: AsyncClient, role: str) -> None:
    await make_user(f"{role}@example.com", role=role)
    token = await login(client, f"{role}@example.com")

    response = await client.get("/api/v1/admin/users", headers=auth_header(token))

    assert response.status_code == 403, f"{role} must NOT reach an admin route"
    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "forbidden"
    assert body["detail"] == "You do not have permission to perform this action."
    assert "users" not in body, "no data leaks in the denial body"


async def test_admin_is_allowed_admin_route(client: AsyncClient) -> None:
    await make_user("boss@example.com", role="admin")
    await make_user("peon@example.com", role="viewer")
    token = await login(client, "boss@example.com")

    response = await client.get("/api/v1/admin/users", headers=auth_header(token))

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    emails = {u["email"] for u in body["data"]["users"]}
    assert emails == {"boss@example.com", "peon@example.com"}


async def test_unauthenticated_is_denied_admin_route(client: AsyncClient) -> None:
    response = await client.get("/api/v1/admin/users")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


async def test_forged_role_claim_does_not_grant_admin(client: AsyncClient) -> None:
    """The role in the JWT is not trusted — the DB row is authoritative.

    A token can be re-signed only with the secret, but even holding it, the
    claim must not be what the guard reads.
    """
    from datetime import datetime, timedelta

    import jwt

    from app.config import get_settings

    user_id = await make_user("liar@example.com", role="viewer")
    settings = get_settings()
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(user_id),
            "type": "access",
            "role": "admin",  # forged
            "tv": 1,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=30)).timestamp()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    response = await client.get("/api/v1/admin/users", headers=auth_header(token))
    assert response.status_code == 403, "role comes from the database, not the claim"


async def test_no_jwt_accepted_in_query_string(client: AsyncClient) -> None:
    """PLAN §9 — a token in a query string lands in access logs and history."""
    await make_user("query@example.com", role="admin")
    token = await login(client, "query@example.com")

    response = await client.get(f"/api/v1/admin/users?token={token}")
    assert response.status_code == 401, "the query parameter must not authenticate"


async def test_health_requires_authentication(client: AsyncClient) -> None:
    """PLAN §9 — an anonymous health endpoint burned four quotas per hit."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 401
