from datetime import UTC, datetime, timedelta

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.config import get_settings
from app.store.models import AuditLog
from app.store.session import get_sessionmaker
from tests.conftest import auth_header, login, make_user


async def test_register_returns_raw_token_pair(client: AsyncClient) -> None:
    """PINNED ENVELOPE EXCEPTION — CONTRACT §1.3.1 #2.

    AuthContext.jsx:171 reads data.access_token off the top level.
    """
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "New@Example.com", "name": "New User", "password": "Password123!"},
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert "ok" not in body, "register must NOT be enveloped"
    assert set(body) == {"access_token", "refresh_token", "token_type", "user"}
    assert body["token_type"] == "bearer"

    user = body["user"]
    assert set(user) == {"id", "email", "name", "role", "created_at"}
    assert user["email"] == "new@example.com", "email is normalised to lowercase"
    assert user["name"] == "New User"
    assert user["role"] == "viewer", "PLAN §9: role defaults to viewer"


async def test_register_rejects_client_supplied_role(client: AsyncClient) -> None:
    """PLAN §9 — the one-HTTP-call self-promotion hole must not exist."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "climber@example.com",
            "name": "Climber",
            "password": "Password123!",
            "role": "admin",
        },
    )
    assert response.status_code == 422, "an unknown field is rejected, not ignored"

    # And no account was created as a side effect.
    follow_up = await client.post(
        "/api/v1/auth/login",
        json={"email": "climber@example.com", "password": "Password123!"},
    )
    assert follow_up.status_code == 401


async def test_register_duplicate_email_conflicts(client: AsyncClient) -> None:
    await make_user("dupe@example.com")
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "dupe@example.com", "name": "Dupe", "password": "Password123!"},
    )
    assert response.status_code == 409
    body = response.json()
    assert body["ok"] is False
    assert body["detail"] == "An account with this email already exists."
    assert body["error"]["code"] == "email_taken"


async def test_register_rejects_short_password(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "short@example.com", "name": "Short", "password": "abc"},
    )
    assert response.status_code == 422


async def test_login_success_and_access_token_is_30_minutes(
    client: AsyncClient,
) -> None:
    """PLAN §3.1 — the login panel's "jwt · 30m access" must be literally true."""
    await make_user("agent@example.com", role="analyst")
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "agent@example.com", "password": "Password123!"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "ok" not in body, "login must NOT be enveloped"
    assert body["user"]["role"] == "analyst"

    settings = get_settings()
    claims = jwt.decode(
        body["access_token"], settings.jwt_secret, algorithms=[settings.jwt_algorithm]
    )
    lifetime = claims["exp"] - claims["iat"]
    assert lifetime == 30 * 60, f"access token lives {lifetime}s, panel claims 1800s"
    assert claims["type"] == "access"

    refresh_claims = jwt.decode(
        body["refresh_token"], settings.jwt_secret, algorithms=[settings.jwt_algorithm]
    )
    assert refresh_claims["exp"] - refresh_claims["iat"] == 7 * 24 * 3600
    assert refresh_claims["type"] == "refresh"


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("ghost@example.com", "Password123!"),
        ("real@example.com", "WrongPassword1!"),
    ],
)
async def test_login_failure_is_401_with_detail(
    client: AsyncClient, email: str, password: str
) -> None:
    await make_user("real@example.com")
    response = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 401
    body = response.json()
    assert body["detail"] == "Incorrect email or password."
    assert body["error"]["code"] == "invalid_credentials"
    # PLAN §9 / §12 — this was `"password" not in text or "Password" not in
    # detail`, which passes as soon as either half holds and so could not fail
    # on a body that echoed the submitted credential in the other casing.
    #
    # Two decisive properties replace it. The message NAMING both possibilities
    # ("email or password") is correct and is what stops it being an enumeration
    # oracle — the parametrisation covers an unknown account and a wrong
    # password, and both reach this identical string.
    assert body["detail"] == "Incorrect email or password.", (
        "an unknown account and a wrong password must be indistinguishable"
    )
    # And nothing the client SENT comes back in any casing.
    lowered = response.text.lower()
    assert password.lower() not in lowered, "the submitted password was echoed"
    assert email.split("@")[0].lower() not in lowered, (
        "the submitted account name was echoed"
    )


async def test_failed_login_is_audited(client: AsyncClient) -> None:
    """PLAN §4.1 — failed logins are written to the audit log."""
    await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "Password123!"},
    )
    async with get_sessionmaker()() as session:
        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.action == "auth.login_failed")))
            .scalars()
            .all()
        )
    assert len(rows) == 1
    entry = rows[0]
    assert entry.details is not None
    assert entry.details["email"] == "nobody@example.com"
    assert entry.details["reason"] == "invalid_credentials"
    assert "password" not in str(entry.details), "the password is never recorded"


async def test_me_returns_whole_body_unenveloped(client: AsyncClient) -> None:
    """PINNED ENVELOPE EXCEPTION — CONTRACT §1.3.1 #4 (setUser(data))."""
    await make_user("me@example.com", role="admin", name="Me Myself")
    token = await login(client, "me@example.com")

    response = await client.get("/api/v1/auth/me", headers=auth_header(token))
    assert response.status_code == 200
    body = response.json()
    assert "ok" not in body and "data" not in body
    assert set(body) == {"id", "email", "name", "role", "created_at"}
    assert body["email"] == "me@example.com"
    assert body["name"] == "Me Myself"
    assert body["role"] == "admin"


async def test_me_requires_authentication(client: AsyncClient) -> None:
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


async def test_refresh_rotates_and_rejects_access_token(client: AsyncClient) -> None:
    await make_user("rot@example.com")
    login_body = (
        await client.post(
            "/api/v1/auth/login",
            json={"email": "rot@example.com", "password": "Password123!"},
        )
    ).json()

    ok = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": login_body["refresh_token"]}
    )
    assert ok.status_code == 200
    assert "ok" not in ok.json(), "refresh must NOT be enveloped"
    assert ok.json()["access_token"]

    # An access token must never work as a refresh token.
    misuse = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": login_body["access_token"]}
    )
    assert misuse.status_code == 401
    assert misuse.json()["error"]["code"] == "invalid_token"


async def test_expired_access_token_is_rejected(client: AsyncClient) -> None:
    user_id = await make_user("stale@example.com")
    settings = get_settings()
    past = datetime.now(UTC) - timedelta(hours=2)
    expired = jwt.encode(
        {
            "sub": str(user_id),
            "type": "access",
            "role": "viewer",
            "tv": 1,
            "iat": int(past.timestamp()),
            "exp": int((past + timedelta(minutes=30)).timestamp()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    response = await client.get("/api/v1/auth/me", headers=auth_header(expired))
    assert response.status_code == 401
    assert response.json()["detail"] == "Token has expired"


async def test_token_signed_with_wrong_secret_is_rejected(client: AsyncClient) -> None:
    user_id = await make_user("forged@example.com")
    forged = jwt.encode(
        {
            "sub": str(user_id),
            "type": "access",
            "role": "admin",
            "tv": 1,
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=30)).timestamp()),
        },
        "a-completely-different-secret-000000000000",
        algorithm="HS256",
    )
    response = await client.get("/api/v1/auth/me", headers=auth_header(forged))
    assert response.status_code == 401


async def test_change_password_invalidates_refresh_tokens(client: AsyncClient) -> None:
    """PLAN §9 — a password change invalidates outstanding refresh tokens."""
    await make_user("rotate@example.com")
    tokens = (
        await client.post(
            "/api/v1/auth/login",
            json={"email": "rotate@example.com", "password": "Password123!"},
        )
    ).json()

    changed = await client.post(
        "/api/v1/auth/change-password",
        headers=auth_header(tokens["access_token"]),
        json={"current_password": "Password123!", "new_password": "BrandNew456!"},
    )
    assert changed.status_code == 200
    body = changed.json()
    assert body["ok"] is True, "change-password IS enveloped"
    assert body["data"]["detail"] == "Password changed"

    stale = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert stale.status_code == 401, "the old refresh token must be dead"

    old_creds = await client.post(
        "/api/v1/auth/login",
        json={"email": "rotate@example.com", "password": "Password123!"},
    )
    assert old_creds.status_code == 401

    new_creds = await client.post(
        "/api/v1/auth/login",
        json={"email": "rotate@example.com", "password": "BrandNew456!"},
    )
    assert new_creds.status_code == 200


async def test_change_password_wrong_current_is_rejected(client: AsyncClient) -> None:
    await make_user("keeper@example.com")
    token = await login(client, "keeper@example.com")
    response = await client.post(
        "/api/v1/auth/change-password",
        headers=auth_header(token),
        json={"current_password": "NotMyPassword1!", "new_password": "Whatever123!"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Current password is incorrect."


async def test_profile_update_cannot_change_role(client: AsyncClient) -> None:
    """PLAN §9 — no route accepts a client-supplied role."""
    await make_user("profile@example.com", role="viewer")
    token = await login(client, "profile@example.com")

    response = await client.put(
        "/api/v1/auth/profile",
        headers=auth_header(token),
        json={"name": "Renamed", "email": "profile@example.com", "role": "admin"},
    )
    assert response.status_code == 422, "role is an unknown field and is rejected"

    me = await client.get("/api/v1/auth/me", headers=auth_header(token))
    assert me.json()["role"] == "viewer"


async def test_profile_update_succeeds_and_is_enveloped(client: AsyncClient) -> None:
    await make_user("rename@example.com")
    token = await login(client, "rename@example.com")

    response = await client.put(
        "/api/v1/auth/profile",
        headers=auth_header(token),
        json={"name": "Renamed Person", "email": "renamed@example.com"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["data"]["name"] == "Renamed Person"
    assert body["data"]["email"] == "renamed@example.com"
    assert body["data"]["role"] == "viewer"


async def test_stale_token_version_is_rejected(client: AsyncClient) -> None:
    """The counter, not a timestamp, is what invalidates a token.

    JWT `iat` is second-granular, so a token minted in the same second as a
    password change would survive a timestamp comparison. This asserts the
    access token dies too, not just the refresh token.
    """
    await make_user("bump@example.com")
    tokens = (
        await client.post(
            "/api/v1/auth/login",
            json={"email": "bump@example.com", "password": "Password123!"},
        )
    ).json()
    access = tokens["access_token"]

    before = await client.get("/api/v1/auth/me", headers=auth_header(access))
    assert before.status_code == 200

    changed = await client.post(
        "/api/v1/auth/change-password",
        headers=auth_header(access),
        json={"current_password": "Password123!", "new_password": "Rotated456!"},
    )
    assert changed.status_code == 200

    after = await client.get("/api/v1/auth/me", headers=auth_header(access))
    assert after.status_code == 401, "the access token must die with the password"
    assert after.json()["error"]["code"] == "unauthorized"
