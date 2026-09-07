"""Demo seed gating.

CONTRACT §8.7 / PLAN §9: admin@flare.dev / admin123 exists ONLY under
--demo-seed. On a default boot the account does not exist and the frontend's
"Quick demo sign in" button 401s. That is intended behaviour, not a bug.
"""

from httpx import AsyncClient

from app.config import get_settings
from scripts.seed_demo import DEMO_EMAIL, DEMO_PASSWORD, seed


async def test_demo_account_absent_on_default_boot(client: AsyncClient) -> None:
    assert get_settings().demo_seed_enabled is False

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
    )

    assert response.status_code == 401, "the demo account must not exist by default"
    assert response.json()["detail"] == "Incorrect email or password."


async def test_demo_account_present_after_explicit_seed(client: AsyncClient) -> None:
    await seed()

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == DEMO_EMAIL
    assert body["user"]["role"] == "admin"


async def test_seed_is_idempotent(client: AsyncClient) -> None:
    await seed()
    await seed()

    token = (
        await client.post(
            "/api/v1/auth/login",
            json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
        )
    ).json()["access_token"]

    users = (
        await client.get(
            "/api/v1/admin/users", headers={"Authorization": f"Bearer {token}"}
        )
    ).json()["data"]["users"]

    assert [u["email"] for u in users].count(DEMO_EMAIL) == 1
