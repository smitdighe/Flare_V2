"""Rate limiter boundary.

PLAN §9 / CONTRACT §1.5: inbound limiting returns a REAL 429 as a JSONResponse,
never a 500, and CORS is registered last so the rejection still carries CORS
headers — without them a browser cannot read the body and the frontend shows a
generic network error instead of the real reason.

The suite raises the limit globally so functional tests never trip it; this
module builds its own app with a low limit instead of touching that.
"""

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from httpx import ASGITransport, AsyncClient

from app.api.errors import register_exception_handlers
from app.api.router import api_router
from app.core.middleware import RateLimitMiddleware, RequestContextMiddleware

LIMIT = 3
ORIGIN = "http://localhost:5174"


def build_limited_app(limit: int = LIMIT, window: int = 60) -> FastAPI:
    """Same middleware order as app.main.create_app, with a low limit."""
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(api_router)

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(RateLimitMiddleware, limit=limit, window_seconds=window)
    # LAST = outermost, so it wraps the limiter's 429 too.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[ORIGIN],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )
    return app


@pytest.fixture
async def limited_client() -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=build_limited_app())
    async with AsyncClient(
        transport=transport, base_url="http://test", headers={"Origin": ORIGIN}
    ) as client:
        yield client


async def test_requests_under_the_limit_are_not_rejected(
    limited_client: AsyncClient,
) -> None:
    for index in range(LIMIT):
        response = await limited_client.get("/api/v1/health")
        assert response.status_code != 429, f"request {index + 1} of {LIMIT} was limited"


async def test_crossing_the_limit_returns_a_real_429(
    limited_client: AsyncClient,
) -> None:
    for _ in range(LIMIT):
        await limited_client.get("/api/v1/health")

    response = await limited_client.get("/api/v1/health")

    assert response.status_code == 429, "must be 429, never 500"

    body = response.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "rate_limited"
    assert body["detail"] == "Too many requests. Please slow down."
    assert body["error"]["detail"]["retry_after_seconds"] >= 1


async def test_429_carries_retry_after_header(limited_client: AsyncClient) -> None:
    for _ in range(LIMIT):
        await limited_client.get("/api/v1/health")

    response = await limited_client.get("/api/v1/health")

    assert response.status_code == 429
    retry_after = response.headers.get("Retry-After")
    assert retry_after is not None, "Retry-After must be present on a 429"
    assert retry_after.isdigit()
    assert 1 <= int(retry_after) <= 60


async def test_429_carries_cors_headers(limited_client: AsyncClient) -> None:
    """CORS is registered last precisely so this holds.

    Registered first, the browser could not read the 429 body and the frontend
    would surface "Cannot reach the server" instead of the real reason.
    """
    for _ in range(LIMIT):
        await limited_client.get("/api/v1/health")

    response = await limited_client.get("/api/v1/health")

    assert response.status_code == 429
    assert response.headers.get("access-control-allow-origin") == ORIGIN


async def test_limiter_keys_separate_callers_independently() -> None:
    """A limited caller must not lock out everyone else.

    Distinct bearer tokens are distinct buckets; the limiter keys on the token
    when present rather than a shared proxy IP (PLAN §9).
    """
    transport = ASGITransport(app=build_limited_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(LIMIT + 1):
            await client.get("/api/v1/health", headers={"Authorization": "Bearer aaa"})

        blocked = await client.get(
            "/api/v1/health", headers={"Authorization": "Bearer aaa"}
        )
        other = await client.get(
            "/api/v1/health", headers={"Authorization": "Bearer bbb"}
        )

    assert blocked.status_code == 429
    assert other.status_code != 429, "a second caller has its own bucket"


async def test_limiter_runs_before_authentication() -> None:
    """The 429 must not require a valid token.

    An unauthenticated flood is exactly what the limiter is for, so it has to
    reject before auth rather than after.
    """
    transport = ASGITransport(app=build_limited_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        codes = [
            (await client.get("/api/v1/health")).status_code
            for _ in range(LIMIT + 2)
        ]

    assert codes[0] == 401, "unauthenticated but under the limit"
    assert codes[-1] == 429, "over the limit, still unauthenticated"
