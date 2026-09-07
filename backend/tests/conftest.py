"""Test bootstrap.

PLAN I10 / T6: pytest must never be able to touch the runtime database. A prior
repo's conftest ran drop_all against whatever DATABASE_URL happened to be set,
so a single test run wiped the demo data.

Two defences, both below, and both BEFORE any app import:
  1. Environment is rewritten to a tmp file per session, so there is nothing
     shared to drop.
  2. `_assert_not_runtime_db` refuses to run at all if the resolved URL looks
     like a real database.

There is no drop_all and no create_all anywhere in this suite. Schema comes
from Alembic (PLAN D18) — the same path production uses.
"""

import os
import tempfile
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# MUST run before `app` is imported anywhere. get_settings() is lru_cached, so
# whatever is in os.environ at first call is what the whole session uses.
# ---------------------------------------------------------------------------
_TMP_DIR = Path(tempfile.mkdtemp(prefix="flare-test-"))
_TEST_DB_PATH = _TMP_DIR / f"test-{uuid.uuid4().hex}.db"

_FORBIDDEN_DB_NAMES = ("flare.db", "prod.db", "production.db")

os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DB_PATH.as_posix()}"
os.environ["JWT_SECRET"] = "test-secret-not-used-in-any-real-environment-000000"
os.environ["ENVIRONMENT"] = "test"
os.environ["DEMO_SEED_ENABLED"] = "false"
os.environ["LOG_LEVEL"] = "WARNING"
# High enough that functional tests never trip it; the limiter has its own test.
os.environ["RATE_LIMIT_REQUESTS"] = "10000"
# The replay loop is started explicitly by the tests that exercise it; an
# autostarted background task would race the per-test table truncation.
os.environ["REPLAY_AUTOSTART"] = "false"
# Hermetic: the suite must never read the developer's .env. Without this a
# local .env carrying real provider keys changes test behaviour, and CI and a
# workstation stop agreeing about what passes.
os.environ["FLARE_DISABLE_ENV_FILE"] = "1"
# PLAN §10.3 fails a provider closed when its key pool is empty, and the suite
# has no keys by design. Offline mode is the DECLARED way to run without them,
# so the app starts, every alert is marked degraded, and no test can reach the
# network by accident. Tests that exercise a provider path build their own
# registry with fake pools and stubbed clients (tests/unit/test_providers.py).
os.environ["OFFLINE_MODE"] = "true"
# PLAN §4.1's scheduler runs background jobs against the database. Left on, its
# ticks race the per-test truncation below and a test's assertions would depend
# on whether a timer happened to fire. The scheduler tests start it explicitly.
os.environ["SCHEDULER_ENABLED"] = "false"


def _assert_not_runtime_db(url: str) -> None:
    lowered = url.lower()
    if any(name in lowered for name in _FORBIDDEN_DB_NAMES):
        raise RuntimeError(
            f"Refusing to run tests against what looks like a runtime database: {url}"
        )
    if str(_TMP_DIR.as_posix()) not in url:
        raise RuntimeError(
            f"Test database escaped the temp directory: {url}"
        )


_assert_not_runtime_db(os.environ["DATABASE_URL"])

# Imports below this line are safe: the environment is already pinned.
from alembic.config import Config  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from alembic import command  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.security.hashing import hash_password  # noqa: E402
from app.store.models import User  # noqa: E402
from app.store.session import dispose_engine, get_sessionmaker  # noqa: E402

BACKEND_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def _migrate() -> Iterator[None]:
    """Bring the schema up with Alembic — the same path production uses."""
    _assert_not_runtime_db(get_settings().database_url)

    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    command.upgrade(cfg, "head")
    yield
    # The whole directory is temporary; nothing to drop, nothing to wipe.


@pytest.fixture(autouse=True)
async def _clean_tables() -> AsyncIterator[None]:
    """Truncate between tests.

    DELETE against the temp database only — never drop_all, and never against a
    URL that survived the guard above.
    """
    yield
    from sqlalchemy import text

    async with get_sessionmaker()() as session:
        # Child tables first: `alerts` and `users` are referenced by the Phase 4
        # tables, and PRAGMA foreign_keys is ON.
        for table in (
            "job_runs",
            "metric_samples",
            "alert_clusters",
            "notification_log",
            "notification_preferences",
            "playbook_executions",
            "playbooks",
            "rules",
            "audit_log",
            "alerts",
            "users",
        ):
            await session.execute(text(f"DELETE FROM {table}"))  # noqa: S608
        await session.commit()

    # The rule engine and the per-user budgets are process-level singletons.
    # Left in place they carry one test's rules or one test's spent tokens into
    # the next, which is the kind of order-dependent failure that only shows up
    # in CI.
    from app.core.health_state import reset_health_cache
    from app.core.user_rate_limit import reset_limiters
    from app.notifications.dispatcher import reset_dispatcher
    from app.notifications.presence import reset_presence
    from app.providers.registry import reset_registry
    from app.rules.engine import reset_rule_engine

    reset_rule_engine()
    reset_limiters()
    # The health cache and the provider registry are process-level singletons
    # too. A /health/deep call in one test recorded a probe result and a
    # `checked_at` timestamp that the next test read as "this provider has been
    # probed" — an order-dependent failure that only appears once the suite is
    # run whole, which is to say only in CI.
    reset_health_cache()
    reset_registry()
    # PLAN §8.2 — presence and the dispatcher's debounce windows are
    # process-level singletons. A connection left registered by one test would
    # suppress another test's notification, which is the exact assertion this
    # phase exists to make.
    reset_presence()
    reset_dispatcher()


@pytest.fixture(scope="session", autouse=True)
def _dispose() -> Iterator[None]:
    # Synchronous on purpose: a session-scoped async fixture would need a
    # session-scoped event loop, while every test runs on its own function
    # loop. Disposing from a throwaway loop at teardown avoids that mismatch.
    yield
    import asyncio

    asyncio.run(dispose_engine())


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    from app.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test"
    ) as async_client:
        yield async_client


async def make_user(
    email: str,
    password: str = "Password123!",
    role: str = "viewer",
    name: str = "Test User",
) -> int:
    async with get_sessionmaker()() as session:
        user = User(
            email=email.lower(),
            name=name,
            password_hash=hash_password(password),
            role=role,
        )
        session.add(user)
        await session.commit()
        return user.id


async def login(client: AsyncClient, email: str, password: str = "Password123!") -> str:
    response = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
