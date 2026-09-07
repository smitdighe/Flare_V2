from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _enable_sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:
    """WAL plus a busy timeout.

    PLAN T10/D1: the prior codebase used journal_mode=DELETE with per-alert
    commits, and `database is locked` killed the stream. WAL lets readers run
    while a writer holds the write lock; busy_timeout stops a concurrent writer
    failing instantly instead of waiting its turn.
    """
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            future=True,
            pool_pre_ping=True,
        )
        if _engine.dialect.name == "sqlite":
            event.listen(_engine.sync_engine, "connect", _enable_sqlite_pragmas)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            get_engine(), expire_on_commit=False, autoflush=False
        )
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session


async def verify_schema() -> None:
    """Assert Alembic has run.

    PLAN D18: Alembic is the only schema authority. There is no create_all in
    this codebase — not at startup, not in tests, not anywhere. If the tables
    are missing the answer is `alembic upgrade head`, and saying so beats
    failing later with a confusing query error.
    """
    engine = get_engine()
    async with engine.connect() as conn:
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'")
        )
        if result.first() is None:
            raise RuntimeError(
                "Database schema is not initialised. Run: alembic upgrade head"
            )


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
