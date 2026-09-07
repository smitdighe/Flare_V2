import asyncio
from logging.config import fileConfig

from sqlalchemy.engine import Connection

from alembic import context
from app.config import get_settings
from app.store.models import Base
from app.store.session import get_engine

config = context.config
if config.config_file_name is not None:
    # `disable_existing_loggers` defaults to True, and that default is a real
    # bug whenever a migration runs IN-PROCESS with the app — the test suite,
    # and the cold-clone smoke test that migrates then boots. It walks every
    # logger already created and sets `disabled = True`, so `flare.providers`,
    # `flare.eval` and every other application logger go silent for the rest of
    # the process. The D39 dead-key line is specified to be startup-visible and
    # would have been swallowed exactly there. Alembic's own loggers are still
    # configured from the ini; nothing else is touched.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _url() -> str:
    return get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite cannot ALTER most things in place; batch mode rewrites the
        # table instead, so later phases can add columns without hand-written
        # table copies.
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = get_engine()
    async with engine.connect() as connection:
        await connection.run_sync(_do_run)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
