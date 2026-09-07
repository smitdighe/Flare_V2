import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.agent.budget import reset_reason_budget
from app.api.errors import register_exception_handlers
from app.api.router import build_api_router
from app.config import get_settings
from app.core.logging import configure_logging
from app.core.middleware import RateLimitMiddleware, RequestContextMiddleware
from app.ingestion.feed import get_feed
from app.ingestion.live import get_live_ingest
from app.intel.aggregator import load_aggregator
from app.ml.classifier import load_classifier
from app.notifications.dispatcher import get_dispatcher
from app.providers.registry import load_registry
from app.rag.retriever import load_retriever
from app.rules.store import refresh_rule_engine
from app.store.session import dispose_engine, get_sessionmaker, verify_schema
from app.workers.scheduler import start_scheduler, stop_scheduler

logger = logging.getLogger("flare.app")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)

    # PLAN D18: Alembic is the only schema authority. There is no create_all
    # here or anywhere else — this asserts the migrations have run and fails
    # loudly with the command to fix it if they have not.
    await verify_schema()

    # PLAN §4.3 — the fast tier loads HERE so a missing, corrupt or
    # schema-mismatched artifact stops the server, rather than being discovered
    # on the first alert. It does not fall through to an LLM and it does not
    # fall through to a default.
    classifier = load_classifier()
    retriever = load_retriever()

    # PLAN §10.3 — a provider enabled with an empty key pool fails CLOSED here.
    # Discovering it on the first alert means discovering it in front of an
    # audience; offline mode is the declared way to run without keys.
    registry = load_registry(settings)
    load_aggregator(settings)
    reset_reason_budget(settings.reason_calls_per_minute)

    logger.info(
        "models loaded",
        extra={
            "request_id": "-",
            "classifier_version": classifier.model_version,
            "index_chunks": retriever.chunk_count,
            # PLAN I16 — model IDs and key COUNTS. Never key material.
            "groq_model": registry.groq.model,
            "gemini_model": registry.gemini.model,
            "groq_keys": len(registry.groq_pool),
            "gemini_keys": len(registry.gemini_pool),
        },
    )
    if settings.offline_mode:
        # PLAN §10.4 / E9 — declared and labelled, never silent.
        logger.warning(
            "OFFLINE MODE is on. No provider is called; every alert is marked "
            "degraded and its trace names 'offline' as the provider.",
            extra={"request_id": "-"},
        )

    logger.info(
        "startup",
        extra={"request_id": "-"},
    )
    if settings.demo_seed_enabled:
        # PLAN §9 / CONTRACT §8.7: loud, because these credentials are public in
        # the shipped frontend bundle.
        logger.warning(
            "demo seed ENABLED - admin@flare.dev exists. Never enable in prod.",
            extra={"request_id": "-"},
        )
    # PLAN D33 / Phase 4 — the rule set is loaded from storage ONCE here and
    # rebuilt after every rule write. The rules node reads the in-memory engine,
    # so a rule that is not loaded exists in the database and changes nothing
    # about any alert.
    async with get_sessionmaker()() as session:
        engine = await refresh_rule_engine(session)
    logger.info(
        "rules loaded", extra={"request_id": "-", "rules": len(engine)}
    )

    # PLAN §8 — the notification worker starts BEFORE the feed so no alert can
    # be emitted before there is anything to consume it. Config has already
    # failed closed if the feature is on without SMTP credentials, so reaching
    # here with it enabled means the transport is configured.
    dispatcher = get_dispatcher()
    await dispatcher.start()
    if settings.notifications_enabled:
        logger.info(
            "notifications enabled",
            extra={
                "request_id": "-",
                # I16 — the host and the sender identity, never the password.
                "smtp_host": settings.smtp_host,
                "smtp_port": settings.smtp_port,
                "sender": settings.smtp_from,
                "severities": settings.notify_severities,
                "debounce_seconds": settings.notification_debounce_seconds,
                "presence_stale_seconds": settings.presence_stale_seconds,
            },
        )

    # PLAN §10 / T4: ONE replay loop per server, not one per connection.
    if settings.replay_autostart:
        await get_feed().start()

    # PLAN D23 / §4.4a / I19 — the live lane, on its own task and its own
    # queue. Started AFTER replay and independently of it: replay is the
    # load-bearing path and must be up whether or not this is. Off by default;
    # `live_ingest_enabled` also gates whether the route exists at all.
    if settings.live_ingest_enabled:
        await get_live_ingest().start()
        logger.warning(
            "LIVE INGEST enabled - POST /ingest/eve is mounted and accepts "
            "external input. Replay is unaffected either way (PLAN I19).",
            extra={"request_id": "-"},
        )

    # PLAN §4.1 — APScheduler. Started AFTER the feed so the first correlation
    # refresh sees whatever is already persisted, and started last so a
    # scheduler failure cannot stop the API coming up.
    await start_scheduler(settings)

    yield

    await stop_scheduler()
    await get_live_ingest().stop()
    await get_feed().stop()
    await dispatcher.stop()
    await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Flare Backend v2",
        version="2.0.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "prod" else None,
        redoc_url=None,
    )

    register_exception_handlers(app)
    # Built here, not imported as a constant: the live-ingest route is
    # conditional on `live_ingest_enabled` and must reflect the settings
    # this app is being created with (PLAN §4.4a).
    app.include_router(build_api_router())

    # Starlette runs middleware in reverse registration order: the LAST added is
    # the OUTERMOST. CORS is therefore added last so it wraps everything,
    # including the 429 from the rate limiter and every error handler response
    # (PLAN §3.2/§9). Registered first, a browser could not read the body of any
    # error response.
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        limit=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )

    return app


app = create_app()
