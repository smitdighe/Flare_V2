from fastapi import APIRouter

from app.api.routes import (
    admin,
    alerts,
    audit,
    auth,
    eval,
    export,
    health,
    health_deep,
    ingest,
    metrics,
    notifications,
    playbooks,
    rules,
    stream,
)
from app.config import get_settings

API_PREFIX = "/api/v1"


def build_api_router() -> APIRouter:
    """Assemble the router from CURRENT settings.

    A function rather than a module-level constant because one route is
    conditional (see below) and a constant would pin the toggle to whatever it
    was at first import — which in a test suite is whatever the first test to
    import this module happened to set.
    """
    router = APIRouter(prefix=API_PREFIX)
    router.include_router(auth.router)
    router.include_router(health.router)
    router.include_router(health_deep.router)
    router.include_router(alerts.router)
    router.include_router(metrics.router)
    router.include_router(eval.router)
    router.include_router(audit.router)
    router.include_router(rules.router)
    router.include_router(playbooks.router)
    router.include_router(notifications.router)
    router.include_router(export.router)
    router.include_router(stream.router)
    router.include_router(admin.router)

    # PLAN D23 / §4.4a / I19 — the live lane is MOUNTED ONLY WHEN IT IS ON.
    #
    # Off means ABSENT, not mounted-and-refusing. With the toggle off there is
    # no route to reach, no schema to fuzz and no credential to guess, so the
    # attack surface of the one externally-fed endpoint is zero rather than
    # small. It also makes I19 literal rather than simulated: the test that
    # asserts replay is unaffected by the live path disables the toggle and
    # finds nothing mounted, which is the state the default build ships in.
    if get_settings().live_ingest_enabled:
        router.include_router(ingest.router)

    return router


#: The default assembly, for callers that do not need to rebuild.
api_router = build_api_router()
