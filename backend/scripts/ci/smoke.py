"""Cold-clone smoke test. PLAN §13.2 check 7.

    python -m scripts.ci.smoke

**WHAT THIS CATCHES:** the "works on my machine" class of demo failure. A fresh
checkout, a fresh database, migrations applied from zero, the app booted, and
both ML artifacts loaded **with the network blocked** — because the failure mode
this exists for is an artifact that is gitignored and silently re-downloaded on
first use, which works forever on the machine that has the cache and fails the
first time it runs anywhere else. That is exactly how the prior build's RAG path
died on a cold clone.

The network block is real: `socket.socket` is replaced with something that
raises. Loopback is permitted because the in-process ASGI transport and SQLite
do not need it, but a driver that decided to open one would otherwise look like
a network call. Anything reaching for a remote host raises `SmokeNetworkBlocked`
and the run fails with the call site in the traceback.

Run against a genuinely fresh clone in CI. Run locally to reproduce; the only
thing it mutates is a temporary directory.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import socket
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[2]


class SmokeNetworkBlocked(RuntimeError):
    """Something tried to reach the network during the cold-clone smoke test."""


_REAL_SOCKET = socket.socket
_REAL_CREATE_CONNECTION = socket.create_connection
_REAL_GETADDRINFO = socket.getaddrinfo


def block_network() -> None:
    """Make any outbound connection raise, loudly, with a usable traceback."""

    def _is_loopback(address: Any) -> bool:
        """Loopback is permitted, and this is not a loophole.

        asyncio's Windows Proactor loop builds its own self-pipe out of a
        127.0.0.1 socket pair, so blocking loopback blocks the event loop rather
        than the network. What the check is about is a REMOTE fetch — an
        artifact that downloads itself on first use — and nothing on 127.0.0.1
        can be that.
        """
        if not isinstance(address, tuple) or not address:
            return True  # AF_UNIX and the like: not the network either
        host = address[0]
        return host in ("127.0.0.1", "::1", "localhost", "", None)

    class _Blocked(_REAL_SOCKET):
        def connect(self, address: Any) -> None:
            if _is_loopback(address):
                return super().connect(address)
            raise SmokeNetworkBlocked(
                f"the cold-clone smoke test blocks the network and something "
                f"tried to connect to {address!r}. An artifact that downloads "
                "itself on first use passes on a warm machine and fails on "
                "every cold one (PLAN D4/D21)."
            )

        def connect_ex(self, address: Any) -> int:
            if _is_loopback(address):
                return int(super().connect_ex(address))
            raise SmokeNetworkBlocked(f"blocked connect_ex to {address!r}")

    def _blocked_create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        if _is_loopback(address):
            return _REAL_CREATE_CONNECTION(address, *args, **kwargs)
        raise SmokeNetworkBlocked(f"blocked create_connection to {address!r}")

    def _blocked_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host in ("localhost", "127.0.0.1", "::1", None):
            return _REAL_GETADDRINFO(host, *args, **kwargs)
        raise SmokeNetworkBlocked(f"blocked DNS lookup for {host!r}")

    # `socket.socket` IS a type, so assigning to it is exactly what mypy
    # objects to — and it is also precisely what this function is for.
    socket.socket = _Blocked  # type: ignore[misc]
    socket.create_connection = _blocked_create_connection
    socket.getaddrinfo = _blocked_getaddrinfo


def restore_network() -> None:
    socket.socket = _REAL_SOCKET  # type: ignore[misc]
    socket.create_connection = _REAL_CREATE_CONNECTION
    socket.getaddrinfo = _REAL_GETADDRINFO


def prepare_environment() -> Path:
    """A throwaway database and a config that cannot reach a provider.

    Set BEFORE any `app` import, because `get_settings` is lru_cached and the
    first call fixes the whole process's view.
    """
    tmp = Path(tempfile.mkdtemp(prefix="flare-smoke-"))
    database = tmp / f"smoke-{uuid.uuid4().hex}.db"

    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{database.as_posix()}"
    # A throwaway secret for a throwaway database in a throwaway directory.
    # It signs one token, for one request, in one process that then exits.
    os.environ["JWT_SECRET"] = "smoke-test-secret-not-used-anywhere-real-00"  # noqa: S105
    os.environ["ENVIRONMENT"] = "test"
    os.environ["LOG_LEVEL"] = "WARNING"
    os.environ["DEMO_SEED_ENABLED"] = "false"
    os.environ["REPLAY_AUTOSTART"] = "false"
    os.environ["SCHEDULER_ENABLED"] = "false"
    os.environ["NOTIFICATIONS_ENABLED"] = "false"
    # A cold clone has no keys. Offline mode is the DECLARED way to run without
    # them (PLAN E9/§10.3); without it the registry fails closed at startup,
    # which would be a correct failure and not the one under test here.
    os.environ["OFFLINE_MODE"] = "true"
    os.environ["FLARE_DISABLE_ENV_FILE"] = "1"
    return database


def step(label: str) -> None:
    print(f"  -> {label}", flush=True)


async def boot_and_probe() -> dict[str, Any]:
    from httpx import ASGITransport, AsyncClient

    from app.main import create_app
    from app.security.hashing import hash_password
    from app.store.models import User
    from app.store.session import get_sessionmaker

    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://smoke"
    ) as client:
        # `/health` is authenticated (PLAN §9 — an anonymous one burned four
        # metered quotas per hit), so the smoke test creates a user first. That
        # the user can be created at all is itself part of what is being smoked:
        # it exercises the migrated schema.
        async with get_sessionmaker()() as session:
            session.add(
                User(
                    email="smoke@example.com",
                    name="Smoke",
                    password_hash=hash_password("SmokePassword123!"),
                    role="viewer",
                )
            )
            await session.commit()

        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "smoke@example.com", "password": "SmokePassword123!"},
        )
        if login.status_code != 200:
            raise SystemExit(f"login failed during smoke test: {login.text}")

        token = login.json()["access_token"]
        response = await client.get(
            "/api/v1/health", headers={"Authorization": f"Bearer {token}"}
        )
        if response.status_code != 200:
            raise SystemExit(f"/health returned {response.status_code}: {response.text}")
        return dict(response.json())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="do NOT block the network (for debugging only — the block is the "
        "point of the check)",
    )
    args = parser.parse_args()

    started = time.perf_counter()
    print("cold-clone smoke test")
    database = prepare_environment()
    step(f"throwaway database at {database}")

    if not args.allow_network:
        block_network()
        step("network blocked (socket.connect raises)")

    try:
        # 1. migrate — Alembic is the only schema authority (D18).
        step("alembic upgrade head")
        from alembic.config import Config

        from alembic import command

        config = Config(str(BACKEND_ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
        command.upgrade(config, "head")

        # 2. load both ML artifacts FROM DISK, with the network still blocked.
        step("load the LightGBM classifier from the committed artifact")
        from app.ml.classifier import load_classifier

        classifier = load_classifier()
        version = getattr(classifier, "model_version", None)
        if not version:
            raise SystemExit("the classifier loaded without a model version (I16)")
        step(f"   classifier {version}")

        step("load the MiniLM index from the committed weights")
        from app.rag.retriever import load_retriever

        retriever = load_retriever()
        chunks = getattr(retriever, "chunk_count", 0)
        dimensions = getattr(retriever, "dimensions", 0)
        if not chunks or not dimensions:
            raise SystemExit(
                f"the retriever loaded with {chunks} chunks / {dimensions} dims"
            )
        step(f"   {chunks} chunks at {dimensions} dimensions")

        # A real query, so the ONNX session actually runs rather than merely
        # being constructed. This is where a lazily-downloaded weight file
        # would reach for the network.
        hits = retriever.search("SYN flood against a web server", 3)
        step(f"   a real query returned {len(hits)} technique(s)")

        # 3. boot the app and hit /health.
        step("boot the app and GET /health")
        payload = asyncio.run(boot_and_probe())
        services = {s["name"]: s["status"] for s in payload["data"]["services"]}
        step(f"   /health 200, services={services}")

    finally:
        restore_network()

    elapsed = round(time.perf_counter() - started, 2)
    print(f"\ncold-clone smoke test PASSED in {elapsed}s")
    print(
        "  migrations applied from zero, both ML artifacts loaded from committed "
        "files with the network blocked, and /health answered 200."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
