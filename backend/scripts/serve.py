"""Server entrypoint that owns argv, so `--demo-seed` is a real flag.

uvicorn's own CLI consumes sys.argv, which is why the documented flag form did
not work in Phase 1 — only the DEMO_SEED_ENABLED env var did. This wrapper
parses our flags first, exports the equivalent settings, seeds if asked, and
only then hands off to uvicorn programmatically.

    python -m scripts.serve --demo-seed
    python -m scripts.serve --host 0.0.0.0 --port 8000 --reload

CONTRACT §8.7 / PLAN §9: admin@flare.dev / admin123 is created ONLY when
--demo-seed is passed. Without it the account does not exist and the frozen
frontend's "Quick demo sign in" button returns 401, which is intended.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scripts.serve", description=__doc__)
    parser.add_argument(
        "--demo-seed",
        action="store_true",
        help="Create admin@flare.dev / admin123 before serving. Demo only.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument(
        "--skip-migrate",
        action="store_true",
        help="Do not run `alembic upgrade head` first.",
    )
    return parser


def _migrate() -> None:
    from pathlib import Path

    from alembic.config import Config

    from alembic import command

    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    command.upgrade(cfg, "head")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.demo_seed:
        # Set before any app import: get_settings() is lru_cached, so the first
        # call fixes the value for the process.
        os.environ["DEMO_SEED_ENABLED"] = "true"

    try:
        from app.config import get_settings

        get_settings()
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        print("Set JWT_SECRET in .env (see .env.example).", file=sys.stderr)
        return 2

    if not args.skip_migrate:
        _migrate()

    if args.demo_seed:
        from scripts.seed_demo import seed

        asyncio.run(seed())
        # The engine created by the seed run belongs to a loop that is about to
        # close; drop it so uvicorn's loop builds its own.
        from app.store.session import dispose_engine

        asyncio.run(dispose_engine())

    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_config=None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
