"""Create the demo account. Gated — never runs on a default boot.

CONTRACT §8.7 / PLAN §9: admin@flare.dev / admin123 is hardcoded in the frozen
frontend's "Quick demo sign in" button (flare/AuthPanel.jsx:72), so the
credentials are already public in the shipped bundle. That is exactly why the
account must not exist unless someone deliberately asks for it.

Usage:
    python -m scripts.seed_demo --demo-seed
    DEMO_SEED_ENABLED=true python -m scripts.seed_demo
"""

import argparse
import asyncio
import sys

from app.api.deps import get_user_by_email
from app.config import get_settings
from app.security.hashing import hash_password
from app.store.models import User
from app.store.repositories import write_audit
from app.store.session import dispose_engine, get_sessionmaker, verify_schema

DEMO_EMAIL = "admin@flare.dev"
# Deliberately public: this pair is hardcoded in the frozen frontend's
# "Quick demo sign in" button, so it is already in the shipped bundle.
DEMO_PASSWORD = "admin123"


async def seed() -> int:
    await verify_schema()
    async with get_sessionmaker()() as session:
        if await get_user_by_email(session, DEMO_EMAIL) is not None:
            print(f"{DEMO_EMAIL} already exists; nothing to do.")
            return 0
        user = User(
            email=DEMO_EMAIL,
            name="Demo Admin",
            password_hash=hash_password(DEMO_PASSWORD),
            role="admin",
        )
        session.add(user)
        await session.flush()
        await write_audit(
            session,
            action="user.demo_seed",
            resource_type="user",
            actor_id=user.id,
            resource_id=str(user.id),
        )
        await session.commit()
    print(f"Seeded {DEMO_EMAIL} (role=admin). Demo only - never enable in prod.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the demo admin account.")
    parser.add_argument(
        "--demo-seed",
        action="store_true",
        help="Required unless DEMO_SEED_ENABLED=true is set.",
    )
    args = parser.parse_args()

    if not (args.demo_seed or get_settings().demo_seed_enabled):
        print(
            "Refusing to seed: pass --demo-seed or set DEMO_SEED_ENABLED=true.",
            file=sys.stderr,
        )
        return 2

    try:
        return asyncio.run(seed())
    finally:
        asyncio.run(dispose_engine())


if __name__ == "__main__":
    raise SystemExit(main())
