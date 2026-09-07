from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import AppError
from app.security.tokens import TokenError, decode_token
from app.store.models import User
from app.store.session import get_session

SessionDep = Annotated[AsyncSession, Depends(get_session)]

ROLES = ("viewer", "analyst", "admin")


def _bearer_token(request: Request) -> str:
    """Read the access token from the Authorization header only.

    PLAN §9: no JWT in a query string. A token there lands in access logs,
    browser history and proxy logs. The WebSocket route uses a first-message
    handshake for the same reason (CONTRACT §3.0).
    """
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AppError(
            "unauthorized",
            "Not authenticated",
            status.HTTP_401_UNAUTHORIZED,
        )
    return token


async def get_current_user(request: Request, session: SessionDep) -> User:
    token = _bearer_token(request)
    try:
        payload = decode_token(token, "access")
    except TokenError as exc:
        raise AppError(
            "unauthorized", str(exc), status.HTTP_401_UNAUTHORIZED
        ) from exc

    user = await session.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise AppError(
            "unauthorized", "Account is not available", status.HTTP_401_UNAUTHORIZED
        )

    # PLAN §9: a password change or deactivation invalidates outstanding tokens.
    # Exact integer comparison — see User.token_version for why this is not a
    # timestamp.
    if int(payload.get("tv", 0)) != user.token_version:
        raise AppError(
            "unauthorized",
            "Session is no longer valid. Please sign in again.",
            status.HTTP_401_UNAUTHORIZED,
        )

    request.state.user_id = user.id
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


#: Attribute stamped on a `require_role` guard, naming the roles it admits.
#: Read by the I8 invariant test to enumerate every gated route from the app.
ROLE_GUARD_ATTR = "allowed_roles"


def require_role(*allowed: str) -> Callable[[User], Awaitable[User]]:
    """PLAN §9 / I8: a route that claims a role enforces it.

    The prior codebase's own test suite asserted that a viewer *could* list
    users. No test here may codify a hole as expected behaviour.
    """
    for role in allowed:
        if role not in ROLES:
            raise ValueError(f"Unknown role: {role}")

    async def _guard(user: CurrentUser) -> User:
        if user.role not in allowed:
            raise AppError(
                "forbidden",
                "You do not have permission to perform this action.",
                status.HTTP_403_FORBIDDEN,
            )
        return user

    # PLAN I8 — the CLAIM, made introspectable. Without this the roles a route
    # declares live only inside a closure, so the only way to check that every
    # gated route actually refuses is a hand-maintained list of routes, and a
    # hand-maintained list is exactly what stops being true. The invariant test
    # enumerates the app's routing table through this attribute instead.
    setattr(_guard, ROLE_GUARD_ATTR, tuple(allowed))
    return _guard


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email.lower()))
    return result.scalar_one_or_none()
