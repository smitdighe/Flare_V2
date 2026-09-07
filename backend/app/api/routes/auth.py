from typing import Any

from fastapi import APIRouter, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.api.deps import CurrentUser, SessionDep, get_user_by_email
from app.api.envelope import enveloped_response
from app.api.errors import HTTP_422_UNPROCESSABLE, AppError
from app.security.hashing import MAX_PASSWORD_BYTES, hash_password, verify_password
from app.security.tokens import TokenError, create_token, decode_token
from app.store.models import User, as_utc
from app.store.repositories import write_audit

router = APIRouter(prefix="/auth", tags=["auth"])

MIN_PASSWORD_LENGTH = 8


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    # extra="forbid" is the privilege-escalation guard: a client that posts
    # {"role": "admin"} is rejected outright rather than having the field
    # silently ignored. PLAN §9 — the prior codebase let a user self-promote in
    # one HTTP call.
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_token: str


class ProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    email: EmailStr


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH)


def user_payload(user: User) -> dict[str, Any]:
    """CONTRACT §9.1 — {id, email, name, role, created_at}, all five required."""
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "created_at": as_utc(user.created_at).isoformat(),
    }


def _token_pair(user: User) -> dict[str, Any]:
    return {
        "access_token": create_token(user.id, "access", user.role, user.token_version),
        "refresh_token": create_token(user.id, "refresh", user.role, user.token_version),
        "token_type": "bearer",
        "user": user_payload(user),
    }


def _reject_long_password(password: str) -> None:
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise AppError(
            "password_too_long",
            f"Password must be at most {MAX_PASSWORD_BYTES} bytes.",
            HTTP_422_UNPROCESSABLE,
        )


@router.post("/register")
async def register(body: RegisterRequest, session: SessionDep) -> dict[str, Any]:
    """PINNED ENVELOPE EXCEPTION — CONTRACT §1.3.1 #2.

    AuthContext.jsx:171 reads data.access_token off the top level. Enveloping
    this breaks sign-up.
    """
    _reject_long_password(body.password)

    if await get_user_by_email(session, body.email) is not None:
        raise AppError(
            "email_taken",
            "An account with this email already exists.",
            status.HTTP_409_CONFLICT,
        )

    # Role is assigned here, never read from the request. PLAN §9.
    user = User(
        email=body.email.lower(),
        name=body.name,
        password_hash=hash_password(body.password),
        role="viewer",
    )
    session.add(user)
    await session.flush()

    await write_audit(
        session,
        action="auth.register",
        resource_type="user",
        actor_id=user.id,
        resource_id=str(user.id),
    )
    await session.commit()
    return _token_pair(user)


@router.post("/login")
async def login(
    body: LoginRequest, request: Request, session: SessionDep
) -> dict[str, Any]:
    """PINNED ENVELOPE EXCEPTION — CONTRACT §1.3.1 #1.

    The demo account (admin@flare.dev) exists only under --demo-seed. On a
    default boot this returns 401 and the frontend's Quick demo sign-in button
    surfaces that through its existing error path. Intended (CONTRACT §8.7).
    """
    user = await get_user_by_email(session, body.email)
    ok = user is not None and verify_password(body.password, user.password_hash)

    if not ok or user is None:
        # PLAN §4.1: failed logins are audited.
        await write_audit(
            session,
            action="auth.login_failed",
            resource_type="user",
            actor_id=user.id if user else None,
            # The submitted email is recorded; the password never is.
            details={"email": body.email.lower(), "reason": "invalid_credentials"},
        )
        await session.commit()
        raise AppError(
            "invalid_credentials",
            "Incorrect email or password.",
            status.HTTP_401_UNAUTHORIZED,
        )

    if not user.is_active:
        await write_audit(
            session,
            action="auth.login_failed",
            resource_type="user",
            actor_id=user.id,
            details={"email": user.email, "reason": "inactive"},
        )
        await session.commit()
        raise AppError(
            "account_inactive",
            "This account has been deactivated.",
            status.HTTP_403_FORBIDDEN,
        )

    await write_audit(
        session,
        action="auth.login",
        resource_type="user",
        actor_id=user.id,
        resource_id=str(user.id),
        details={"request_id": getattr(request.state, "request_id", None)},
    )
    await session.commit()
    return _token_pair(user)


@router.post("/refresh")
async def refresh(body: RefreshRequest, session: SessionDep) -> dict[str, Any]:
    """PINNED ENVELOPE EXCEPTION — CONTRACT §1.3.1 #3."""
    try:
        payload = decode_token(body.refresh_token, "refresh")
    except TokenError as exc:
        raise AppError(
            "invalid_token", "Refresh token is invalid or expired.",
            status.HTTP_401_UNAUTHORIZED,
        ) from exc

    user = await session.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise AppError(
            "invalid_token", "Refresh token is invalid or expired.",
            status.HTTP_401_UNAUTHORIZED,
        )

    if int(payload.get("tv", 0)) != user.token_version:
        raise AppError(
            "invalid_token",
            "Session is no longer valid. Please sign in again.",
            status.HTTP_401_UNAUTHORIZED,
        )

    return _token_pair(user)


@router.get("/me")
async def me(user: CurrentUser) -> dict[str, Any]:
    """PINNED ENVELOPE EXCEPTION — CONTRACT §1.3.1 #4.

    AuthContext.jsx:93 does `setUser(data)` — the whole body becomes the user
    object.
    """
    return user_payload(user)


@router.put("/profile")
async def update_profile(
    body: ProfileRequest, request: Request, user: CurrentUser, session: SessionDep
) -> Any:
    """Enveloped — the frontend reads only res.ok (SettingsPage.jsx:29).

    `role` is not a field on ProfileRequest and extra="forbid" rejects it, so
    this route cannot be used to self-promote.
    """
    new_email = body.email.lower()
    if new_email != user.email:
        existing = await get_user_by_email(session, new_email)
        if existing is not None:
            raise AppError(
                "email_taken",
                "An account with this email already exists.",
                status.HTTP_409_CONFLICT,
            )

    user.name = body.name
    user.email = new_email
    await write_audit(
        session,
        action="user.update_profile",
        resource_type="user",
        actor_id=user.id,
        resource_id=str(user.id),
    )
    await session.commit()
    return enveloped_response(user_payload(user), request)


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    user: CurrentUser,
    session: SessionDep,
) -> Any:
    """Enveloped — the frontend reads res.ok, and err.detail on failure."""
    _reject_long_password(body.new_password)

    if not verify_password(body.current_password, user.password_hash):
        await write_audit(
            session,
            action="auth.change_password_failed",
            resource_type="user",
            actor_id=user.id,
            resource_id=str(user.id),
        )
        await session.commit()
        raise AppError(
            "invalid_credentials",
            "Current password is incorrect.",
            status.HTTP_400_BAD_REQUEST,
        )

    user.password_hash = hash_password(body.new_password)

    # PLAN §9: invalidate every outstanding token, access and refresh alike.
    # Bumping the counter is exact; a timestamp could not separate a token
    # minted in the same second as this change.
    user.token_version += 1

    await write_audit(
        session,
        action="auth.change_password",
        resource_type="user",
        actor_id=user.id,
        resource_id=str(user.id),
    )
    await session.commit()
    return enveloped_response({"detail": "Password changed"}, request)
