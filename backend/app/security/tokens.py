from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import jwt

from app.config import get_settings

TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def create_token(subject: int, token_type: TokenType, role: str, token_version: int) -> str:
    settings = get_settings()
    issued = _now()
    if token_type == "access":
        expires = issued + timedelta(minutes=settings.access_token_ttl_minutes)
    else:
        expires = issued + timedelta(days=settings.refresh_token_ttl_days)

    payload: dict[str, Any] = {
        "sub": str(subject),
        "type": token_type,
        "role": role,
        "tv": token_version,
        "iat": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str, expected_type: TokenType) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat", "sub", "type", "tv"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("Token is invalid") from exc

    if payload.get("type") != expected_type:
        # An access token must never be usable as a refresh token or vice versa.
        raise TokenError("Token is invalid")
    return payload


def issued_at(payload: dict[str, Any]) -> datetime:
    return datetime.fromtimestamp(payload["iat"], tz=UTC)
