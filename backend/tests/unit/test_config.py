"""Config fails closed.

PLAN §9 / §14: no hardcoded fallback for JWT_SECRET, no default that silently
works, and no flag that nothing reads.
"""

import pytest
from pydantic import ValidationError

# `pydantic.fields` rather than `pydantic_core`: the latter is pydantic's
# own compiled core and is not a declared distribution, so importing it
# directly is the same undeclared-dependency shape the cold-clone job
# exists to catch.
from pydantic.fields import PydanticUndefined

from app.config import Settings


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {"jwt_secret": "x" * 32}
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_missing_jwt_secret_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert "jwt_secret" in str(exc.value)


def test_short_jwt_secret_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(jwt_secret="too-short", _env_file=None)  # type: ignore[call-arg]


def test_no_silent_default_secret_exists() -> None:
    """PLAN §9 — no hardcoded fallback, fail closed if unset.

    Previously written as `default is None or is_required()`, which PLAN §12
    bans: both branches are plausible, so it passed on the weaker one. Required
    is the property that matters and it is asserted on its own.
    """
    field = Settings.model_fields["jwt_secret"]
    assert field.is_required(), "jwt_secret must have no usable default at all"
    assert field.default is PydanticUndefined, (
        f"jwt_secret carries a default ({field.default!r}); a fallback secret is "
        "the hole PLAN §9 names"
    )


def test_wildcard_cors_with_credentials_is_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden"):
        _settings(cors_origins=["*"], cors_allow_credentials=True)


def test_wildcard_cors_without_credentials_is_allowed() -> None:
    settings = _settings(cors_origins=["*"], cors_allow_credentials=False)
    assert settings.cors_origins == ["*"]


def test_demo_seed_defaults_off() -> None:
    assert Settings.model_fields["demo_seed_enabled"].default is False


def test_access_ttl_default_matches_the_login_panel_claim() -> None:
    assert Settings.model_fields["access_token_ttl_minutes"].default == 30
    assert Settings.model_fields["refresh_token_ttl_days"].default == 7


def test_health_stale_must_exceed_ttl() -> None:
    with pytest.raises(ValueError, match="must exceed"):
        _settings(health_cache_ttl_seconds=120, health_cache_stale_seconds=60)


def test_unknown_env_var_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(classify_enabled=True)
