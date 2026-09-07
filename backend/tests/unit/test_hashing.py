import pytest

from app.security.hashing import (
    MAX_PASSWORD_BYTES,
    PasswordTooLongError,
    hash_password,
    verify_password,
)


def test_hash_verifies() -> None:
    digest = hash_password("Password123!")
    assert digest != "Password123!"
    assert digest.startswith("$2b$")
    assert verify_password("Password123!", digest) is True


def test_wrong_password_fails() -> None:
    assert verify_password("Nope", hash_password("Password123!")) is False


def test_salt_differs_per_hash() -> None:
    assert hash_password("same") != hash_password("same")


def test_overlong_password_is_rejected_not_truncated() -> None:
    with pytest.raises(PasswordTooLongError):
        hash_password("a" * (MAX_PASSWORD_BYTES + 1))


def test_malformed_stored_hash_fails_closed() -> None:
    assert verify_password("anything", "not-a-bcrypt-hash") is False
