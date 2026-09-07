import bcrypt

# bcrypt truncates at 72 bytes; longer input silently shares a hash with its
# prefix, so it is rejected rather than quietly accepted.
MAX_PASSWORD_BYTES = 72


class PasswordTooLongError(ValueError):
    pass


def hash_password(password: str) -> str:
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise PasswordTooLongError(f"Password exceeds {MAX_PASSWORD_BYTES} bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(raw, password_hash.encode("utf-8"))
    except ValueError:
        # Malformed stored hash. Treat as a failed login, never as a pass.
        return False
