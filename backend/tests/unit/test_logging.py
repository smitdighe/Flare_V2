from app.core.logging import sanitize_request_id


def test_safe_request_id_is_returned_unchanged() -> None:
    assert sanitize_request_id("abc-123_XYZ.4") == "abc-123_XYZ.4"


def test_newline_is_rejected() -> None:
    """PLAN §9 — the id reaches a log line; a newline could forge entries."""
    forged = 'x"}\n{"level":"CRITICAL"'
    result = sanitize_request_id(forged)
    assert result != forged
    assert "\n" not in result


def test_oversized_id_is_rejected() -> None:
    assert sanitize_request_id("a" * 65) != "a" * 65


def test_missing_id_generates_one() -> None:
    generated = sanitize_request_id(None)
    assert len(generated) == 32
    assert sanitize_request_id(None) != generated
