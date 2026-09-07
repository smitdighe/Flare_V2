from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

# CONTRACT.md §1.3.1 — the pinned envelope exception list.
#
# These operations return a RAW body because the frozen frontend reads a
# top-level key off it (`d.rules`, `data.access_token`) or takes the whole body
# as component state (`setUser(data)`). Wrapping any of them makes the read key
# undefined and the screen renders its empty state permanently, with no error
# anywhere.
#
# The list is CLOSED. A new operation is enveloped. Nothing joins or leaves this
# list without a corresponding frontend change.
#
# Entries are "METHOD /path" with the /api/v1 prefix stripped.
ENVELOPE_EXCEPTIONS: frozenset[str] = frozenset(
    {
        "POST /auth/login",
        "POST /auth/register",
        "POST /auth/refresh",
        "GET /auth/me",
        "GET /rules",
        "GET /rules/alerts/{alert_id}/explain-rules",
        "GET /playbooks",
        "POST /playbooks/{playbook_id}/execute",
        "GET /playbooks/executions/{execution_id}",
        "GET /notifications/preferences",
        "GET /export/alerts/{format}",
    }
)


def latency_ms(request: Request) -> float | None:
    """Elapsed time for this request, measured with perf_counter.

    PLAN §11 / I2: never a hardcoded 0.0. **The comment used to say that while
    the code returned 0.0 anyway**, which is the exact shape I2 exists to catch
    — a fabricated zero rendering as a measurement of zero milliseconds. It now
    returns None, and `envelope` OMITS the field rather than inventing a value,
    the same convention `cost_usd` follows in the eval payload: absent means
    "not measured", and there is no number to misread.

    None is only reachable if `RequestContextMiddleware` did not run, which in
    the shipped app it always does.
    """
    from time import perf_counter

    start = getattr(request.state, "start_time", None)
    if start is None:
        return None
    return round((perf_counter() - start) * 1000, 3)


def envelope(data: Any, request: Request) -> dict[str, Any]:
    """PLAN §3.2 / D17 — the default response shape.

    `meta.latency_ms` is present whenever it was measured, which is every
    request the middleware touched. It is ABSENT rather than zero when it was
    not (PLAN §11).
    """
    elapsed = latency_ms(request)
    meta: dict[str, Any] = {} if elapsed is None else {"latency_ms": elapsed}
    return {"ok": True, "data": data, "meta": meta}


def enveloped_response(
    data: Any, request: Request, status_code: int = 200
) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=envelope(data, request))


def error_body(
    code: str, message: str, detail: Any = None
) -> dict[str, Any]:
    """CONTRACT.md §1.4 — carries BOTH shapes by design.

    PLAN §3.2 specifies `{ok:false, error:{code,message,detail}}`, but six frozen
    frontend call sites read a flat `err.detail` and fall back to a generic
    string when it is absent. Emitting `detail` at the top level alongside the
    structured object satisfies both with no frontend edit.

    `detail` is rendered verbatim to the user on the login, register,
    change-password, rule-create, playbook-save and playbook-execute paths.
    """
    return {
        "ok": False,
        "detail": message,
        "error": {"code": code, "message": message, "detail": detail},
    }
