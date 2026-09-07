import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.envelope import error_body

logger = logging.getLogger("flare.errors")

# Starlette renamed HTTP_422_UNPROCESSABLE_ENTITY to HTTP_422_UNPROCESSABLE_CONTENT
# and the old name now emits a DeprecationWarning, which the warnings-as-errors
# pytest config turns into a failure. The number is stable; the constant is not.
HTTP_422_UNPROCESSABLE = 422

_STATUS_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    413: "payload_too_large",
    422: "validation_error",
    429: "rate_limited",
    503: "service_unavailable",
}


class AppError(Exception):
    """Application error carrying an explicit code and HTTP status.

    `message` is user-facing — it is rendered verbatim by the frozen frontend on
    six paths, so it must stay precise and free of internals (PLAN §9).
    """

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        detail: object = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.detail = detail


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(exc.code, exc.message, exc.detail),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else code
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(code, message),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Pydantic puts the offending input in `input`; it can carry a submitted
        # password, so the field list is reduced to location and reason only.
        fields = [
            {"loc": list(err.get("loc", ())), "msg": err.get("msg", "")}
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=HTTP_422_UNPROCESSABLE,
            content=error_body("validation_error", "Request validation failed", fields),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # PLAN T13: never swallow silently. Log with the request id, return a
        # structured body, and say nothing about internals to the caller.
        logger.exception(
            "unhandled_exception",
            extra={"request_id": getattr(request.state, "request_id", "-")},
            exc_info=exc,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_body("internal_error", "Internal server error"),
        )
