import logging
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.envelope import error_body
from app.core.logging import sanitize_request_id

logger = logging.getLogger("flare.access")

Handler = Callable[[Request], Awaitable[Response]]


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attaches a request id and the perf_counter start used for meta.latency_ms."""

    async def dispatch(self, request: Request, call_next: Handler) -> Response:
        request_id = sanitize_request_id(request.headers.get("X-Request-ID"))
        request.state.request_id = request_id
        request.state.start_time = time.perf_counter()

        response = await call_next(request)

        elapsed = round((time.perf_counter() - request.state.start_time) * 1000, 3)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "latency_ms": elapsed,
            },
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window limiter returning a real 429 as a JSONResponse.

    PLAN §9 / CONTRACT §1.5: a 429, never a 500. CORS is registered after this
    so the rejection still carries CORS headers and the browser can read it.

    Keyed on the authenticated subject when present, falling back to the peer
    address. PLAN §9 warns against keying on a raw proxy-shared IP; the bearer
    token is the better key whenever there is one.
    """

    def __init__(self, app: object, limit: int, window_seconds: int) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._limit = limit
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _key(self, request: Request) -> str:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return f"tok:{hash(auth[7:])}"
        client = request.client
        return f"ip:{client.host if client else 'unknown'}"

    async def dispatch(self, request: Request, call_next: Handler) -> Response:
        now = time.monotonic()
        key = self._key(request)
        bucket = self._hits[key]

        cutoff = now - self._window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self._limit:
            retry_after = max(1, int(self._window - (now - bucket[0])))
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content=error_body(
                    "rate_limited",
                    "Too many requests. Please slow down.",
                    {"retry_after_seconds": retry_after},
                ),
                headers={"Retry-After": str(retry_after)},
            )

        bucket.append(now)

        # Bounded memory: drop keys whose windows have fully expired. Without
        # this the dict grows once per distinct caller and never shrinks.
        if len(self._hits) > 2048:
            for stale in [k for k, v in self._hits.items() if not v or v[-1] < cutoff]:
                del self._hits[stale]

        return await call_next(request)
