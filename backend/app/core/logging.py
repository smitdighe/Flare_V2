import json
import logging
import re
import sys
import uuid
from typing import Any

# PLAN §9: a client-supplied X-Request-ID is echoed into every log line for this
# request, so it is untrusted input on a path that ends in a log file. Anything
# outside this character set — newlines above all — could forge log entries.
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def sanitize_request_id(raw: str | None) -> str:
    """Return the client's id if it is safe to echo, else a fresh one."""
    if raw and _REQUEST_ID_PATTERN.match(raw):
        return raw
    return uuid.uuid4().hex


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("request_id", "method", "path", "status", "latency_ms", "user_id"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # uvicorn duplicates access lines that our own middleware already emits with
    # a request id attached.
    logging.getLogger("uvicorn.access").disabled = True
