"""POST /ingest/eve — live staged-attack ingestion. CONTRACT §2.10 #31, PLAN D23 / §4.4a.

**THIS IS THE ONLY ENDPOINT THAT ACCEPTS UNSOLICITED EXTERNAL INPUT**, and every
control on it follows from that one sentence:

  * a **dedicated service token**, not a user JWT (`app/security/service_token.py`);
  * its **own rate limit**, separate from the global 120/min, keyed by the
    credential rather than by a user id — there is no user;
  * a **payload size cap enforced before the body is read**, so an oversized
    body costs a header parse rather than a megabyte of memory;
  * **per-event schema validation**, strict on the fields the normalizer
    CONSUMES and permissive about the rest, with a bad event rejected
    individually instead of poisoning the batch;
  * every interpolated field **escaped exactly like any other untrusted input**
    — which it already is, because live alerts go through the same
    `app/security/sanitize.py` path as replay alerts, and there is no second
    prompt builder for them to bypass it with.

**THE ENDPOINT IS NOT MOUNTED WHEN THE TOGGLE IS OFF.** `live_ingest_enabled`
defaults to False and `app/api/router.py` includes this router only when it is
on. Off means absent — not mounted-and-403 — so the attack surface with the
feature disabled is zero rather than small.

**`accepted` AND `dropped` ARE BOTH REPORTED (PLAN T13).** An eve.json is mostly
`flow`, `dns`, `http` and `stats` records; only `alert` records become alerts.
Those are COUNTED as dropped-with-a-reason, never silently discarded, because a
forwarder operator staring at "accepted: 3" needs to know whether the other 997
records were non-alerts (normal) or malformed (their problem) or refused by a
full lane (ours).

**202, not 201.** The batch is queued onto the live lane and processed by its
own worker. Returning 201 would claim the alerts exist, and at the moment of the
response they do not yet.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.api.envelope import enveloped_response
from app.api.errors import AppError
from app.config import get_settings
from app.core.user_rate_limit import get_limiter
from app.ingestion.live import get_live_ingest
from app.ingestion.suricata import EveParseError, parse_eve_record
from app.security.service_token import verify_service_token

# Starlette renamed HTTP_413_REQUEST_ENTITY_TOO_LARGE and the old name now
# emits a DeprecationWarning, which the warnings-as-errors pytest config
# turns into a failure. The number is stable; the constant is not. Same
# treatment as the 422 constant in `app/api/errors.py`.
HTTP_413_PAYLOAD_TOO_LARGE = 413

logger = logging.getLogger("flare.ingest")

router = APIRouter(prefix="/ingest", tags=["ingest"])

#: The rate limiter is keyed by an integer user id everywhere else. There is no
#: user here, and inventing one would put a fake principal in a security path,
#: so the whole route shares a single bucket under this sentinel key. That is
#: the honest model: one credential, one budget.
_SERVICE_PRINCIPAL = -1


class EveAlertDetail(BaseModel):
    """The `alert` sub-object. Only what the normalizer actually reads."""

    model_config = ConfigDict(extra="ignore")

    signature: str = Field(min_length=1, max_length=512)
    signature_id: int | None = None
    category: str | None = Field(default=None, max_length=256)
    severity: int | None = Field(default=None, ge=1, le=4)


class EveEvent(BaseModel):
    """One EVE record. Strict about what we consume, silent about the rest.

    **`extra="ignore"` is the only implementable rule here, and it was measured
    rather than assumed.** Against the 107 real alert records from a Suricata
    8.0.6 run, `extra="forbid"` rejects **107 of 107**: those records carry 22
    distinct top-level keys against the eight this model names, and the 14 it
    does not name are `app_proto`, `direction`, `files`, `flow`, `flow_id`,
    `http`, `ip_v`, `metadata`, `pcap_cnt`, `pkt_src`, `tc_progress`, `tls`,
    `ts_progress` and `tx_id`. A reject-on-unknown endpoint cannot ingest live
    Suricata output at all, and would break again on the next version bump.

    That list is the offline-pcap set and is exhaustive for it. A capture taken
    off a live interface adds at least `in_iface`, which pcap mode never emits —
    so the real key set is open-ended in practice, which is the argument for
    `ignore` rather than a longer allowlist.

    **This is not a weaker check, it is a differently-scoped one.** Every field
    the normalizer reads is typed and bounded, and a malformed value in one of
    them rejects that record — `dest_port=999999` is a rejection, not a
    truncation. What `ignore` buys is that unlisted keys are DISCARDED UNREAD:
    `model_dump` hands the parser only the declared subset, so nothing outside
    it can reach the pipeline whether or not we validated it.

    The batch envelope is a different matter and stays `extra="forbid"` — that
    shape is ours, not Suricata's, so an unexpected key there is our bug.
    """

    model_config = ConfigDict(extra="ignore")

    event_type: str = Field(min_length=1, max_length=64)
    timestamp: str = Field(min_length=1, max_length=64)
    src_ip: str | None = Field(default=None, max_length=64)
    dest_ip: str | None = Field(default=None, max_length=64)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    proto: str | None = Field(default=None, max_length=16)
    alert: EveAlertDetail | None = None


class EveBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[dict[str, Any]] = Field(min_length=1)


def _reject(reason: str, count: int) -> dict[str, Any]:
    return {"reason": reason, "count": count}


@router.post("/eve", status_code=status.HTTP_202_ACCEPTED)
async def ingest_eve(request: Request) -> Any:
    """Accept a batch of EVE records onto the live lane.

    Returns 202 with `{accepted, dropped, ...}`. Nothing here raises on a bad
    individual event: the batch is a best-effort hand-off from a script tailing
    a file, and failing 200 good records because the 201st was truncated
    mid-write — which is what a tail on a live file produces routinely — would
    make the forwarder unusable.
    """
    settings = get_settings()

    # 1. Credential first. Nothing about the body is touched until this passes,
    #    so an unauthenticated caller cannot make us parse anything.
    verify_service_token(request)

    # 2. Size cap, from the header, BEFORE reading the body.
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError as exc:
            raise AppError(
                "bad_request", "Content-Length is not a number", status.HTTP_400_BAD_REQUEST
            ) from exc
        if length > settings.ingest_max_body_bytes:
            raise AppError(
                "payload_too_large",
                f"Batch exceeds the {settings.ingest_max_body_bytes}-byte ingest cap.",
                HTTP_413_PAYLOAD_TOO_LARGE,
            )

    # 3. This route's own budget. Separate from the global limiter, which is
    #    sized for a browser reading alerts and is the wrong number for a
    #    machine POSTing batches.
    limiter = get_limiter(
        "ingest_eve",
        settings.ingest_requests_per_minute,
        burst=settings.ingest_burst,
    )
    retry_after = limiter.check(_SERVICE_PRINCIPAL)
    if retry_after is not None:
        raise AppError(
            "rate_limited",
            f"Ingest rate limit reached. Retry in {retry_after:.0f}s.",
            status.HTTP_429_TOO_MANY_REQUESTS,
        )

    raw = await request.body()
    # A chunked request carries no Content-Length, so the cap is re-checked
    # against what actually arrived. Starlette has already buffered it, so this
    # is a backstop for the declared-size check rather than a replacement.
    if len(raw) > settings.ingest_max_body_bytes:
        raise AppError(
            "payload_too_large",
            f"Batch exceeds the {settings.ingest_max_body_bytes}-byte ingest cap.",
            HTTP_413_PAYLOAD_TOO_LARGE,
        )

    try:
        batch = EveBatch.model_validate_json(raw)
    except ValidationError as exc:
        raise AppError(
            "validation_error",
            "Body must be {\"events\": [...]} with at least one record.",
            422,
            detail=exc.error_count(),
        ) from exc

    if len(batch.events) > settings.ingest_max_events_per_batch:
        raise AppError(
            "payload_too_large",
            f"Batch carries {len(batch.events)} events; the cap is "
            f"{settings.ingest_max_events_per_batch}.",
            HTTP_413_PAYLOAD_TOO_LARGE,
        )

    live = get_live_ingest()

    accepted = 0
    non_alert = 0
    invalid = 0
    unparsed = 0
    refused = 0

    for record in batch.events:
        try:
            event = EveEvent.model_validate(record)
        except ValidationError:
            invalid += 1
            continue

        # Cheap discriminator first: the overwhelming majority of an eve.json
        # is not an alert, and those cost nothing beyond this comparison.
        if event.event_type != "alert":
            non_alert += 1
            continue

        try:
            # PLAN D24 — the source tag is set AT THE INGESTION BOUNDARY and is
            # never inferred downstream. PLAN I15 — `live_demo` carries no
            # ground truth, which `parse_eve_record` enforces by construction
            # (`ground_truth_class=None`, `features={}`).
            alert = parse_eve_record(
                event.model_dump(exclude_none=True), source="live_demo"
            )
        except (EveParseError, ValueError, KeyError):
            unparsed += 1
            continue

        if alert is None:  # pragma: no cover - event_type was checked above
            non_alert += 1
            continue

        if live.submit(alert):
            accepted += 1
        else:
            # The live lane is full. NOT a 503: replay is untouched and the
            # correct answer is to tell the forwarder how many were refused so
            # it can back off (I19).
            refused += 1

    live.non_alert_records += non_alert
    live.malformed_records += invalid + unparsed

    dropped = non_alert + invalid + unparsed + refused
    if dropped:
        logger.info(
            "ingest batch partially dropped",
            extra={
                "request_id": getattr(request.state, "request_id", "-"),
                "accepted": accepted,
                "non_alert": non_alert,
                "invalid": invalid,
                "unparsed": unparsed,
                "refused": refused,
            },
        )

    return enveloped_response(
        {
            "accepted": accepted,
            "dropped": dropped,
            # PLAN T13 — the breakdown, because "dropped: 997" alone cannot
            # distinguish a normal eve.json from a broken forwarder.
            "dropped_breakdown": [
                _reject("not_an_alert_record", non_alert),
                _reject("schema_invalid", invalid),
                _reject("unparseable_alert", unparsed),
                _reject("live_lane_full", refused),
            ],
            "source": "live_demo",
            "queue_depth": live.queue.stats().depth,
        },
        request,
        status_code=status.HTTP_202_ACCEPTED,
    )
