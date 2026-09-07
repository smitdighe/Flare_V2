from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.store.models import Alert, AuditLog


async def write_audit(
    session: AsyncSession,
    *,
    action: str,
    resource_type: str,
    actor_id: int | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """PLAN §4.1: every state-changing operation, including failed logins.

    Caller commits. Details must never carry secrets, tokens or full request
    bodies (PLAN §9).
    """
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
    )
    session.add(entry)
    return entry


async def list_audit(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    action: str | None = None,
    resource_type: str | None = None,
    actor_id: int | None = None,
) -> tuple[list[AuditLog], int]:
    """Returns (rows, total).

    CONTRACT §9.7: `total` is the POST-FILTER count — the frontend paginates on
    `Math.ceil(total / 25)`, so a pre-filter count yields a wrong page count.
    """
    filters = []
    if action:
        filters.append(AuditLog.action == action)
    if resource_type:
        filters.append(AuditLog.resource_type == resource_type)
    if actor_id is not None:
        filters.append(AuditLog.actor_id == actor_id)

    count_stmt = select(func.count()).select_from(AuditLog)
    rows_stmt = select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    for condition in filters:
        count_stmt = count_stmt.where(condition)
        rows_stmt = rows_stmt.where(condition)

    total = (await session.execute(count_stmt)).scalar_one()
    rows = list(
        (await session.execute(rows_stmt.limit(limit).offset(offset))).scalars().all()
    )
    return rows, total


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    """Serialize to the frozen Alert schema in openapi.yaml.

    The same shape goes over the WebSocket and out of GET /alerts, so FE-6's
    hydrate-then-stream merge is a concat plus a de-dupe on `id` with no
    reshaping (CONTRACT §8.8).

    `ground_truth_class` is deliberately absent — PLAN I4. The label lives in
    the eval partition on disk and never travels with a rendered alert.
    """
    from app.store.models import as_utc

    return {
        "id": alert.id,
        "timestamp": as_utc(alert.timestamp).isoformat(),
        "source": alert.source,
        "severity": alert.severity,
        "attack_type": alert.attack_type,
        "src_ip": alert.src_ip,
        "dest_ip": alert.dest_ip,
        "dest_port": alert.dest_port,
        "protocol": alert.protocol,
        "signature": alert.signature,
        "mitre_technique": alert.mitre_technique,
        "ioc_checked": alert.ioc_checked,
        "ioc_reputation": alert.ioc_reputation,
        "vt_ip": alert.vt_ip,
        "vt_hash": alert.vt_hash,
        "explanation": alert.explanation,
        "remediation": alert.remediation,
        "classify_latency_ms": alert.classify_latency_ms,
        "enrich_latency_ms": alert.enrich_latency_ms,
        "reasoning_latency_ms": alert.reasoning_latency_ms,
        "trace": alert.trace,
        "confidence": alert.confidence,
        "degraded": alert.degraded,
        # PLAN §4.1 — written by the `add_tag` rule action. Not rendered by the
        # frozen frontend; emitted because the action is real and the field it
        # writes has to be visible to anything that reads an alert.
        "tags": alert.tags or [],
        # PLAN §4.1 — "per-condition fire trace, surfaced in the alert payload".
        # The same array `GET /rules/alerts/{id}/explain-rules` serves, from the
        # same stored column, so the drawer's extra fetch and the streamed alert
        # can never disagree. Empty when no rule was configured at triage time,
        # which is the honest value rather than an absent key.
        "rule_trace": alert.rule_trace or [],
    }


async def upsert_alert(session: AsyncSession, normalized: Any) -> Alert:
    """Persist a NormalizedAlert. Idempotent on `id`.

    Replay loops over the same partition, so the same row id recurs; an insert
    would raise on the second pass. The client de-dupes on `id` too (FE-6).
    """
    existing = await session.get(Alert, normalized.id)
    target = existing or Alert(id=normalized.id)

    target.timestamp = normalized.timestamp
    target.source = normalized.source
    target.severity = normalized.severity
    target.attack_type = normalized.attack_type
    target.src_ip = normalized.src_ip
    target.dest_ip = normalized.dest_ip
    target.dest_port = normalized.dest_port
    target.protocol = normalized.protocol
    target.signature = normalized.signature
    target.mitre_technique = normalized.mitre_technique
    target.ioc_checked = normalized.ioc_checked
    target.ioc_reputation = normalized.ioc_reputation
    target.vt_ip = normalized.vt_ip
    target.vt_hash = normalized.vt_hash
    target.explanation = normalized.explanation
    target.remediation = normalized.remediation
    target.classify_latency_ms = normalized.classify_latency_ms
    target.enrich_latency_ms = normalized.enrich_latency_ms
    target.reasoning_latency_ms = normalized.reasoning_latency_ms
    target.trace = normalized.trace
    target.confidence = normalized.confidence
    target.degraded = normalized.degraded
    target.tags = list(getattr(normalized, "tags", []) or [])
    target.rule_trace = list(getattr(normalized, "rule_trace", []) or [])

    if existing is None:
        session.add(target)
    return target


async def list_alerts(
    session: AsyncSession,
    *,
    limit: int,
    offset: int,
    severity: str | None = None,
    attack_type: str | None = None,
    search: str | None = None,
) -> tuple[list[Alert], int]:
    """Newest first, matching the WS prepend so hydrated and live halves agree.

    `total` is the POST-FILTER count, same rule as the audit list.
    """
    filters = []
    if severity:
        filters.append(Alert.severity == severity)
    if attack_type:
        filters.append(Alert.attack_type == attack_type)
    if search:
        needle = f"%{search.strip()}%"
        filters.append(
            or_(
                Alert.src_ip.like(needle),
                Alert.dest_ip.like(needle),
                Alert.id.like(needle.upper()),
                Alert.signature.like(needle),
            )
        )

    count_stmt = select(func.count()).select_from(Alert)
    rows_stmt = select(Alert).order_by(Alert.timestamp.desc(), Alert.id.desc())
    for condition in filters:
        count_stmt = count_stmt.where(condition)
        rows_stmt = rows_stmt.where(condition)

    total = (await session.execute(count_stmt)).scalar_one()
    rows = list(
        (await session.execute(rows_stmt.limit(limit).offset(offset))).scalars().all()
    )
    return rows, total
