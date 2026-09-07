from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    """Attach UTC to a naive value read back from the database.

    SQLite has no native timestamp type, so DateTime(timezone=True) round-trips
    as a NAIVE datetime regardless of what was written. Comparing one of those
    against an aware datetime raises TypeError, so every read of a stored
    timestamp goes through here.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)

    # PLAN §9: defaults to viewer. A user cannot set this on themselves —
    # register never reads a client-supplied role, and the profile route
    # rejects the field outright.
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # PLAN §9: a password change or a deactivation invalidates outstanding
    # tokens. This is a COUNTER, not a timestamp, because JWT `iat` has
    # one-second granularity — a timestamp comparison cannot separate a token
    # minted in the same second as the change, so one would survive. The
    # counter is embedded in every token as `tv` and compared exactly.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class Alert(Base):
    """Triaged alert.

    Columns mirror the frozen Alert schema in openapi.yaml. Phase 1 creates the
    table; Phase 2 fills it.
    """

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # PLAN D24. Only cicids_replay may ever be scored by the eval (I15).
    source: Mapped[str] = mapped_column(String(20), nullable=False)

    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(40), nullable=False)

    # PLAN D16: dest_*, never dst_*.
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dest_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dest_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)

    signature: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_technique: Mapped[str | None] = mapped_column(String(20))

    ioc_checked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ioc_reputation: Mapped[int | None] = mapped_column(Integer)
    vt_ip: Mapped[str | None] = mapped_column(String(20))
    vt_hash: Mapped[str | None] = mapped_column(String(80))

    explanation: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)

    classify_latency_ms: Mapped[float | None] = mapped_column(Float)
    enrich_latency_ms: Mapped[float | None] = mapped_column(Float)
    reasoning_latency_ms: Mapped[float | None] = mapped_column(Float)

    # PLAN I1: exactly one entry per node, always.
    trace: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)

    confidence: Mapped[float | None] = mapped_column(Float)
    degraded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # PLAN §4.1 Phase 4 — the `add_tag` rule action has to land somewhere real
    # or it is bookkeeping that pretends (T14). This is that somewhere.
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # CONTRACT §2.6 #16 — the per-condition fire trace the drawer renders,
    # recorded AS EVALUATED AT TRIAGE TIME rather than recomputed on read. A
    # recomputation would answer "what would today's rules say", which is a
    # different question from "why does this alert look like this", and the
    # drawer is asking the second one.
    rule_trace: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_alerts_timestamp", "timestamp"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_attack_type", "attack_type"),
        Index("ix_alerts_src_ip", "src_ip"),
        Index("ix_alerts_source", "source"),
    )


class AuditLog(Base):
    """PLAN §4.1: every state-changing operation, including failed logins."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(64))

    # PLAN §9: no secrets, no tokens, no full request bodies.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_audit_created_at", "created_at"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_resource_type", "resource_type"),
        Index("ix_audit_actor_id", "actor_id"),
    )


class Rule(Base):
    """A detection rule. PLAN D33 — the engine shipped in Phase 3, storage here.

    Owner-scoped on LOOKUP, not only on list (PLAN §9, IDOR): every read filters
    by owner in the WHERE clause, so another user's id is a 404 rather than a
    row that happens not to be rendered.

    `match_count` is a REAL counter (PLAN I2). It is incremented in the same
    transaction that persists an alert the rule fired on, so it cannot drift
    from the alerts that produced it.
    """

    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # CONTRACT RuleConditionGroup — {logic, conditions[]}. Stored verbatim as
    # the client sent it so the rule renders back unchanged.
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    actions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)

    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (Index("ix_rules_owner_id", "owner_id"),)


class Playbook(Base):
    """A response playbook and its ordered steps."""

    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # CONTRACT Playbook.alert_type — FREE TEXT, not an enum. The form field is a
    # plain input and "" is legal, meaning "any type".
    alert_type: Mapped[str | None] = mapped_column(String(64))

    # PLAN D27 — low < medium < high < critical; `unknown` sits outside the
    # order and satisfies no threshold. NULL means "any severity".
    severity_threshold: Mapped[str | None] = mapped_column(String(10))

    steps: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (Index("ix_playbooks_owner_id", "owner_id"),)


class PlaybookExecution(Base):
    """One run of a playbook. CONTRACT §9.6 — five statuses, three terminal.

    `steps` is a SNAPSHOT of the playbook's steps at execution time. Editing a
    playbook mid-run must not rewrite the history of a run already in progress,
    and deleting it must not erase the record that it ran.
    """

    __tablename__ = "playbook_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    playbook_id: Mapped[int | None] = mapped_column(
        ForeignKey("playbooks.id", ondelete="SET NULL")
    )
    owner_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    # CONTRACT §9.9 — OPTIONAL. With no alert selected the frontend posts
    # `…/execute?` with an empty query string.
    alert_id: Mapped[str | None] = mapped_column(String(16))

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    steps: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    completed_steps: Mapped[list[int]] = mapped_column(
        JSON, nullable=False, default=list
    )
    current_step: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Per-step notes, PLAN §4.1. The frozen UI always posts {"notes": ""} and has
    # no input, so this is filled only by an API client — recorded rather than
    # discarded, so the field has a real producer the moment one exists.
    step_notes: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )

    # Set when the run entered a terminal status, with the reason. `failed` and
    # `cancelled` are real outcomes and are never reported as `completed`.
    terminal_reason: Mapped[str | None] = mapped_column(Text)
    triggered_by: Mapped[str] = mapped_column(
        String(16), nullable=False, default="manual"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_executions_playbook_id", "playbook_id"),
        Index("ix_executions_owner_id", "owner_id"),
        # One AUTO execution per (playbook, alert). Replay loops over the same
        # partition, so without this the same alert id would start a fresh run
        # on every pass. Manual runs are deliberately unconstrained — an analyst
        # may run the same playbook against the same alert twice.
        Index(
            "uq_executions_auto",
            "playbook_id",
            "alert_id",
            unique=True,
            sqlite_where=text("triggered_by = 'auto'"),
        ),
    )


class NotificationPreference(Base):
    """CONTRACT §2.8 — unique on (user, channel, event_type); POST upserts."""

    __tablename__ = "notification_preferences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "user_id", "channel", "event_type", name="uq_notification_pref"
        ),
    )


class NotificationLog(Base):
    """One dispatch DECISION. PLAN §8.3 — send, suppression and failure alike.

    A SUPPRESSION IS A ROW, not an absence. "We did not email you because you
    were looking at it" is the evidence that the presence logic worked, and an
    absent row is indistinguishable from a dispatcher that never ran.

    One row per (user, event type, debounce window) rather than one per alert.
    `rollup_count` is how many alerts that window covered and is updated in
    place as more arrive, which is the same collapse the outgoing email
    performs — a log that recorded every alert separately while the mail
    rolled them up would describe a system that does not exist.
    """

    __tablename__ = "notification_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)

    # sent | suppressed | failed
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    # Why. Never empty on `suppressed` or `failed`: a row that cannot say why
    # is not evidence of anything.
    reason: Mapped[str | None] = mapped_column(Text)

    # The alert that OPENED the window. Deliberately not a foreign key: the
    # log outlives the alert table's retention and a cascade would erase the
    # record that a notification happened.
    alert_id: Mapped[str | None] = mapped_column(String(16))
    severity: Mapped[str | None] = mapped_column(String(10))
    rollup_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    recipient: Mapped[str | None] = mapped_column(String(320))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_notification_log_user_id", "user_id"),
        Index("ix_notification_log_created_at", "created_at"),
        Index("ix_notification_log_outcome", "outcome"),
    )


class AlertCluster(Base):
    """A source-IP correlation cluster. PLAN §3.1 — served from the DB.

    Written by the scheduler's correlation job and READ by GET /alerts/clusters.
    The job is load-bearing: the endpoint does not recompute, so a job that
    aggregated and discarded would be visible as an empty screen rather than
    invisible.
    """

    __tablename__ = "alert_clusters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False)
    dominant_attack_type: Mapped[str] = mapped_column(String(40), nullable=False)
    attack_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    max_severity: Mapped[str] = mapped_column(String(10), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("src_ip", name="uq_cluster_src_ip"),
        Index("ix_clusters_alert_count", "alert_count"),
    )


class MetricSample(Base):
    """One observation of the live alert rate. PLAN §3.1 — "real samples".

    The right rail's signal-velocity panel plots a SAMPLED series: each row is
    one measurement of alerts/min taken at a fixed cadence by the scheduler.
    That series cannot be reconstructed from the alerts table afterwards —
    re-bucketing stored timestamps yields counts per bucket, which is a
    different quantity from a rate observed at an instant — so the job that
    writes these rows is what makes the panel possible at all.
    """

    __tablename__ = "metric_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    alerts_per_minute: Mapped[float] = mapped_column(Float, nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    queue_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    subscribers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (Index("ix_metric_samples_observed_at", "observed_at"),)


class JobRun(Base):
    """One scheduler execution, with what it actually computed.

    PLAN T14 — a job that aggregates and discards is a defect. This row is the
    receipt: which job, when, how long, and the counts it wrote. A run that
    produced nothing says so, and a run that raised keeps the exception text.
    """

    __tablename__ = "job_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job: Mapped[str] = mapped_column(String(48), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    trigger: Mapped[str] = mapped_column(
        String(16), nullable=False, default="schedule"
    )
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_job_runs_job", "job"),
        Index("ix_job_runs_started_at", "started_at"),
    )
