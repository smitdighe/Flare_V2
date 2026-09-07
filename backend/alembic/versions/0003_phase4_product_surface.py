"""Phase 4 — product surface.

Rules, playbooks and their executions, notification preferences, correlation
clusters, sampled metrics and job runs. Plus two columns on `alerts` that the
rule actions need somewhere real to land (PLAN T14): `tags` for `add_tag`, and
`rule_trace` for the drawer's per-condition fire trace.

PLAN D18 — Alembic is the sole schema authority. There is no create_all.

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---- alerts: somewhere real for the rule actions to land --------------
    # server_default is set so rows written before this migration read back as
    # an empty list rather than NULL; the ORM default covers new rows.
    op.add_column(
        "alerts",
        sa.Column("tags", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "alerts",
        sa.Column(
            "rule_trace", sa.JSON(), nullable=False, server_default=sa.text("'[]'")
        ),
    )

    # ---- rules -------------------------------------------------------------
    op.create_table(
        "rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "owner_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("conditions", sa.JSON(), nullable=False),
        sa.Column("actions", sa.JSON(), nullable=False),
        sa.Column(
            "is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column(
            "match_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
    )
    op.create_index("ix_rules_owner_id", "rules", ["owner_id"])

    # ---- playbooks ---------------------------------------------------------
    op.create_table(
        "playbooks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "owner_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("alert_type", sa.String(length=64), nullable=True),
        sa.Column("severity_threshold", sa.String(length=10), nullable=True),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column(
            "is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
    )
    op.create_index("ix_playbooks_owner_id", "playbooks", ["owner_id"])

    op.create_table(
        "playbook_executions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "playbook_id",
            sa.Integer(),
            sa.ForeignKey("playbooks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "owner_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("alert_id", sa.String(length=16), nullable=True),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("completed_steps", sa.JSON(), nullable=False),
        sa.Column(
            "current_step", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("step_notes", sa.JSON(), nullable=False),
        sa.Column("terminal_reason", sa.Text(), nullable=True),
        sa.Column(
            "triggered_by",
            sa.String(length=16),
            nullable=False,
            server_default="manual",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
    )
    op.create_index(
        "ix_executions_playbook_id", "playbook_executions", ["playbook_id"]
    )
    op.create_index("ix_executions_owner_id", "playbook_executions", ["owner_id"])
    # Partial unique index: replay loops over the same partition, so without
    # this the same alert id would start a fresh auto run on every pass. Manual
    # runs stay unconstrained — an analyst may legitimately run the same
    # playbook against the same alert twice.
    op.create_index(
        "uq_executions_auto",
        "playbook_executions",
        ["playbook_id", "alert_id"],
        unique=True,
        sqlite_where=sa.text("triggered_by = 'auto'"),
    )

    # ---- notification preferences -----------------------------------------
    op.create_table(
        "notification_preferences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column(
            "is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.UniqueConstraint(
            "user_id", "channel", "event_type", name="uq_notification_pref"
        ),
    )

    # ---- correlation clusters ---------------------------------------------
    op.create_table(
        "alert_clusters",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("dominant_attack_type", sa.String(length=40), nullable=False),
        sa.Column("attack_types", sa.JSON(), nullable=False),
        sa.Column("max_severity", sa.String(length=10), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_minutes", sa.Integer(), nullable=False),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.UniqueConstraint("src_ip", name="uq_cluster_src_ip"),
    )
    op.create_index("ix_clusters_alert_count", "alert_clusters", ["alert_count"])

    # ---- sampled metrics ---------------------------------------------------
    op.create_table(
        "metric_samples",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("alerts_per_minute", sa.Float(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column(
            "queue_depth", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "subscribers", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
    )
    op.create_index(
        "ix_metric_samples_observed_at", "metric_samples", ["observed_at"]
    )

    # ---- job runs ----------------------------------------------------------
    op.create_table(
        "job_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job", sa.String(length=48), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "trigger",
            sa.String(length=16),
            nullable=False,
            server_default="schedule",
        ),
        sa.Column("duration_ms", sa.Float(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
    )
    op.create_index("ix_job_runs_job", "job_runs", ["job"])
    op.create_index("ix_job_runs_started_at", "job_runs", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_job_runs_started_at", table_name="job_runs")
    op.drop_index("ix_job_runs_job", table_name="job_runs")
    op.drop_table("job_runs")

    op.drop_index("ix_metric_samples_observed_at", table_name="metric_samples")
    op.drop_table("metric_samples")

    op.drop_index("ix_clusters_alert_count", table_name="alert_clusters")
    op.drop_table("alert_clusters")

    op.drop_table("notification_preferences")

    op.drop_index("uq_executions_auto", table_name="playbook_executions")
    op.drop_index("ix_executions_owner_id", table_name="playbook_executions")
    op.drop_index("ix_executions_playbook_id", table_name="playbook_executions")
    op.drop_table("playbook_executions")

    op.drop_index("ix_playbooks_owner_id", table_name="playbooks")
    op.drop_table("playbooks")

    op.drop_index("ix_rules_owner_id", table_name="rules")
    op.drop_table("rules")

    op.drop_column("alerts", "rule_trace")
    op.drop_column("alerts", "tags")
