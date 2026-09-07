"""Baseline: users, alerts, audit_log.

PLAN D18 — Alembic is the sole schema authority. This migration, not
create_all, is what brings a database into existence.

Revision ID: 0001
Revises:
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=128), nullable=False),
        sa.Column(
            "role", sa.String(length=20), nullable=False, server_default="viewer"
        ),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "tokens_valid_from",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "alerts",
        sa.Column("id", sa.String(length=16), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("attack_type", sa.String(length=40), nullable=False),
        sa.Column("src_ip", sa.String(length=45), nullable=False),
        sa.Column("dest_ip", sa.String(length=45), nullable=False),
        sa.Column("dest_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=10), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("mitre_technique", sa.String(length=20), nullable=True),
        sa.Column(
            "ioc_checked", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("ioc_reputation", sa.Integer(), nullable=True),
        sa.Column("vt_ip", sa.String(length=20), nullable=True),
        sa.Column("vt_hash", sa.String(length=80), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("classify_latency_ms", sa.Float(), nullable=True),
        sa.Column("enrich_latency_ms", sa.Float(), nullable=True),
        sa.Column("reasoning_latency_ms", sa.Float(), nullable=True),
        sa.Column("trace", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column(
            "degraded", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
    )
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_attack_type", "alerts", ["attack_type"])
    op.create_index("ix_alerts_src_ip", "alerts", ["src_ip"])
    op.create_index("ix_alerts_source", "alerts", ["source"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=32), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_audit_created_at", "audit_log", ["created_at"])
    op.create_index("ix_audit_action", "audit_log", ["action"])
    op.create_index("ix_audit_resource_type", "audit_log", ["resource_type"])
    op.create_index("ix_audit_actor_id", "audit_log", ["actor_id"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("alerts")
    op.drop_table("users")
