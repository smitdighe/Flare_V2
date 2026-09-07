"""Phase 5 — the notification log.

One row per dispatch decision: sent, suppressed or failed. PLAN §8.3 requires
suppressions to be recorded rather than silently skipped, so this table is the
evidence the presence logic worked, not just an outbox.

`user_id` is SET NULL rather than CASCADE: deleting a user must not erase the
record that mail was sent on their behalf. `alert_id` carries no foreign key at
all — the log outlives the alerts table's retention.

PLAN D18 — Alembic is the sole schema authority. There is no create_all.

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notification_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("alert_id", sa.String(length=16), nullable=True),
        sa.Column("severity", sa.String(length=10), nullable=True),
        sa.Column(
            "rollup_count", sa.Integer(), nullable=False, server_default=sa.text("1")
        ),
        sa.Column("recipient", sa.String(length=320), nullable=True),
        sa.Column(
            "attempts", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
    )
    op.create_index(
        "ix_notification_log_user_id", "notification_log", ["user_id"]
    )
    op.create_index(
        "ix_notification_log_created_at", "notification_log", ["created_at"]
    )
    op.create_index(
        "ix_notification_log_outcome", "notification_log", ["outcome"]
    )


def downgrade() -> None:
    op.drop_index("ix_notification_log_outcome", table_name="notification_log")
    op.drop_index("ix_notification_log_created_at", table_name="notification_log")
    op.drop_index("ix_notification_log_user_id", table_name="notification_log")
    op.drop_table("notification_log")
