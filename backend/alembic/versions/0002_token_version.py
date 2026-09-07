"""Replace tokens_valid_from with an exact token_version counter.

JWT `iat` has one-second granularity, so a timestamp comparison cannot separate
a token minted in the same second as a password change — one would survive the
invalidation. A counter bumped on every credential change is exact.

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column(
                "token_version", sa.Integer(), nullable=False, server_default="1"
            )
        )
        batch.drop_column("tokens_valid_from")


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column(
                "tokens_valid_from",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.current_timestamp(),
            )
        )
        batch.drop_column("token_version")
