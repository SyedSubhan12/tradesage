# migrations/versions/<new_rev>_drop_legacy_session_id.py
from alembic import op
import sqlalchemy as sa
from typing import Sequence, Union

revision: str = "f7c4a195eafd"
down_revision: Union[str, None] = "5039a1606b3e"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # If the column still exists, drop it
    op.execute(
        """
        ALTER TABLE user_sessions
        DROP COLUMN IF EXISTS session_id;
        """
    )


def downgrade() -> None:
    # Re-create the column (nullable) for rollback
    op.add_column(
        "user_sessions",
        sa.Column("session_id", sa.String(64), nullable=True),
    )