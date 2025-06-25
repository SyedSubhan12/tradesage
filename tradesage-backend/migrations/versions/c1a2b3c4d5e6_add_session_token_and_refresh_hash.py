"""add session_token and refresh_token_hash columns to user_sessions

Revision ID: c1a2b3c4d5e6
Revises: b2b5e7b4cabc
Create Date: 2025-06-24 12:55:30
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c1a2b3c4d5e6'
down_revision: Union[str, None] = 'b2b5e7b4cabc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    bind = op.get_bind()
    # Add session_token column if it doesn't exist
    bind.execute(sa.text("""
        ALTER TABLE user_sessions
        ADD COLUMN IF NOT EXISTS session_token VARCHAR(64);
    """))
    # Add refresh_token_hash column if it doesn't exist
    bind.execute(sa.text("""
        ALTER TABLE user_sessions
        ADD COLUMN IF NOT EXISTS refresh_token_hash VARCHAR(255);
    """))
    # Create unique index on session_token if it doesn't exist
    bind.execute(sa.text("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'ix_user_sessions_session_token'
            ) THEN
                CREATE UNIQUE INDEX ix_user_sessions_session_token ON user_sessions(session_token);
            END IF;
        END;
        $$;
    """))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("DROP INDEX IF EXISTS ix_user_sessions_session_token;"))
    bind.execute(sa.text("ALTER TABLE user_sessions DROP COLUMN IF EXISTS refresh_token_hash;"))
    bind.execute(sa.text("ALTER TABLE user_sessions DROP COLUMN IF EXISTS session_token;"))
