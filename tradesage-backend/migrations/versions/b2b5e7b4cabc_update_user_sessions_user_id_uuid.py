"""convert user_sessions.user_id to UUID and add FK to users.id

Revision ID: b2b5e7b4cabc
Revises: af44c649a453
Create Date: 2025-06-24 11:36:30
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'b2b5e7b4cabc'
down_revision: Union[str, None] = 'af44c649a453'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Ensure no existing constraint (optional safe-drop)
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        # Drop FK if it exists
        batch_op.execute(
            "ALTER TABLE user_sessions DROP CONSTRAINT IF EXISTS fk_user_sessions_user_id_users"
        )

        # Alter column type from VARCHAR to UUID, casting existing values
        batch_op.alter_column(
            'user_id',
            existing_type=sa.String(length=50),
            type_=postgresql.UUID(as_uuid=True),
            postgresql_using='user_id::uuid',
            nullable=False,
        )

        # Create new foreign key to users.id
        batch_op.create_foreign_key(
            'fk_user_sessions_user_id_users',
            'users',
            ['user_id'], ['id'],
            ondelete='CASCADE'
        )


def downgrade() -> None:
    with op.batch_alter_table('user_sessions', schema=None) as batch_op:
        # Drop FK
        batch_op.drop_constraint('fk_user_sessions_user_id_users', type_='foreignkey')

        # Revert column back to VARCHAR
        batch_op.alter_column(
            'user_id',
            existing_type=postgresql.UUID(as_uuid=True),
            type_=sa.String(length=50),
            postgresql_using='user_id::text',
            nullable=False,
        )
