"""update_user_sessions_state_enum

Revision ID: 5039a1606b3e
Revises: c1a2b3c4d5e6
Create Date: 2025-06-24 08:16:05.670559

"""
from typing import Sequence, Union
# import sqlenum
# from sqlalchemy.dialects.postgresql import Enum
from sqlalchemy.types import Enum as SQLEnum
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5039a1606b3e'
down_revision: Union[str, None] = 'c1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop default constraint if it exists
    op.execute("ALTER TABLE user_sessions ALTER COLUMN state DROP DEFAULT")

    # Rename existing enum
    op.execute("ALTER TYPE sessionstate RENAME TO sessionstate_old")

    # Create new enum
    op.execute("CREATE TYPE sessionstate AS ENUM('active', 'suspended', 'expired', 'terminated')")

    # Update the column type
    op.execute("ALTER TABLE user_sessions ALTER COLUMN state TYPE sessionstate USING state::text::sessionstate")

    # Drop the old enum
    op.execute("DROP TYPE sessionstate_old")

    # Set the new default value
    op.execute("ALTER TABLE user_sessions ALTER COLUMN state SET DEFAULT 'active'")


def downgrade() -> None:
    op.alter_column('user_sessions', 'state',
                   type_=sa.String(20),
                   postgresql_using='state::text',
                   nullable=True)
    op.execute("DROP TYPE IF EXISTS sessionstate")
