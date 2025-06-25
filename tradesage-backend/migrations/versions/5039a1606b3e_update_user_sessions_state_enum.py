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
    # Create the enum type if it doesn't exist
    op.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'sessionstate') THEN
            CREATE TYPE sessionstate AS ENUM ('active', 'suspended', 'expired', 'terminated');
        END IF;
    END
    $$;
    """)
    
    # Drop default constraint if it exists
    op.execute("""
    ALTER TABLE user_sessions 
    ALTER COLUMN state DROP DEFAULT;
    """)
    
    # Convert existing values to the new enum type
    op.execute("""
    DO $$
    BEGIN
        -- First update any invalid values to 'active'
        UPDATE user_sessions 
        SET state = 'active' 
        WHERE state IS NULL OR state NOT IN ('active', 'suspended', 'expired', 'terminated');
        
        -- Now alter the column type
        EXECUTE 'ALTER TABLE user_sessions ALTER COLUMN state TYPE sessionstate USING state::text::sessionstate';
    END
    $$;
    """)
    
    # Set the default value
    op.execute("""
    ALTER TABLE user_sessions 
    ALTER COLUMN state SET DEFAULT 'active'::sessionstate;
    """)
    
    # Make the column NOT NULL
    op.alter_column('user_sessions', 'state', 
                   existing_type=sa.Enum('active', 'suspended', 'expired', 'terminated', name='sessionstate'),
                   nullable=False)


def downgrade() -> None:
    # Convert back to string type
    op.alter_column('user_sessions', 'state',
                   type_=sa.String(20),
                   postgresql_using='state::text',
                   nullable=True)
    
    # Drop the enum type if no longer used
    op.execute("""
    DROP TYPE IF EXISTS sessionstate;
    """)
