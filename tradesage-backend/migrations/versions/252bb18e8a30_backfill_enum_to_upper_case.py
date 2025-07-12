"""backfill enum to upper case

Revision ID: 252bb18e8a30
Revises: f7c4a195eafd
Create Date: 2025-06-24 09:12:41.607400

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '252bb18e8a30'
down_revision: Union[str, None] = 'f7c4a195eafd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        UPDATE user_sessions
        SET state = UPPER(state::text)::sessionstate
        WHERE state IN ('active','suspended','expired','terminated');
    """)

def downgrade() -> None:
    op.execute("""
        UPDATE user_sessions
        SET state = LOWER(state::text)::sessionstate
        WHERE state IN ('ACTIVE','SUSPENDED','EXPIRED','TERMINATED');
    """)
