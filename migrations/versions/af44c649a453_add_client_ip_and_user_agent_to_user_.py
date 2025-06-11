"""add client_ip and user_agent to user_sessions table

Revision ID: af44c649a453
Revises: d77fa6d0ecb9
Create Date: 2025-06-09 12:15:03.044065

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'af44c649a453'
down_revision: Union[str, None] = 'd77fa6d0ecb9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('user_sessions', sa.Column('client_ip', sa.String(length=45), nullable=True))
    op.add_column('user_sessions', sa.Column('user_agent', sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column('user_sessions', 'user_agent')
    op.drop_column('user_sessions', 'client_ip')
