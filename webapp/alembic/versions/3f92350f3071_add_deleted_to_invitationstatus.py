"""add DELETED to invitationstatus

Revision ID: 3f92350f3071
Revises: 9cd3491e245b
Create Date: 2026-05-14 00:28:22.765594

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '3f92350f3071'
down_revision: Union[str, Sequence[str], None] = '9cd3491e245b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE invitationstatus ADD VALUE IF NOT EXISTS 'DELETED'")


def downgrade() -> None:
    op.execute("""
        ALTER TABLE tinyinvitation
            ALTER COLUMN status TYPE VARCHAR
            USING status::VARCHAR
    """)
    op.execute("DROP TYPE invitationstatus")
    op.execute("""
        CREATE TYPE invitationstatus AS ENUM (
            'CREATED',
            'OPENED',
            'LOCKED',
            'EXCEPTION',
            'ISSUED'
        )
    """)
    op.execute("""
        ALTER TABLE tinyinvitation
            ALTER COLUMN status TYPE invitationstatus
            USING status::invitationstatus
    """)
