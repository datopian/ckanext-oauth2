"""empty message

Revision ID: ac01a2c4ab0a
Revises: 
Create Date: 2025-05-29 17:16:07.160422

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ac01a2c4ab0a'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'user_token',
        sa.Column('user_name', sa.Text(), primary_key=True),
        sa.Column('access_token', sa.Text(), nullable=True),
        sa.Column('token_type', sa.Text(), nullable=True),
        sa.Column('refresh_token', sa.Text(), nullable=True),
        sa.Column('expires_in', sa.Text(), nullable=True),
        sa.Column('provider', sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_table('user_token')