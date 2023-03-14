"""remove category column

Revision ID: eccbc6854314
Revises: b9576629e182
Create Date: 2023-03-14 17:20:43.122767

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'eccbc6854314'
down_revision = 'b9576629e182'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column('user', 'category')


def downgrade() -> None:
    op.add_column('user', sa.Column('category', sa.String(25)))