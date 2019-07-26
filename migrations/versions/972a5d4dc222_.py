"""empty message

Revision ID: 972a5d4dc222
Revises: d43fc5e828b1
Create Date: 2019-07-24 15:00:31.326129

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '972a5d4dc222'
down_revision = 'd43fc5e828b1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('form',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=140), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_form_timestamp'), 'form', ['timestamp'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_form_timestamp'), table_name='form')
    op.drop_table('form')
    # ### end Alembic commands ###