"""session and two-factor hardening

Revision ID: 4c7a2d918e31
Revises: e9b958ce9a1b
"""
from alembic import op
import sqlalchemy as sa


revision = '4c7a2d918e31'
down_revision = 'e9b958ce9a1b'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    user_otp_columns = {c['name']: c for c in inspector.get_columns('user_otp')}
    if 'last_used_step' not in user_otp_columns or user_otp_columns['secret']['type'].length != 255:
        with op.batch_alter_table('user_otp') as batch:
            if user_otp_columns['secret']['type'].length != 255:
                batch.alter_column('secret', existing_type=sa.String(32), type_=sa.String(255), nullable=False)
            if 'last_used_step' not in user_otp_columns:
                batch.add_column(sa.Column('last_used_step', sa.BigInteger(), nullable=True))
    admin_otp_columns = {c['name']: c for c in inspector.get_columns('admin_otp')}
    if 'last_used_step' not in admin_otp_columns or admin_otp_columns['secret']['type'].length != 255:
        with op.batch_alter_table('admin_otp') as batch:
            if admin_otp_columns['secret']['type'].length != 255:
                batch.alter_column('secret', existing_type=sa.String(32), type_=sa.String(255), nullable=False)
            if 'last_used_step' not in admin_otp_columns:
                batch.add_column(sa.Column('last_used_step', sa.BigInteger(), nullable=True))
    admin_columns = {c['name'] for c in inspector.get_columns('admin_account')}
    if 'auth_version' not in admin_columns:
        with op.batch_alter_table('admin_account') as batch:
            batch.add_column(sa.Column('auth_version', sa.Integer(), nullable=False, server_default='1'))
    indexes = {i['name'] for i in inspector.get_indexes('app_user')}
    if 'uq_app_user_username_lower' not in indexes:
        op.create_index('uq_app_user_username_lower', 'app_user', [sa.text('lower(username)')], unique=True)


def downgrade():
    op.drop_index('uq_app_user_username_lower', table_name='app_user')
    with op.batch_alter_table('admin_account') as batch:
        batch.drop_column('auth_version')
    with op.batch_alter_table('admin_otp') as batch:
        batch.drop_column('last_used_step')
        batch.alter_column('secret', existing_type=sa.String(255), type_=sa.String(32), nullable=False)
    with op.batch_alter_table('user_otp') as batch:
        batch.drop_column('last_used_step')
        batch.alter_column('secret', existing_type=sa.String(255), type_=sa.String(32), nullable=False)
