"""baseline BambiVault schema

Revision ID: e9b958ce9a1b
Revises:
Create Date: 2026-08-13 23:20:06.198610

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e9b958ce9a1b'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())
    # Existing SQLite installations already have these tables from the legacy
    # runner. A fresh PostgreSQL database receives the model-defined schema.
    if 'app_user' not in existing:
        from models import db
        db.metadata.create_all(bind=bind)


def downgrade():
    from models import db
    bind = op.get_bind()
    db.metadata.drop_all(bind=bind)
