"""Small versioned schema runner for BambiVault deployments.

Each migration is recorded once in schema_migration. Table creation uses the
SQLAlchemy model metadata with checkfirst=True, making the initial adoption safe
for both existing installations and new databases.
"""
from datetime import datetime
from sqlalchemy import text


MIGRATIONS = (
    (1, 'core account, analysis, vault, OTP, and session tables', (
        'app_user', 'password_analysis_log', 'vault_entry', 'user_otp', 'user_session',
    )),
    (2, 'administrator account and two-factor authentication tables', (
        'admin_account', 'admin_otp',
    )),
    (3, 'persistent authentication rate limiting', ('rate_limit_bucket',)),
)


def run_database_migrations(db):
    engine = db.engine
    with engine.begin() as connection:
        connection.execute(text(
            'CREATE TABLE IF NOT EXISTS schema_migration ('
            'version INTEGER PRIMARY KEY, description VARCHAR(255) NOT NULL, applied_at DATETIME NOT NULL)'
        ))
        applied = {row[0] for row in connection.execute(text('SELECT version FROM schema_migration'))}

    for version, description, table_names in MIGRATIONS:
        if version in applied:
            continue
        with engine.begin() as connection:
            for table_name in table_names:
                db.metadata.tables[table_name].create(bind=connection, checkfirst=True)
            connection.execute(
                text('INSERT INTO schema_migration(version, description, applied_at) VALUES (:v, :d, :a)'),
                {'v': version, 'd': description, 'a': datetime.utcnow()},
            )
