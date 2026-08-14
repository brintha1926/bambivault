"""One-time, verified BambiVault SQLite to PostgreSQL data transfer.

Usage (PowerShell):
  $env:POSTGRES_DATABASE_URL='postgresql+psycopg://...'
  python migrate_sqlite_to_postgres.py --source instance/password_logs.db

The destination must contain no application data. Vault ciphertext is copied
unchanged and is never decrypted by this utility.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sqlalchemy import MetaData, create_engine, func, inspect, select, text


TRANSFER_ORDER = (
    'app_user', 'admin_account', 'password_analysis_log', 'user_otp',
    'admin_otp', 'user_session', 'vault_entry', 'rate_limit_bucket',
)


def normalize_postgres_url(url: str) -> str:
    if url.startswith('postgres://'):
        return 'postgresql+psycopg://' + url[len('postgres://'):]
    if url.startswith('postgresql://'):
        return 'postgresql+psycopg://' + url[len('postgresql://'):]
    return url


def transfer(source_path: Path, destination_url: str, dry_run: bool = False) -> dict[str, int]:
    if not source_path.is_file():
        raise RuntimeError(f'SQLite database not found: {source_path}')
    destination_url = normalize_postgres_url(destination_url)
    if not destination_url.startswith('postgresql+psycopg://'):
        raise RuntimeError('POSTGRES_DATABASE_URL must point to PostgreSQL.')

    source = create_engine(f'sqlite:///{source_path.resolve().as_posix()}')
    destination = create_engine(destination_url, pool_pre_ping=True)
    source_meta = MetaData()
    destination_meta = MetaData()
    source_meta.reflect(bind=source)
    destination_meta.reflect(bind=destination)

    missing = [name for name in TRANSFER_ORDER if name in source_meta.tables and name not in destination_meta.tables]
    if missing:
        raise RuntimeError('Destination schema is missing: ' + ', '.join(missing) + '. Run the application migration first.')

    source_counts: dict[str, int] = {}
    with source.connect() as src, destination.begin() as dst:
        initial_destination_counts = {
            name: dst.execute(
                select(func.count()).select_from(destination_meta.tables[name])
            ).scalar_one()
            for name in TRANSFER_ORDER
            if name in destination_meta.tables
        }
        for name in TRANSFER_ORDER:
            if name not in source_meta.tables:
                continue
            src_table = source_meta.tables[name]
            dst_table = destination_meta.tables[name]
            rows = [dict(row._mapping) for row in src.execute(select(src_table))]
            source_counts[name] = len(rows)
            destination_count = dst.execute(select(func.count()).select_from(dst_table)).scalar_one()
            # Loading the Flask application to run Alembic creates the initial
            # administrator account. On an otherwise empty destination it is
            # safe to replace that seed with the administrator copied from the
            # existing SQLite database.
            if name == 'admin_account' and destination_count == 1 and rows:
                seeded_ids = dst.execute(select(dst_table.c.id)).scalars().all()
                other_data = any(
                    count
                    for table_name, count in initial_destination_counts.items()
                    if table_name != 'admin_account'
                )
                if seeded_ids == [1] and not other_data:
                    dst.execute(dst_table.delete())
                    destination_count = 0
            if destination_count:
                raise RuntimeError(f'Destination table {name} is not empty ({destination_count} rows).')
            if rows and not dry_run:
                dst.execute(dst_table.insert(), rows)

        if dry_run:
            dst.rollback()
            return source_counts

        for name, expected in source_counts.items():
            dst_table = destination_meta.tables[name]
            actual = dst.execute(select(func.count()).select_from(dst_table)).scalar_one()
            if actual != expected:
                raise RuntimeError(f'Count mismatch for {name}: expected {expected}, found {actual}.')

        if destination.dialect.name == 'postgresql':
            for name in TRANSFER_ORDER:
                table = destination_meta.tables.get(name)
                if table is None or 'id' not in table.c or not table.c.id.primary_key:
                    continue
                dst.execute(text(
                    "SELECT setval(pg_get_serial_sequence(:table_name, 'id'), "
                    "COALESCE((SELECT MAX(id) FROM \"" + name + "\"), 1), "
                    "(SELECT COUNT(*) > 0 FROM \"" + name + "\"))"
                ), {'table_name': name})

    with destination.connect() as dst:
        broken = dst.execute(text('''
            SELECT COUNT(*) FROM vault_entry v
            LEFT JOIN app_user u ON u.id = v.user_id WHERE u.id IS NULL
        ''')).scalar_one()
        if broken:
            raise RuntimeError(f'Foreign-key validation failed: {broken} orphaned vault entries.')
    return source_counts


def main() -> int:
    parser = argparse.ArgumentParser(description='Transfer BambiVault data from SQLite to PostgreSQL.')
    parser.add_argument('--source', default='instance/password_logs.db', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    url = os.environ.get('POSTGRES_DATABASE_URL', '').strip()
    if not url:
        print('Set POSTGRES_DATABASE_URL before running this command.', file=sys.stderr)
        return 2
    counts = transfer(args.source, url, dry_run=args.dry_run)
    action = 'Validated' if args.dry_run else 'Transferred and verified'
    print(action + ':')
    for table, count in counts.items():
        print(f'  {table}: {count}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
