from pathlib import Path

import pytest

from migrate_sqlite_to_postgres import normalize_postgres_url, transfer


def test_normalizes_managed_postgres_urls():
    assert normalize_postgres_url('postgres://u:p@host/db') == 'postgresql+psycopg://u:p@host/db'
    assert normalize_postgres_url('postgresql://u:p@host/db') == 'postgresql+psycopg://u:p@host/db'


def test_transfer_requires_postgres_destination(tmp_path):
    source = tmp_path / 'source.db'
    source.touch()
    with pytest.raises(RuntimeError, match='must point to PostgreSQL'):
        transfer(source, 'sqlite:///destination.db')


def test_transfer_requires_existing_source(tmp_path):
    with pytest.raises(RuntimeError, match='not found'):
        transfer(Path(tmp_path / 'missing.db'), 'postgresql+psycopg://u:p@host/db')
