"""Shared isolated pytest fixtures."""

import os
import sys
import tempfile
import pytest

# Configuration is set before importing the application.
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("FLASK_DEBUG", "False")
os.environ.setdefault("FLASK_ENV", "development")  # keep cookies non-Secure for the test client

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _StubModel:
    """Stands in for the real RandomForestClassifier so tests don't
    depend on model/strength_model_rf_v3.pkl existing or on scikit-learn
    reproducing a specific trained result. Always predicts 'Medium' (2)
    with 80% confidence."""

    def predict(self, vector):
        return [2]

    def predict_proba(self, vector):
        return [[0.05, 0.05, 0.8, 0.05, 0.05]]


@pytest.fixture(scope="session", autouse=True)
def _ensure_model_file_exists():
    """Creates a throwaway model/*.pkl before app.py is ever imported, so
    joblib.load(...) at app.py's module level doesn't blow up in CI or on
    a fresh checkout that hasn't run train_model_v3.py yet. Skipped
    entirely if a real model file is already present."""
    import joblib
    model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model")
    model_path = os.path.join(model_dir, "strength_model_rf_v3.pkl")
    created = False
    if not os.path.exists(model_path):
        os.makedirs(model_dir, exist_ok=True)
        joblib.dump(_StubModel(), model_path)
        created = True
    yield
    if created:
        os.remove(model_path)


@pytest.fixture()
def app_module(monkeypatch, tmp_path):
    """
    Imports the Flask app fresh for each test. Because app.py loads the
    ML model from disk at import time (joblib.load(...)), tests that
    don't care about the ML model can monkeypatch classify_strength
    directly — see the `client` fixture below for the common case.
    """
    import app as app_mod
    yield app_mod


@pytest.fixture()
def client(app_module):
    app_module.app.config['TESTING'] = True
    with app_module.app.test_client() as c:
        c.get('/')
        with c.session_transaction() as sess:
            c.environ_base['HTTP_X_CSRF_TOKEN'] = sess['_csrf_token']
        yield c


@pytest.fixture(autouse=True)
def _reset_rate_limiters(app_module):
    """Every test starts with a clean rate-limit window so one test's
    requests never bleed into another's and cause spurious 429s."""
    from models import db, RateLimitBucket
    with app_module.app.app_context():
        RateLimitBucket.query.delete()
        db.session.commit()
    yield
    with app_module.app.app_context():
        RateLimitBucket.query.delete()
        db.session.commit()


@pytest.fixture()
def mock_hibp_not_found(monkeypatch):
    """Simulates HIBP returning 'ok' with no matching suffix — i.e. a
    password that has never appeared in a known breach."""
    import breach

    def fake_query(prefix):
        return {"status": "ok", "hashes": {}}

    monkeypatch.setattr(breach, "_query_hibp", fake_query)


@pytest.fixture()
def mock_hibp_found(monkeypatch):
    """Simulates HIBP returning a match — password has been breached
    12345 times. Uses a fixed fake suffix; check_breach() computes the
    real SHA-1 of the input password itself, so the test patches
    hashlib indirectly by making the fake response match ANY suffix
    via a wildcard-style dict subclass."""
    import breach

    class _AnyMatchDict(dict):
        def get(self, key, default=None):
            return 12345

    def fake_query(prefix):
        return {"status": "ok", "hashes": _AnyMatchDict()}

    monkeypatch.setattr(breach, "_query_hibp", fake_query)


@pytest.fixture()
def mock_hibp_error(monkeypatch):
    """Simulates a total HIBP outage — check_breach() should gracefully
    fall back to local-pattern-only assessment rather than raising."""
    import breach

    def fake_query(prefix):
        return {"status": "error", "hashes": {}}

    monkeypatch.setattr(breach, "_query_hibp", fake_query)


@pytest.fixture()
def isolated_breach_cache(monkeypatch, tmp_path):
    """Points breach.py's SQLite cache at a throwaway file so tests never
    read/write your real data/breach_cache.db, and each test starts with
    a guaranteed-empty cache."""
    from collections import defaultdict
    import breach
    cache_path = tmp_path / "test_breach_cache.db"
    monkeypatch.setattr(breach, "CACHE_DB_PATH", str(cache_path))
    monkeypatch.setattr(breach, "_rate_tracker", defaultdict(list))
    yield cache_path
