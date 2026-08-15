"""Password analysis and strengthening endpoint tests."""

import pytest


def test_analyse_rejects_empty_password(client):
    resp = client.post("/analyse", json={"password": ""})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_analyse_returns_expected_shape(client, mock_hibp_not_found, isolated_breach_cache, monkeypatch):
    import ai_feedback
    # Force the AI path to fall back so the test doesn't depend on a real
    # GROQ_API_KEY or network access.
    monkeypatch.setattr(ai_feedback, "GROQ_API_KEY", "")

    resp = client.post("/analyse", json={"password": "Xk9#mLp2vQ7zUnique"})
    assert resp.status_code == 200

    data = resp.get_json()
    for field in ("strength_label", "strength_score", "behaviour_profile",
                  "entropy", "breach_found", "breach_risk", "recommendations"):
        assert field in data

    assert isinstance(data["recommendations"], list)
    assert 1 <= len(data["recommendations"]) <= 3


def test_analyse_rate_limit_kicks_in(client, mock_hibp_not_found, isolated_breach_cache, monkeypatch, app_module):
    import ai_feedback
    monkeypatch.setattr(ai_feedback, "GROQ_API_KEY", "")
    monkeypatch.setattr(app_module, "RATE_LIMIT_MAX", 2)

    r1 = client.post("/analyse", json={"password": "test-password-one"})
    r2 = client.post("/analyse", json={"password": "test-password-two"})
    r3 = client.post("/analyse", json={"password": "test-password-three"})

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429


def test_health_endpoint_reports_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_render_health_endpoint_reports_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_admin_stats_uses_portable_daily_trend_query(client, app_module):
    from datetime import datetime
    from models import db, PasswordLog

    with app_module.app.app_context():
        PasswordLog.query.delete()
        db.session.commit()

        row = PasswordLog(
            hash_prefix="ABCDE",
            strength_label="Weak",
            entropy=12.0,
            breach_exposed=True,
            breach_risk="Critical",
            submitted_at=datetime(2026, 8, 14, 8, 30),
        )
        db.session.add(row)
        db.session.commit()

    with client.session_transaction() as session:
        session["is_admin"] = True

    response = client.get("/api/admin/stats")
    assert response.status_code == 200
    assert response.get_json()["breach_trend"][-1]["day"] == "2026-08-14"


def test_strengthen_returns_three_distinct_variants(client):
    original = "amy"
    resp = client.post("/strengthen", json={"password": original})

    assert resp.status_code == 200
    data = resp.get_json()
    variants = data["variants"]
    assert len(variants) == 3
    passwords = [item["password"] for item in variants]
    assert len(set(passwords)) == 3
    assert original not in passwords
