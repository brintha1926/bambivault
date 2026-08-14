import pytest


def test_post_without_csrf_token_is_rejected(app_module):
    app_module.app.config['TESTING'] = True
    with app_module.app.test_client() as client:
        response = client.post('/analyse', json={'password': 'Example!234'})
    assert response.status_code == 400
    assert 'Security token' in response.get_json()['error']


def test_admin_login_is_rate_limited(client, app_module):
    for _ in range(5):
        response = client.post('/admin/login', data={'password': 'incorrect'})
        assert response.status_code == 200
    response = client.post('/admin/login', data={'password': 'incorrect'})
    assert response.status_code == 429


def test_analysis_result_rejects_mismatched_label(app_module):
    with pytest.raises(ValueError):
        app_module.validate_analysis_result(
            {'entropy': 20.0, 'length': 10}, 1, 'Very Strong', 80.0,
            {'risk_score': 10, 'risk_label': 'Low Risk', 'breach_count': 0},
        )


def test_verification_resend_does_not_require_login(client, monkeypatch):
    import vault_routes
    sent = []
    monkeypatch.setattr(vault_routes.eu, 'send_verification_email', lambda user: sent.append(user.email))
    response = client.post('/api/account/resend-verification', json={'identifier': 'unknown@example.com'})
    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}
    assert sent == []
