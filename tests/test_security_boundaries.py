import pytest
import pyotp
from types import SimpleNamespace
from werkzeug.security import generate_password_hash


def test_post_without_csrf_token_is_rejected(app_module):
    app_module.app.config['TESTING'] = True
    with app_module.app.test_client() as client:
        response = client.post('/analyse', json={'password': 'Example!234'})
    assert response.status_code == 400
    assert 'Security token' in response.get_json()['error']


def test_csp_blocks_script_attributes_and_uses_nonce(client):
    response = client.get('/')
    policy = response.headers['Content-Security-Policy']
    assert "script-src-attr 'none'" in policy
    assert "script-src 'self' 'nonce-" in policy
    assert "script-src 'self' 'unsafe-inline'" not in policy


def test_sensitive_api_responses_are_not_cached(client):
    response = client.get('/api/account/status')
    assert response.headers['Cache-Control'] == 'no-store, private'
    assert response.headers['Pragma'] == 'no-cache'


def test_admin_login_is_rate_limited(client, app_module):
    for _ in range(5):
        response = client.post('/admin/login', data={'password': 'incorrect'})
        assert response.status_code == 200
    response = client.post('/admin/login', data={'password': 'incorrect'})
    assert response.status_code == 429


def test_registration_limit_allows_uat_on_shared_network(client):
    for _ in range(15):
        response = client.post('/api/account/register', json={})
        assert response.status_code == 400

    response = client.post('/api/account/register', json={})
    assert response.status_code == 429
    assert response.get_json()['error'] == (
        'Registration is temporarily unavailable for this network. '
        'Please try again in 15 minutes.'
    )


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


def test_recovery_code_hashes_are_fast_and_backward_compatible(app_module):
    from security_utils import hash_recovery_code, verify_recovery_code

    with app_module.app.app_context():
        current = hash_recovery_code('A1B2C3D4')
        assert current.startswith('hmac-sha256$')
        assert verify_recovery_code(current, 'a1b2c3d4')
        assert not verify_recovery_code(current, 'FFFFFFFF')

        legacy = generate_password_hash('A1B2C3D4')
        assert verify_recovery_code(legacy, 'a1b2c3d4')


def test_totp_verification_uses_timezone_independent_unix_time(
    client, monkeypatch
):
    import security_utils
    from security_utils import verify_totp_once

    fixed_time = 1_800_000_000
    secret = pyotp.random_base32()
    token = pyotp.TOTP(secret).at(fixed_time)
    monkeypatch.setattr(security_utils, 'unix_time', lambda: fixed_time)
    monkeypatch.setattr(security_utils, 'decrypt_totp_secret', lambda _: secret)
    monkeypatch.setattr(
        security_utils, 'encrypt_totp_secret', lambda value: f'encrypted:{value}'
    )

    otp = SimpleNamespace(secret='encrypted-secret', last_used_step=None)
    assert verify_totp_once(otp, token, valid_window=1)
    assert not verify_totp_once(otp, token, valid_window=1)


def test_user_twofa_setup_returns_loadable_same_origin_qr(client, app_module):
    from models import db, User, UserSession

    with app_module.app.app_context():
        user = User(
            email='qr-setup@example.test',
            username='qr_setup_user',
            password_hash=generate_password_hash('AccountPassword!42'),
            email_verified=True,
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id
        login_token = 'qr-setup-session'
        db.session.add(UserSession(user_id=user_id, session_token=login_token))
        db.session.commit()

    with client.session_transaction() as session:
        session['user_id'] = user_id
        session['login_session_id'] = login_token

    setup = client.post(
        '/api/account/2fa/setup',
        json={'password': 'AccountPassword!42'},
    )
    assert setup.status_code == 200
    qr_url = setup.get_json()['qr_url']
    assert qr_url.startswith('/api/account/2fa/qr?')

    qr = client.get(qr_url)
    assert qr.status_code == 200
    assert qr.mimetype == 'image/png'
    assert qr.data.startswith(b'\x89PNG\r\n\x1a\n')
