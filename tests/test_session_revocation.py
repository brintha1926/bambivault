from werkzeug.security import generate_password_hash

from models import db, User, UserSession
import email_utils


def test_revoked_session_cannot_use_account_api(client, app_module):
    with app_module.app.app_context():
        user = User(email='revoked@example.test', username='revoked_user',
                    password_hash=generate_password_hash('Password!42'), email_verified=True)
        db.session.add(user)
        db.session.commit()
        row = UserSession(user_id=user.id, session_token='revoked-token')
        db.session.add(row)
        db.session.commit()
        user_id = user.id

    with client.session_transaction() as session:
        session['user_id'] = user_id
        session['login_session_id'] = 'revoked-token'

    with app_module.app.app_context():
        UserSession.query.filter_by(session_token='revoked-token').delete()
        db.session.commit()

    response = client.get('/api/account/export')
    assert response.status_code == 401


def test_password_reset_revokes_all_sessions(client, app_module):
    with app_module.app.app_context():
        user = User(email='reset-revoke@example.test', username='reset_revoke',
                    password_hash=generate_password_hash('OldPassword!42'), email_verified=True)
        db.session.add(user)
        db.session.commit()
        db.session.add(UserSession(user_id=user.id, session_token='other-browser'))
        db.session.commit()
        user_id = user.id
        token = email_utils.generate_reset_token(user)

    response = client.post(f'/api/account/reset-password/{token}', json={
        'password': 'NewPassword!42', 'confirm': 'NewPassword!42'
    })
    assert response.status_code == 200
    with app_module.app.app_context():
        assert UserSession.query.filter_by(user_id=user_id).count() == 0
