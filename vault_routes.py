"""Account, authentication, export, and encrypted-vault routes."""

import json
import base64
import io
import pyzipper
from reportlab.lib.pdfencrypt import StandardEncryption
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode

from models import db, User, VaultEntry, PasswordLog, UserOTP, UserSession
from feature_extraction import extract_features
from ml_classifier import classify_strength
from breach import check_breach
import vault_crypto as vc
import email_utils as eu
from security_utils import consume_rate_limit, clear_rate_limit, valid_email, valid_username

vault_bp = Blueprint('vault_bp', __name__)


# HELPERS

def _current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return User.query.get(uid)


def _current_vault_key():
    uid   = session.get('user_id')
    token = session.get('vault_token')
    if not uid or not token:
        return None
    return vc.get_vault_key(token, uid)


def _client_info():
    """Return informational client details for the session list."""
    ua = request.headers.get('User-Agent', 'Unknown device')
    if len(ua) > 255:
        ua = ua[:255]
    return request.remote_addr or 'Unknown', ua


def _create_login_session(user_id: int) -> str:
    """Create a revocable login session and return its token."""
    import secrets as _secrets
    token = _secrets.token_urlsafe(32)
    ip, ua = _client_info()
    row = UserSession(user_id=user_id, session_token=token, ip_address=ip, user_agent=ua)
    db.session.add(row)
    db.session.commit()
    return token


RESET_RATE_MAX    = 3     # requests
RESET_RATE_WINDOW = 300   # 5 minutes
TWOFA_RATE_MAX    = 8
TWOFA_RATE_WINDOW = 60


# ACCOUNT — register / login / logout / status

@vault_bp.route('/api/account/register', methods=['POST'])
def register():
    ip, _ = _client_info()
    if consume_rate_limit('user-register', ip, 5, 3600):
        return jsonify({'error': 'Too many registration attempts. Try again later.'}), 429
    data     = request.get_json(silent=True) or {}
    email    = data.get('email', '').strip().lower()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password')

    if not valid_email(email):
        return jsonify({'error': 'Enter a valid email address.'}), 400
    if not valid_username(username):
        return jsonify({'error': 'Username must be 3–50 characters and use only letters, numbers, dots, hyphens, or underscores.'}), 400
    if len(password) < 8 or len(password) > 256:
        return jsonify({'error': 'Password must contain between 8 and 256 characters.'}), 400
    if confirm_password is not None and password != confirm_password:
        return jsonify({'error': 'Passwords do not match.'}), 400

    if User.query.filter((User.email == email) | (User.username == username)).first():
        return jsonify({'error': 'An account with that email or username already exists.'}), 409

    user = User(email=email, username=username,
                password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    eu.send_verification_email(user)

    clear_rate_limit('user-register', ip)
    return jsonify({'status': 'ok', 'next': 'verify_email'})


@vault_bp.route('/api/account/login', methods=['POST'])
def login():
    ip, _ = _client_info()
    if consume_rate_limit('user-login', ip, 8, 900):
        return jsonify({'error': 'Too many sign-in attempts. Try again in 15 minutes.'}), 429
    data       = request.get_json(silent=True) or {}
    identifier = data.get('identifier', '').strip().lower()
    password   = data.get('password', '')

    user = User.query.filter(
        (User.email == identifier) | (User.username == identifier)
    ).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Incorrect email/username or password.'}), 401
    if not user.email_verified:
        return jsonify({'error': 'Verify your email before signing in.', 'verification_required': True}), 403
    clear_rate_limit('user-login', ip)

    otp = UserOTP.query.filter_by(user_id=user.id, enabled=True).first()
    if otp:
        # Password is correct but 2FA is required — do NOT establish a full
        # session yet. The pending uid is only enough to complete the 2FA
        # challenge, not to access any protected route.
        session['2fa_pending_uid'] = user.id
        return jsonify({'status': 'ok', 'requires_2fa': True})

    session['user_id'] = user.id
    session['login_session_id'] = _create_login_session(user.id)
    session.pop('vault_token', None)  # force vault re-unlock on every fresh login
    return jsonify({'status': 'ok', 'requires_2fa': False, 'vault_configured': user.vault_configured})


@vault_bp.route('/api/account/login/2fa-verify', methods=['POST'])
def login_2fa_verify():
    pending_uid = session.get('2fa_pending_uid')
    if not pending_uid:
        return jsonify({'error': 'Your sign-in session has expired. Start a new sign-in attempt.'}), 400

    ip, _ = _client_info()
    if consume_rate_limit('user-2fa', ip, TWOFA_RATE_MAX, TWOFA_RATE_WINDOW):
        return jsonify({'error': 'The maximum number of attempts has been reached. Try again after 60 seconds.'}), 429

    data  = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()
    recovery_code = data.get('recovery_code', '').strip()

    otp = UserOTP.query.filter_by(user_id=pending_uid, enabled=True).first()
    if not otp:
        return jsonify({'error': 'Two-factor authentication is not set up on this account.'}), 400

    verified = False

    if token:
        verified = pyotp.TOTP(otp.secret).verify(token, valid_window=1)
    elif recovery_code:
        codes = json.loads(otp.recovery_codes or '[]')
        for i, hashed in enumerate(codes):
            if check_password_hash(hashed, recovery_code):
                verified = True
                codes.pop(i)  # single-use — burn it immediately
                otp.recovery_codes = json.dumps(codes)
                db.session.commit()
                break

    if not verified:
        return jsonify({'error': 'The verification code is invalid or has expired.'}), 401

    session.pop('2fa_pending_uid', None)
    session['user_id'] = pending_uid
    session['login_session_id'] = _create_login_session(pending_uid)
    session.pop('vault_token', None)
    clear_rate_limit('user-2fa', ip)

    user = User.query.get(pending_uid)
    return jsonify({'status': 'ok', 'vault_configured': user.vault_configured})


@vault_bp.route('/api/account/logout', methods=['POST'])
def logout():
    login_sid = session.pop('login_session_id', None)
    if login_sid:
        UserSession.query.filter_by(session_token=login_sid).delete()
        db.session.commit()
    token = session.pop('vault_token', None)
    if token:
        vc.clear_vault_key(token)
    session.pop('user_id', None)
    return jsonify({'status': 'ok'})


@vault_bp.route('/api/account/status')
def status():
    user = _current_user()
    if not user:
        return jsonify({'logged_in': False})
    otp = UserOTP.query.filter_by(user_id=user.id, enabled=True).first()
    return jsonify({
        'logged_in':        True,
        'username':         user.username,
        'email':            user.email,
        'email_verified':   user.email_verified,
        'vault_configured': user.vault_configured,
        'vault_unlocked':   _current_vault_key() is not None,
        'twofa_enabled':    otp is not None,
        'created_at':       user.created_at.strftime('%Y-%m-%d') if user.created_at else None,
    })


# EMAIL VERIFICATION

@vault_bp.route('/api/account/resend-verification', methods=['POST'])
def resend_verification():
    user = _current_user()
    data = request.get_json(silent=True) or {}
    identifier = str(data.get('identifier', '')).strip().lower()
    ip, _ = _client_info()
    if not user:
        if consume_rate_limit('verification-resend-ip', ip, 5, 3600):
            return jsonify({'status': 'ok'})
        if identifier:
            user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()
    if user and not user.email_verified:
        eu.send_verification_email(user)
    return jsonify({'status': 'ok'})


@vault_bp.route('/verify-email/<token>')
def verify_email(token):
    uid, err = eu.parse_token(token, purpose='verify', max_age=eu.VERIFY_TOKEN_MAX_AGE)
    if err:
        return render_template('auth_result.html', title='Email verification unsuccessful',
                                message=err, success=False)

    user = User.query.get(uid)
    if not user:
        return render_template('auth_result.html', title='Email verification unsuccessful',
                                message='Account not found.', success=False)

    user.email_verified = True
    db.session.commit()
    return render_template('auth_result.html', title='Email Verified',
                            message='Your email has been verified. You can close this tab.',
                            success=True)


# FORGOT / RESET PASSWORD  (login password — NOT the vault master password)

@vault_bp.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot_password.html')


@vault_bp.route('/api/account/request-reset', methods=['POST'])
def request_reset():
    ip    = request.remote_addr
    data  = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()

    if consume_rate_limit('user-recovery-ip', ip or 'unknown', RESET_RATE_MAX, RESET_RATE_WINDOW) or consume_rate_limit('user-recovery-email', email, RESET_RATE_MAX, RESET_RATE_WINDOW):
        return jsonify({'status': 'ok'})

    user = User.query.filter_by(email=email).first()
    if user:
        eu.send_reset_email(user)

    return jsonify({'status': 'ok'})


@vault_bp.route('/reset-password/<token>')
def reset_password_page(token):
    uid, fingerprint, err = eu.parse_password_reset_token(token)
    user = db.session.get(User, uid) if uid else None
    if err or not user or fingerprint != eu._password_fingerprint(user.password_hash):
        return render_template('auth_result.html', title='Password-reset link unavailable',
                                message=err or 'This reset link is no longer valid.', success=False)
    return render_template('reset_password.html', token=token)


@vault_bp.route('/api/account/reset-password/<token>', methods=['POST'])
def do_reset_password(token):
    uid, fingerprint, err = eu.parse_password_reset_token(token)
    user = db.session.get(User, uid) if uid else None
    if err or not user or fingerprint != eu._password_fingerprint(user.password_hash):
        return jsonify({'error': err or 'This reset link is no longer valid.'}), 400

    data     = request.get_json(silent=True) or {}
    password = data.get('password', '')
    confirm  = data.get('confirm', '')

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters.'}), 400
    if password != confirm:
        return jsonify({'error': 'Passwords do not match.'}), 400

    user.password_hash = generate_password_hash(password)
    db.session.commit()

    # Login-password recovery does not change vault credentials.
    return jsonify({'status': 'ok'})


# TWO-FACTOR AUTHENTICATION (TOTP)

@vault_bp.route('/api/account/2fa/status')
def twofa_status():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    otp = UserOTP.query.filter_by(user_id=user.id).first()
    return jsonify({'enabled': bool(otp and otp.enabled)})


@vault_bp.route('/api/account/2fa/setup', methods=['POST'])
def setup_2fa():
    """Create a pending TOTP secret for verification."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    otp = UserOTP.query.filter_by(user_id=user.id).first()
    if otp and otp.enabled:
        return jsonify({'error': '2FA is already enabled. Disable it first to reconfigure.'}), 400

    secret = pyotp.random_base32()
    if otp:
        otp.secret = secret
    else:
        otp = UserOTP(user_id=user.id, secret=secret, enabled=False)
        db.session.add(otp)
    db.session.commit()

    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="BambiVault")
    qr  = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return jsonify({
        'secret':  secret,   # shown as manual-entry fallback under the QR code
        'qr_data': f'data:image/png;base64,{qr_b64}',
    })


@vault_bp.route('/api/account/2fa/verify', methods=['POST'])
def verify_2fa():
    """Completes 2FA setup: proves the user's authenticator app actually
    has the secret, then enables 2FA and issues one-time recovery codes."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    otp = UserOTP.query.filter_by(user_id=user.id).first()
    if not otp:
        return jsonify({'error': '2FA setup was not started. Please try again.'}), 400
    if otp.enabled:
        return jsonify({'error': '2FA is already enabled.'}), 400

    data  = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()

    if not pyotp.TOTP(otp.secret).verify(token, valid_window=1):
        return jsonify({'error': 'Incorrect code. Check your authenticator app and try again.'}), 401

    import secrets as _secrets
    codes = [_secrets.token_hex(4).upper() for _ in range(10)]   # e.g. "A1B2C3D4"
    otp.recovery_codes = json.dumps([generate_password_hash(c) for c in codes])
    otp.enabled = True
    db.session.commit()

    return jsonify({'status': 'ok', 'recovery_codes': codes})


@vault_bp.route('/api/account/2fa/disable', methods=['POST'])
def disable_2fa():
    """Requires the account's login password to disable — 2FA is a
    security boundary, so turning it off needs the same proof of identity
    as any other sensitive account action (mirrors /api/account/delete)."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    data     = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Incorrect password.'}), 401

    otp = UserOTP.query.filter_by(user_id=user.id).first()
    if otp:
        db.session.delete(otp)
        db.session.commit()

    return jsonify({'status': 'ok'})


# ACTIVE SESSIONS

@vault_bp.route('/api/account/sessions')
def list_sessions():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    current_token = session.get('login_session_id')
    rows = UserSession.query.filter_by(user_id=user.id) \
                             .order_by(UserSession.last_activity.desc()).all()
    return jsonify({'sessions': [r.to_dict(current_token) for r in rows]})


@vault_bp.route('/api/account/sessions/revoke', methods=['POST'])
def revoke_session():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    data = request.get_json(silent=True) or {}
    sid  = data.get('id')

    row = UserSession.query.filter_by(id=sid, user_id=user.id).first()
    if not row:
        return jsonify({'error': 'Session not found.'}), 404

    was_current = row.session_token == session.get('login_session_id')
    db.session.delete(row)
    db.session.commit()

    if was_current:
        # Revoking the current session also clears local authentication state.
        session.pop('user_id', None)
        session.pop('login_session_id', None)
        token = session.pop('vault_token', None)
        if token:
            vc.clear_vault_key(token)

    return jsonify({'status': 'ok', 'was_current': was_current})


# ACCOUNT DATA EXPORT (portability)

@vault_bp.route('/api/account/export')
def export_account_data():
    """Export account data, including vault entries when unlocked."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    logs = PasswordLog.query.filter_by(user_id=user.id) \
                             .order_by(PasswordLog.submitted_at.desc()).all()

    export = {
        'exported_at': __import__('datetime').datetime.utcnow().isoformat(),
        'profile': user.to_profile_dict(),
        'analysis_history': [l.to_dict() for l in logs],
    }

    key = _current_vault_key()
    if key:
        entries = VaultEntry.query.filter_by(user_id=user.id).all()
        export['vault_entries'] = [e.to_dict(key) for e in entries]
        export['vault_entries_note'] = 'Included because the vault was unlocked at export time.'
    else:
        export['vault_entries'] = None
        export['vault_entries_note'] = 'Vault was locked at export time — unlock it first to include entries.'

    buf = io.BytesIO(json.dumps(export, indent=2).encode('utf-8'))
    return send_file(buf, mimetype='application/json', as_attachment=True,
                      download_name=f'bambivault_export_{user.username}.json')





# SECURE EXPORT (PDF / TXT-in-ZIP, password-protected)

def _export_text_content(user, logs, entries):
    lines = [
        "BAMBIVAULT — ACCOUNT EXPORT", "=" * 40,
        f"Username: {user.username}", f"Email: {user.email}",
        f"Member since: {user.created_at.strftime('%Y-%m-%d') if user.created_at else '-'}",
        "", "ANALYSIS HISTORY", "-" * 20,
    ]
    for l in logs:
        d = l.to_dict()
        lines.append(f"{d['submitted_at']} | {d['strength_label']} | breach={d['breach_exposed']}")
    if entries:
        lines += ["", "VAULT ENTRIES", "-" * 20]
        for e in entries:
            lines.append(f"{e['site_name']} | user={e['username']} | pass={e['password']}")
    else:
        lines += ["", "(Vault was locked — entries not included.)"]
    return "\n".join(lines)


@vault_bp.route('/api/account/export-secure', methods=['POST'])
def export_secure():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    data = request.get_json(silent=True) or {}
    fmt = data.get('format', 'pdf')
    password = data.get('password', '')
    if len(password) < 6:
        return jsonify({'error': 'Choose a protection password of at least 6 characters.'}), 400

    logs = PasswordLog.query.filter_by(user_id=user.id).order_by(PasswordLog.submitted_at.desc()).all()
    key = _current_vault_key()
    entries = [e.to_dict(key) for e in VaultEntry.query.filter_by(user_id=user.id).all()] if key else []

    if fmt == 'pdf':
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        buf = io.BytesIO()
        enc = StandardEncryption(password, password + '_owner',
                                  canPrint=1, canModify=0, canCopy=0, canAnnotate=0)
        doc = SimpleDocTemplate(buf, pagesize=A4, encrypt=enc)
        styles = getSampleStyleSheet()
        story = [Paragraph("BambiVault — Account Export", styles['Title']),
                 Paragraph(f"User: {user.username}", styles['Normal']), Spacer(1, 12)]
        for l in logs:
            d = l.to_dict()
            story.append(Paragraph(f"{d['submitted_at']} — {d['strength_label']} — "
                                    f"breach: {d['breach_exposed']}", styles['Normal']))
        if entries:
            story.append(Spacer(1, 16))
            story.append(Paragraph("Vault entries", styles['Heading2']))
            for e in entries:
                story.append(Paragraph(f"{e['site_name']} — {e['username']} — {e['password']}",
                                        styles['Normal']))
        doc.build(story)
        buf.seek(0)
        return send_file(buf, mimetype='application/pdf', as_attachment=True,
                          download_name=f'bambivault_export_{user.username}.pdf')

    text_content = _export_text_content(user, logs, entries)
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, 'w', compression=pyzipper.ZIP_LZMA,
                              encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        zf.writestr('bambivault_export.txt', text_content)
    buf.seek(0)
    return send_file(buf, mimetype='application/zip', as_attachment=True,
                      download_name=f'bambivault_export_{user.username}.zip')


# SETTINGS PAGE + ACCOUNT DELETION

@vault_bp.route('/api/account/update-username', methods=['POST'])
def update_username():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    data = request.get_json(silent=True) or {}
    new_username = data.get('username', '').strip()
    if not valid_username(new_username):
        return jsonify({'error': 'Username must be 3–50 characters and use only letters, numbers, dots, hyphens, or underscores.'}), 400
    if User.query.filter(User.username == new_username, User.id != user.id).first():
        return jsonify({'error': 'That username is already taken.'}), 409
    user.username = new_username
    db.session.commit()
    return jsonify({'status': 'ok', 'username': new_username})



@vault_bp.route('/settings')
def settings_page():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    return render_template('settings.html')


@vault_bp.route('/api/account/delete', methods=['POST'])
def delete_account():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    data     = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Incorrect password.'}), 401

    VaultEntry.query.filter_by(user_id=user.id).delete()
    UserSession.query.filter_by(user_id=user.id).delete()
    UserOTP.query.filter_by(user_id=user.id).delete()

    # PasswordLog rows are anonymised (user_id -> NULL) rather than
    # deleted, so institutional trend data in the admin dashboard isn't
    # distorted by account deletions.
    PasswordLog.query.filter_by(user_id=user.id).update({'user_id': None})

    token = session.pop('vault_token', None)
    if token:
        vc.clear_vault_key(token)
    session.pop('login_session_id', None)

    db.session.delete(user)
    db.session.commit()

    session.pop('user_id', None)
    return jsonify({'status': 'ok'})


# VAULT SETUP / UNLOCK  (master password + Account Key)

@vault_bp.route('/api/vault/setup', methods=['POST'])
def vault_setup():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    if user.vault_configured:
        return jsonify({'error': 'Vault already configured for this account.'}), 400

    data            = request.get_json(silent=True) or {}
    master_password = data.get('master_password', '')
    confirm         = data.get('confirm', '')

    if len(master_password) < 8:
        return jsonify({'error': 'Master password must be at least 8 characters.'}), 400
    if master_password != confirm:
        return jsonify({'error': 'Master passwords do not match.'}), 400
    if check_password_hash(user.password_hash, master_password):
        return jsonify({'error': 'Your master password should be different from your login password — '
                                  'that separation is the whole point of the vault.'}), 400

    account_key = vc.generate_account_key()
    salt        = vc.generate_salt()
    verifier    = vc.make_verifier(master_password, account_key, salt)

    user.vault_salt       = salt
    user.vault_verifier   = verifier
    user.vault_configured = True
    db.session.commit()

    key   = vc.verify_master_password(master_password, account_key, salt, verifier)
    token = vc.store_vault_key(user.id, key, user.vault_auto_lock_minutes)
    session['vault_token'] = token

    return jsonify({'status': 'ok', 'account_key': account_key})


@vault_bp.route('/api/vault/unlock', methods=['POST'])
def vault_unlock():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    if not user.vault_configured:
        return jsonify({'error': 'Vault not set up yet.'}), 400

    data            = request.get_json(silent=True) or {}
    master_password = data.get('master_password', '')
    account_key     = data.get('account_key', '')

    key = vc.verify_master_password(master_password, account_key, user.vault_salt, user.vault_verifier)
    if not key:
        return jsonify({'error': 'Incorrect master password or Account Key.'}), 401

    token = vc.store_vault_key(user.id, key, user.vault_auto_lock_minutes)
    session['vault_token'] = token
    return jsonify({'status': 'ok'})


@vault_bp.route('/api/vault/lock', methods=['POST'])
def vault_lock():
    token = session.pop('vault_token', None)
    if token:
        vc.clear_vault_key(token)
    return jsonify({'status': 'ok'})


@vault_bp.route('/api/vault/reset', methods=['POST'])
def vault_reset():
    """Wipes the existing vault (all entries + vault_salt/verifier/config)
    so the user can run /api/vault/setup again from scratch. Requires the
    CURRENT vault master password as proof of intent."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    if not user.vault_configured:
        return jsonify({'error': 'Vault not set up yet.'}), 400

    data            = request.get_json(silent=True) or {}
    master_password = data.get('master_password', '')
    account_key     = data.get('account_key', '')

    key = vc.verify_master_password(master_password, account_key, user.vault_salt, user.vault_verifier)
    if not key:
        return jsonify({'error': 'Incorrect master password or Account Key.'}), 401

    VaultEntry.query.filter_by(user_id=user.id).delete()

    user.vault_salt       = None
    user.vault_verifier   = None
    user.vault_configured = False
    db.session.commit()

    token = session.pop('vault_token', None)
    if token:
        vc.clear_vault_key(token)

    return jsonify({'status': 'ok'})


@vault_bp.route('/api/vault/auto-lock', methods=['POST'])
def set_auto_lock():
    """Updates the per-user auto-lock timeout preference. Takes effect on
    the NEXT unlock — an already-open vault session keeps its original
    timeout rather than being silently extended or shortened mid-session."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    data    = request.get_json(silent=True) or {}
    minutes = data.get('minutes')

    if minutes is not None and (not isinstance(minutes, int) or minutes < 1 or minutes > 240):
        return jsonify({'error': 'Timeout must be between 1 and 240 minutes.'}), 400

    user.vault_auto_lock_minutes = minutes
    db.session.commit()
    return jsonify({'status': 'ok', 'minutes': minutes})


# VAULT HEALTH AUDIT

@vault_bp.route('/api/vault/health')
def vault_health():
    """Assess weak, breached, and reused vault credentials on demand."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    key = _current_vault_key()
    if not key:
        return jsonify({'error': 'Vault is locked.'}), 403

    entries = VaultEntry.query.filter_by(user_id=user.id).all()
    total = len(entries)
    weak_count = 0
    breached_count = 0
    seen_passwords = {}
    reused_count = 0

    for e in entries:
        from vault_crypto import decrypt_field
        pw = decrypt_field(key, e.enc_password)
        if not pw or pw == '[decryption failed]':
            continue

        feats = extract_features(pw)
        score, _, _ = classify_strength(feats)
        if score < 2:
            weak_count += 1

        breach_result = check_breach(pw)
        if breach_result.get('is_breached'):
            breached_count += 1

        seen_passwords[pw] = seen_passwords.get(pw, 0) + 1

    reused_count = sum(1 for c in seen_passwords.values() if c > 1)

    return jsonify({
        'total_entries':  total,
        'weak_count':     weak_count,
        'breached_count': breached_count,
        'reused_count':   reused_count,
    })


# VAULT ENTRY CRUD

@vault_bp.route('/api/vault/entries', methods=['GET'])
def list_entries():
    """List vault metadata without returning decrypted passwords."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    key = _current_vault_key()
    if not key:
        return jsonify({'error': 'Vault is locked.'}), 403

    entries = VaultEntry.query.filter_by(user_id=user.id).order_by(VaultEntry.site_name).all()
    return jsonify({'entries': [
        {
            'id':         e.id,
            'site_name':  e.site_name,
            'username':   vc.decrypt_field(key, e.enc_username),
            'email':      vc.decrypt_field(key, e.enc_email),
            'created_at': e.created_at.strftime('%Y-%m-%d %H:%M'),
        }
        for e in entries
    ]})


@vault_bp.route('/api/vault/entries/<int:entry_id>/reveal', methods=['POST'])
def reveal_entry_password(entry_id):
    """Decrypts and returns the password for exactly ONE entry, on
    explicit request (the 'Copy' button). This is the only route that
    ever sends a decrypted vault password to the browser."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    key = _current_vault_key()
    if not key:
        return jsonify({'error': 'Vault is locked.'}), 403

    entry = VaultEntry.query.filter_by(id=entry_id, user_id=user.id).first()
    if not entry:
        return jsonify({'error': 'Entry not found.'}), 404

    return jsonify({'password': vc.decrypt_field(key, entry.enc_password)})


@vault_bp.route('/api/vault/entries', methods=['POST'])
def add_entry():
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    key = _current_vault_key()
    if not key:
        return jsonify({'error': 'Vault is locked.'}), 403

    data      = request.get_json(silent=True) or {}
    site_name = data.get('site_name', '').strip()
    username_ = data.get('username', '').strip()
    email_    = data.get('email', '').strip()
    password_ = data.get('password', '')

    if not site_name or not password_:
        return jsonify({'error': 'Site name and password are required.'}), 400
    if len(site_name) > 120 or len(username_) > 255 or len(email_) > 254 or len(password_) > 4096:
        return jsonify({'error': 'One or more vault fields exceed the allowed length.'}), 400
    if email_ and not valid_email(email_):
        return jsonify({'error': 'Enter a valid email address or leave it blank.'}), 400

    entry = VaultEntry(
        user_id=user.id,
        site_name=site_name,
        enc_username=vc.encrypt_field(key, username_),
        enc_email=vc.encrypt_field(key, email_),
        enc_password=vc.encrypt_field(key, password_),
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({'status': 'ok', 'entry': entry.to_dict(key)})


@vault_bp.route('/api/vault/entries/<int:entry_id>', methods=['DELETE'])
def delete_entry(entry_id):
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401
    key = _current_vault_key()
    if not key:
        return jsonify({'error': 'Vault is locked.'}), 403

    entry = VaultEntry.query.filter_by(id=entry_id, user_id=user.id).first()
    if not entry:
        return jsonify({'error': 'Entry not found.'}), 404

    db.session.delete(entry)
    db.session.commit()
    return jsonify({'status': 'ok'})


@vault_bp.route('/api/vault/entries/<int:entry_id>', methods=['PUT'])
def update_entry(entry_id):
    """Update vault metadata and optionally replace its encrypted password."""
    user = _current_user()
    if not user:
        return jsonify({'error': 'Not logged in.'}), 401

    key = _current_vault_key()
    if not key:
        return jsonify({'error': 'Vault is locked.'}), 403

    entry = VaultEntry.query.filter_by(id=entry_id, user_id=user.id).first()
    if not entry:
        return jsonify({'error': 'Entry not found.'}), 404

    data = request.get_json(silent=True) or {}
    site_name = data.get('site_name', '').strip()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not site_name:
        return jsonify({'error': 'Site name is required.'}), 400
    if len(site_name) > 120 or len(username) > 255 or len(email) > 254 or len(password) > 4096:
        return jsonify({'error': 'One or more vault fields exceed the allowed length.'}), 400
    if email and not valid_email(email):
        return jsonify({'error': 'Enter a valid email address or leave it blank.'}), 400

    entry.site_name = site_name
    entry.enc_username = vc.encrypt_field(key, username)
    entry.enc_email = vc.encrypt_field(key, email)
    if password:
        entry.enc_password = vc.encrypt_field(key, password)

    db.session.commit()
    return jsonify({
        'status': 'ok',
        'entry': {
            'id': entry.id,
            'site_name': entry.site_name,
            'username': username,
            'email': email,
            'created_at': entry.created_at.strftime('%Y-%m-%d %H:%M'),
        }
    })
