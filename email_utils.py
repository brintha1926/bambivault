"""Email verification and password-recovery token delivery."""

import os
import smtplib
import logging
import hashlib
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

logger = logging.getLogger('bambivault')

SECRET_KEY   = os.environ.get('SECRET_KEY', '')
SMTP_HOST    = os.environ.get('SMTP_HOST', '')
SMTP_PORT    = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER    = os.environ.get('SMTP_USER', '')
SMTP_PASS    = os.environ.get('SMTP_PASS', '')
SMTP_FROM    = os.environ.get('SMTP_FROM', SMTP_USER or 'no-reply@bambivault.local')
APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://127.0.0.1:5000')
IS_PRODUCTION = os.environ.get('FLASK_ENV', 'development').strip().lower() == 'production'

VERIFY_TOKEN_MAX_AGE = 60 * 60 * 24   # 24 hours
RESET_TOKEN_MAX_AGE  = 60 * 60        # 1 hour — shorter, since a leaked
                                        # reset link is more dangerous than
                                        # a leaked verification link

_serializer = URLSafeTimedSerializer(SECRET_KEY)


def _send_email(to_addr: str, subject: str, body: str) -> bool:
    if SMTP_HOST and SMTP_USER and SMTP_PASS:
        try:
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From']    = SMTP_FROM
            msg['To']      = to_addr
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_FROM, [to_addr], msg.as_string())
            logger.info(f"Email sent | to={to_addr} | subject={subject}")
            return True
        except Exception as e:
            logger.warning(f"Email send FAILED | to={to_addr} | error={e} — falling back to log output")

    # Fallback — no SMTP configured, or send failed: log the content so the
    # full flow (including link) is still testable locally without a mail
    # server. Check logs/bambivault.log for the actual link.
    if IS_PRODUCTION:
        logger.error('Email delivery unavailable in production | to=%s | subject=%s', to_addr, subject)
        return False
    logger.info(f"[EMAIL FALLBACK — no SMTP or send failed] To: {to_addr} | Subject: {subject}\n{body}")
    return False


def generate_verification_token(user_id: int) -> str:
    return _serializer.dumps({'uid': user_id, 'purpose': 'verify'})


def _password_fingerprint(password_hash: str) -> str:
    return hashlib.sha256(password_hash.encode('utf-8')).hexdigest()[:20]


def generate_reset_token(user) -> str:
    return _serializer.dumps({'uid': user.id, 'purpose': 'reset', 'ph': _password_fingerprint(user.password_hash)})


def generate_admin_reset_token(admin) -> str:
    return _serializer.dumps({'aid': admin.id, 'purpose': 'admin-reset', 'ph': _password_fingerprint(admin.password_hash)})


def parse_token(token: str, purpose: str, max_age: int):
    """Returns (user_id, None) if valid, or (None, error_message) on failure."""
    try:
        data = _serializer.loads(token, max_age=max_age)
    except SignatureExpired:
        return None, 'This link has expired. Request a new verification link.'
    except BadSignature:
        return None, 'This link is invalid.'
    if data.get('purpose') != purpose:
        return None, 'This link is invalid.'
    return data.get('uid'), None


def parse_password_reset_token(token: str):
    try:
        data = _serializer.loads(token, max_age=RESET_TOKEN_MAX_AGE)
    except SignatureExpired:
        return None, None, 'This reset link has expired.'
    except BadSignature:
        return None, None, 'This reset link is invalid.'
    if data.get('purpose') != 'reset':
        return None, None, 'This reset link is invalid.'
    return data.get('uid'), data.get('ph'), None


def parse_admin_reset_token(token: str):
    """Return the administrator id from a valid, unexpired reset token."""
    try:
        data = _serializer.loads(token, max_age=RESET_TOKEN_MAX_AGE)
    except SignatureExpired:
        return None, None, 'This reset link has expired.'
    except BadSignature:
        return None, None, 'This reset link is invalid.'
    if data.get('purpose') != 'admin-reset':
        return None, None, 'This reset link is invalid.'
    return data.get('aid'), data.get('ph'), None


def send_verification_email(user) -> bool:
    token = generate_verification_token(user.id)
    link  = f"{APP_BASE_URL}/verify-email/{token}"
    body  = (
        f"Hi {user.username},\n\n"
        f"Please verify your BambiVault account by clicking the link below "
        f"(expires in 24 hours):\n\n{link}\n\n"
        f"If you didn't create this account, you can ignore this email."
    )
    return _send_email(user.email, "Verify your BambiVault account", body)


def send_reset_email(user) -> bool:
    token = generate_reset_token(user)
    link  = f"{APP_BASE_URL}/reset-password/{token}"
    body  = (
        f"Hi {user.username},\n\n"
        f"We received a request to reset your BambiVault login password. "
        f"Click the link below to choose a new one (expires in 1 hour):\n\n"
        f"{link}\n\n"
        f"If you didn't request this, you can safely ignore this email — "
        f"your password won't be changed.\n\n"
        f"Note: resetting your LOGIN password does not affect your vault. "
        f"Your vault master password and Account Key are separate and "
        f"unaffected by this reset."
    )
    return _send_email(user.email, "Reset your BambiVault password", body)


def send_admin_reset_email(admin) -> bool:
    token = generate_admin_reset_token(admin)
    link = f"{APP_BASE_URL}/admin/reset-password/{token}"
    body = (
        "A password reset was requested for the BambiVault administrator account.\n\n"
        f"Use the secure link below within one hour:\n\n{link}\n\n"
        "If you did not request this change, no action is required."
    )
    return _send_email(admin.email, "Reset the BambiVault administrator password", body)
