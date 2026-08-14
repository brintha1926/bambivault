"""Email verification and password-recovery token delivery."""

import hashlib
import logging
import os
import smtplib
from email.mime.text import MIMEText

import requests
from dotenv import load_dotenv
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


load_dotenv()


logger = logging.getLogger('bambivault')

SECRET_KEY = os.environ.get('SECRET_KEY', '')
SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM', SMTP_USER or 'no-reply@bambivault.local')
BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '')
EMAIL_FROM = os.environ.get('EMAIL_FROM', SMTP_FROM)
EMAIL_FROM_NAME = os.environ.get('EMAIL_FROM_NAME', 'BambiVault')
APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://127.0.0.1:5000')
IS_PRODUCTION = os.environ.get('FLASK_ENV', 'development').strip().lower() == 'production'

VERIFY_TOKEN_MAX_AGE = 60 * 60 * 24
RESET_TOKEN_MAX_AGE = 60 * 60

_serializer = URLSafeTimedSerializer(SECRET_KEY)


def _recipient_reference(to_addr: str) -> str:
    return hashlib.sha256(to_addr.strip().lower().encode('utf-8')).hexdigest()[:12]


def _send_with_brevo(to_addr: str, subject: str, body: str) -> bool:
    """Deliver a transactional email through Brevo's HTTPS API."""
    if not BREVO_API_KEY:
        logger.error('Brevo configuration incomplete | missing=BREVO_API_KEY')
        return False
    if not EMAIL_FROM:
        logger.error('Brevo configuration incomplete | missing=EMAIL_FROM')
        return False

    recipient_ref = _recipient_reference(to_addr)
    try:
        response = requests.post(
            'https://api.brevo.com/v3/smtp/email',
            headers={
                'accept': 'application/json',
                'api-key': BREVO_API_KEY,
                'content-type': 'application/json',
            },
            json={
                'sender': {'name': EMAIL_FROM_NAME, 'email': EMAIL_FROM},
                'to': [{'email': to_addr}],
                'subject': subject,
                'textContent': body,
            },
            timeout=12,
        )
        response.raise_for_status()
        logger.info('Email delivered through Brevo | recipient=%s', recipient_ref)
        return True
    except requests.RequestException as exc:
        status = getattr(exc.response, 'status_code', 'unavailable')
        logger.warning(
            'Brevo delivery failed | recipient=%s | status=%s',
            recipient_ref,
            status,
        )
        return False


def _send_with_smtp(to_addr: str, subject: str, body: str) -> bool:
    """Deliver through SMTP when it is configured and available."""
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        return False

    recipient_ref = _recipient_reference(to_addr)
    try:
        message = MIMEText(body, _charset='utf-8')
        message['Subject'] = subject
        message['From'] = SMTP_FROM
        message['To'] = to_addr
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_addr], message.as_string())
        logger.info('Email delivered through SMTP | recipient=%s', recipient_ref)
        return True
    except (OSError, smtplib.SMTPException):
        logger.warning('SMTP delivery failed | recipient=%s', recipient_ref)
        return False


def _send_email(to_addr: str, subject: str, body: str) -> bool:
    if _send_with_brevo(to_addr, subject, body):
        return True
    if _send_with_smtp(to_addr, subject, body):
        return True

    if IS_PRODUCTION:
        logger.error(
            'Email delivery unavailable in production | recipient=%s',
            _recipient_reference(to_addr),
        )
        return False

    logger.info('[LOCAL EMAIL] To: %s | Subject: %s\n%s', to_addr, subject, body)
    return False


def generate_verification_token(user_id: int) -> str:
    return _serializer.dumps({'uid': user_id, 'purpose': 'verify'})


def _password_fingerprint(password_hash: str) -> str:
    return hashlib.sha256(password_hash.encode('utf-8')).hexdigest()[:20]


def generate_reset_token(user) -> str:
    return _serializer.dumps({
        'uid': user.id,
        'purpose': 'reset',
        'ph': _password_fingerprint(user.password_hash),
    })


def generate_admin_reset_token(admin) -> str:
    return _serializer.dumps({
        'aid': admin.id,
        'purpose': 'admin-reset',
        'ph': _password_fingerprint(admin.password_hash),
    })


def parse_token(token: str, purpose: str, max_age: int):
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
    link = f'{APP_BASE_URL}/verify-email/{token}'
    body = (
        f'Hi {user.username},\n\n'
        'Verify your BambiVault account using the secure link below. '
        f'The link expires in 24 hours.\n\n{link}\n\n'
        'If you did not create this account, no action is required.'
    )
    return _send_email(user.email, 'Verify your BambiVault account', body)


def send_reset_email(user) -> bool:
    token = generate_reset_token(user)
    link = f'{APP_BASE_URL}/reset-password/{token}'
    body = (
        f'Hi {user.username},\n\n'
        'A password reset was requested for your BambiVault account. '
        f'Use the secure link below within one hour.\n\n{link}\n\n'
        'If you did not request this change, no action is required. '
        'Your vault master password and Account Key are not affected.'
    )
    return _send_email(user.email, 'Reset your BambiVault password', body)


def send_admin_reset_email(admin) -> bool:
    token = generate_admin_reset_token(admin)
    link = f'{APP_BASE_URL}/admin/reset-password/{token}'
    body = (
        'A password reset was requested for the BambiVault administrator account.\n\n'
        f'Use the secure link below within one hour.\n\n{link}\n\n'
        'If you did not request this change, no action is required.'
    )
    return _send_email(admin.email, 'Reset the BambiVault administrator password', body)
