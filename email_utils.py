"""Email verification and password-recovery token delivery."""

import hashlib
import html
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
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
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
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


def _send_with_resend(
    to_addr: str,
    subject: str,
    body: str,
    html_body: str | None = None,
) -> bool:
    """Deliver a transactional message through Resend's HTTPS API."""
    if not RESEND_API_KEY:
        return False
    if not EMAIL_FROM:
        logger.error('Resend configuration incomplete | missing=EMAIL_FROM')
        return False

    recipient_ref = _recipient_reference(to_addr)
    payload = {
        'from': f'{EMAIL_FROM_NAME} <{EMAIL_FROM}>',
        'to': [to_addr],
        'subject': subject,
        'text': body,
    }
    if html_body:
        payload['html'] = html_body

    try:
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'authorization': f'Bearer {RESEND_API_KEY}',
                'content-type': 'application/json',
            },
            json=payload,
            timeout=12,
        )
        response.raise_for_status()
        logger.info('Email delivered through Resend | recipient=%s', recipient_ref)
        return True
    except requests.RequestException as exc:
        status = getattr(exc.response, 'status_code', 'unavailable')
        logger.warning(
            'Resend delivery failed | recipient=%s | status=%s',
            recipient_ref,
            status,
        )
        return False


def _send_with_brevo(
    to_addr: str,
    subject: str,
    body: str,
    html_body: str | None = None,
) -> bool:
    """Deliver a transactional email through Brevo's HTTPS API."""
    if not BREVO_API_KEY:
        logger.error('Brevo configuration incomplete | missing=BREVO_API_KEY')
        return False
    if not EMAIL_FROM:
        logger.error('Brevo configuration incomplete | missing=EMAIL_FROM')
        return False

    recipient_ref = _recipient_reference(to_addr)
    try:
        payload = {
            'sender': {'name': EMAIL_FROM_NAME, 'email': EMAIL_FROM},
            'to': [{'email': to_addr}],
            'subject': subject,
            'textContent': body,
        }
        if html_body:
            payload['htmlContent'] = html_body

        response = requests.post(
            'https://api.brevo.com/v3/smtp/email',
            headers={
                'accept': 'application/json',
                'api-key': BREVO_API_KEY,
                'content-type': 'application/json',
            },
            json=payload,
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


def _send_with_smtp(
    to_addr: str,
    subject: str,
    body: str,
    html_body: str | None = None,
) -> bool:
    """Deliver through SMTP when it is configured and available."""
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        return False

    recipient_ref = _recipient_reference(to_addr)
    try:
        message = MIMEMultipart('alternative')
        message['Subject'] = subject
        message['From'] = SMTP_FROM
        message['To'] = to_addr
        message.attach(MIMEText(body, 'plain', 'utf-8'))
        if html_body:
            message.attach(MIMEText(html_body, 'html', 'utf-8'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_addr], message.as_string())
        logger.info('Email delivered through SMTP | recipient=%s', recipient_ref)
        return True
    except (OSError, smtplib.SMTPException):
        logger.warning('SMTP delivery failed | recipient=%s', recipient_ref)
        return False


def _send_email(
    to_addr: str,
    subject: str,
    body: str,
    html_body: str | None = None,
) -> bool:
    if _send_with_resend(to_addr, subject, body, html_body):
        return True
    if _send_with_brevo(to_addr, subject, body, html_body):
        return True
    if _send_with_smtp(to_addr, subject, body, html_body):
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


def _transactional_email(
    *,
    greeting: str,
    heading: str,
    introduction: str,
    action_label: str,
    action_url: str,
    expiry: str,
    security_notice: str,
    supporting_note: str | None = None,
) -> tuple[str, str]:
    """Build matching plain-text and branded HTML transactional emails."""
    text_sections = [
        greeting,
        '',
        heading,
        introduction,
        '',
        f'{action_label}: {action_url}',
        '',
        expiry,
    ]
    if supporting_note:
        text_sections.extend(['', supporting_note])
    text_sections.extend([
        '',
        f'Security notice: {security_notice}',
        '',
        'BambiVault Security',
        'This is an automated service message. Please do not reply.',
    ])

    safe = {
        'greeting': html.escape(greeting),
        'heading': html.escape(heading),
        'introduction': html.escape(introduction),
        'action_label': html.escape(action_label),
        'action_url': html.escape(action_url, quote=True),
        'expiry': html.escape(expiry),
        'security_notice': html.escape(security_notice),
        'supporting_note': html.escape(supporting_note) if supporting_note else '',
    }
    supporting_html = ''
    if supporting_note:
        supporting_html = (
            '<p style="margin:18px 0 0;color:#475569;font-size:14px;line-height:1.6;">'
            f"{safe['supporting_note']}</p>"
        )

    html_content = f'''<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#f1f5f9;font-family:Inter,Arial,sans-serif;color:#0f172a;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">{safe['introduction']}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f1f5f9;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;overflow:hidden;box-shadow:0 8px 24px rgba(15,23,42,.06);">
        <tr><td style="height:4px;background:#0d9488;"></td></tr>
        <tr><td style="padding:26px 36px 18px;border-bottom:1px solid #e2e8f0;">
          <div style="font-size:20px;font-weight:800;letter-spacing:-.3px;">Bambi<span style="color:#0d9488;">Vault</span></div>
          <div style="margin-top:4px;color:#64748b;font-size:12px;letter-spacing:.08em;text-transform:uppercase;">Account security notification</div>
        </td></tr>
        <tr><td style="padding:32px 36px;">
          <p style="margin:0 0 18px;color:#334155;font-size:15px;line-height:1.6;">{safe['greeting']}</p>
          <h1 style="margin:0 0 12px;font-size:24px;line-height:1.3;letter-spacing:-.4px;color:#0f172a;">{safe['heading']}</h1>
          <p style="margin:0;color:#475569;font-size:15px;line-height:1.65;">{safe['introduction']}</p>
          <table role="presentation" cellspacing="0" cellpadding="0" style="margin:26px 0 22px;"><tr><td style="border-radius:8px;background:#0d9488;">
            <a href="{safe['action_url']}" style="display:inline-block;padding:13px 22px;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;">{safe['action_label']}</a>
          </td></tr></table>
          <p style="margin:0;color:#64748b;font-size:13px;line-height:1.55;">{safe['expiry']}</p>
          {supporting_html}
          <div style="margin-top:24px;padding:14px 16px;border-left:3px solid #0d9488;background:#f0fdfa;border-radius:6px;color:#334155;font-size:13px;line-height:1.55;">
            <strong>Security notice</strong><br>{safe['security_notice']}
          </div>
          <p style="margin:24px 0 6px;color:#64748b;font-size:12px;line-height:1.5;">If the button is unavailable, copy this address into your browser:</p>
          <p style="margin:0;word-break:break-all;color:#0f766e;font-size:12px;line-height:1.5;">{safe['action_url']}</p>
        </td></tr>
        <tr><td style="padding:20px 36px;background:#f8fafc;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;line-height:1.5;">
          BambiVault Security<br>This is an automated service message. Please do not reply.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>'''
    return '\n'.join(text_sections), html_content


def send_verification_email(user) -> bool:
    token = generate_verification_token(user.id)
    link = f'{APP_BASE_URL}/verify-email/{token}'
    body, html_body = _transactional_email(
        greeting=f'Hello {user.username},',
        heading='Confirm your email address',
        introduction=(
            'Confirm this address to complete your BambiVault account setup '
            'and enable secure account recovery.'
        ),
        action_label='Confirm email address',
        action_url=link,
        expiry='This secure link expires in 24 hours and can be used once.',
        security_notice=(
            'If you did not create this account, you can disregard this message.'
        ),
    )
    return _send_email(
        user.email,
        'Confirm your BambiVault email address',
        body,
        html_body,
    )


def send_reset_email(user) -> bool:
    token = generate_reset_token(user)
    link = f'{APP_BASE_URL}/reset-password/{token}'
    body, html_body = _transactional_email(
        greeting=f'Hello {user.username},',
        heading='Reset your account password',
        introduction=(
            'We received a request to reset the password used to sign in '
            'to your BambiVault account.'
        ),
        action_label='Reset account password',
        action_url=link,
        expiry='This secure link expires in one hour and can be used once.',
        supporting_note=(
            'This change applies only to your account password. Your vault master '
            'password and Account Key remain unchanged.'
        ),
        security_notice=(
            'If you did not request this reset, no action is required and your '
            'current password remains valid.'
        ),
    )
    return _send_email(
        user.email,
        'BambiVault account password reset',
        body,
        html_body,
    )


def send_admin_reset_email(admin) -> bool:
    token = generate_admin_reset_token(admin)
    link = f'{APP_BASE_URL}/admin/reset-password/{token}'
    body, html_body = _transactional_email(
        greeting='Hello Administrator,',
        heading='Reset the administrator password',
        introduction=(
            'We received a request to reset the password for the BambiVault '
            'administrator account.'
        ),
        action_label='Reset administrator password',
        action_url=link,
        expiry='This secure link expires in one hour and can be used once.',
        security_notice=(
            'If you did not request this reset, no action is required. Review '
            'administrative access if this request was unexpected.'
        ),
    )
    return _send_email(
        admin.email,
        'BambiVault administrator password reset',
        body,
        html_body,
    )
