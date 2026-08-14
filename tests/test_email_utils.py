"""Email-provider routing tests."""

import requests

import email_utils


class _SuccessfulResponse:
    status_code = 201

    def raise_for_status(self) -> None:
        return None


def test_brevo_delivery_uses_https_api(monkeypatch):
    captured = {}

    def fake_post(url, *, headers, json, timeout):
        captured.update({
            'url': url,
            'headers': headers,
            'json': json,
            'timeout': timeout,
        })
        return _SuccessfulResponse()

    monkeypatch.setattr(email_utils, 'BREVO_API_KEY', 'test-api-key')
    monkeypatch.setattr(email_utils, 'EMAIL_FROM', 'verified@example.com')
    monkeypatch.setattr(email_utils, 'EMAIL_FROM_NAME', 'BambiVault')
    monkeypatch.setattr(email_utils.requests, 'post', fake_post)

    assert email_utils._send_with_brevo(
        'member@example.com',
        'Verify account',
        'Verification message',
    ) is True
    assert captured['url'] == 'https://api.brevo.com/v3/smtp/email'
    assert captured['headers']['api-key'] == 'test-api-key'
    assert captured['json']['sender'] == {
        'name': 'BambiVault',
        'email': 'verified@example.com',
    }
    assert captured['json']['to'] == [{'email': 'member@example.com'}]
    assert captured['json']['textContent'] == 'Verification message'
    assert captured['timeout'] == 12


def test_brevo_failure_returns_false(monkeypatch):
    def failed_post(*args, **kwargs):
        raise requests.ConnectionError('provider unavailable')

    monkeypatch.setattr(email_utils, 'BREVO_API_KEY', 'test-api-key')
    monkeypatch.setattr(email_utils, 'EMAIL_FROM', 'verified@example.com')
    monkeypatch.setattr(email_utils.requests, 'post', failed_post)

    assert email_utils._send_with_brevo(
        'member@example.com',
        'Verify account',
        'Verification message',
    ) is False


def test_email_prefers_brevo_before_smtp(monkeypatch):
    calls = []
    monkeypatch.setattr(
        email_utils,
        '_send_with_brevo',
        lambda *args: calls.append('brevo') or True,
    )
    monkeypatch.setattr(
        email_utils,
        '_send_with_smtp',
        lambda *args: calls.append('smtp') or True,
    )

    assert email_utils._send_email('member@example.com', 'Subject', 'Body') is True
    assert calls == ['brevo']


def test_email_falls_back_to_smtp(monkeypatch):
    calls = []
    monkeypatch.setattr(
        email_utils,
        '_send_with_brevo',
        lambda *args: calls.append('brevo') or False,
    )
    monkeypatch.setattr(
        email_utils,
        '_send_with_smtp',
        lambda *args: calls.append('smtp') or True,
    )

    assert email_utils._send_email('member@example.com', 'Subject', 'Body') is True
    assert calls == ['brevo', 'smtp']
