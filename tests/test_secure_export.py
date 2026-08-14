"""Secure account exports must remain available when the vault is locked."""

import pytest
from werkzeug.security import generate_password_hash

from models import db, User


@pytest.mark.parametrize(
    ("fmt", "expected_mimetype"),
    [("pdf", "application/pdf"), ("zip", "application/zip")],
)
def test_secure_export_does_not_fail_when_vault_is_locked(
    client, app_module, fmt, expected_mimetype
):
    with app_module.app.app_context():
        user = User(
            email=f"export-{fmt}@example.test",
            username=f"export_{fmt}",
            password_hash=generate_password_hash("TestPassword!42"),
            email_verified=True,
            vault_configured=True,
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    with client.session_transaction() as session:
        session["user_id"] = user_id
        session.pop("vault_token", None)

    response = client.post(
        "/api/account/export-secure",
        json={"format": fmt, "password": "ExportProtection!42"},
    )

    assert response.status_code == 200
    assert response.mimetype == expected_mimetype
    assert response.data
