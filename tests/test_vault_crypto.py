"""Vault key derivation, encryption, and tamper-resistance tests."""

import pytest
import vault_crypto as vc


@pytest.fixture()
def vault_setup():
    """Create complete vault credentials for a test."""
    master_password = "correct horse battery staple 42"
    account_key = vc.generate_account_key()
    salt = vc.generate_salt()
    verifier = vc.make_verifier(master_password, account_key, salt)
    return {
        "master_password": master_password,
        "account_key": account_key,
        "salt": salt,
        "verifier": verifier,
    }


def test_account_key_format():
    key = vc.generate_account_key()
    # 20 chars grouped into 5 blocks of 4, dash-separated -> "XXXX-XXXX-XXXX-XXXX-XXXX"
    parts = key.split("-")
    assert len(parts) == 5
    assert all(len(p) == 4 for p in parts)
    assert len(key.replace("-", "")) == 20


def test_correct_master_password_and_account_key_unlock(vault_setup):
    key = vc.verify_master_password(
        vault_setup["master_password"],
        vault_setup["account_key"],
        vault_setup["salt"],
        vault_setup["verifier"],
    )
    assert key is not None


def test_wrong_master_password_is_rejected(vault_setup):
    key = vc.verify_master_password(
        "wrong password entirely",
        vault_setup["account_key"],
        vault_setup["salt"],
        vault_setup["verifier"],
    )
    assert key is None


def test_wrong_account_key_is_rejected(vault_setup):
    """The whole point of the Account Key as a second factor: a correct
    master password ALONE must not be sufficient."""
    key = vc.verify_master_password(
        vault_setup["master_password"],
        "WRNG-WRNG-WRNG-WRNG-WRNG",
        vault_setup["salt"],
        vault_setup["verifier"],
    )
    assert key is None


def test_account_key_dashes_and_case_are_forgiving(vault_setup):
    """_normalise_account_key should treat 'a1b2 c3d4...' the same as
    'A1B2-C3D4...' for manual entry forgiveness, without weakening
    the derivation itself."""
    messy_key = vault_setup["account_key"].lower().replace("-", " ")
    key = vc.verify_master_password(
        vault_setup["master_password"],
        messy_key,
        vault_setup["salt"],
        vault_setup["verifier"],
    )
    assert key is not None


def test_encrypt_decrypt_round_trip(vault_setup):
    key = vc.verify_master_password(
        vault_setup["master_password"],
        vault_setup["account_key"],
        vault_setup["salt"],
        vault_setup["verifier"],
    )
    assert key is not None

    plaintext = "hunter2-super-secret-site-password!"
    ciphertext = vc.encrypt_field(key, plaintext)

    assert ciphertext != plaintext
    assert vc.decrypt_field(key, ciphertext) == plaintext


def test_decrypt_with_wrong_key_fails_safely(vault_setup):
    """Decrypting with the WRONG derived key must return the documented
    '[decryption failed]' sentinel rather than raising or, worse,
    silently returning garbage that looks like a real password."""
    key = vc.verify_master_password(
        vault_setup["master_password"],
        vault_setup["account_key"],
        vault_setup["salt"],
        vault_setup["verifier"],
    )
    ciphertext = vc.encrypt_field(key, "some secret value")

    other_salt = vc.generate_salt()
    wrong_key = vc._derive_key("a totally different password", vault_setup["account_key"], other_salt)

    result = vc.decrypt_field(wrong_key, ciphertext)
    assert result == "[decryption failed]"


def test_empty_field_encrypts_and_decrypts_as_empty(vault_setup):
    key = vc.verify_master_password(
        vault_setup["master_password"],
        vault_setup["account_key"],
        vault_setup["salt"],
        vault_setup["verifier"],
    )
    assert vc.encrypt_field(key, "") == ""
    assert vc.decrypt_field(key, "") == ""


def test_session_key_store_round_trip():
    """store_vault_key -> get_vault_key should return the same key bytes
    for the correct (token, user_id) pair, and None for a mismatched
    user_id (prevents one session's token being reused for another
    account even if somehow leaked)."""
    fake_key = b"0" * 32
    token = vc.store_vault_key(user_id=1, key=fake_key)

    assert vc.get_vault_key(token, user_id=1) == fake_key
    assert vc.get_vault_key(token, user_id=999) is None

    vc.clear_vault_key(token)
    assert vc.get_vault_key(token, user_id=1) is None


def test_different_salts_produce_different_keys():
    """Same master password + same Account Key but different salts must
    derive DIFFERENT keys — otherwise the salt is decorative."""
    master_password = "same password for both"
    account_key = vc.generate_account_key()

    salt_a = vc.generate_salt()
    salt_b = vc.generate_salt()

    key_a = vc._derive_key(master_password, account_key, salt_a)
    key_b = vc._derive_key(master_password, account_key, salt_b)

    assert key_a != key_b
