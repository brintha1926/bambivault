"""Vault key derivation, encryption, verification, and session-key storage.

Keys are derived from the master password and Account Key using
PBKDF2-HMAC-SHA256. Vault fields use authenticated Fernet encryption.
"""

import os
import time
import string
import base64
import hashlib
import secrets
from typing import Optional, TypedDict
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 480_000
SALT_BYTES = 16

VAULT_SESSION_TIMEOUT = 15 * 60  # default: 15 minutes of inactivity before auto-lock

# token -> {"key": bytes, "user_id": int, "last_used": float, "timeout": int}
class VaultKeyRecord(TypedDict):
    key: bytes
    user_id: int
    last_used: float
    timeout: int


VAULT_KEY_STORE: dict[str, VaultKeyRecord] = {}


# ACCOUNT KEY GENERATION

def generate_account_key() -> str:
    """Generate a grouped, high-entropy Account Key."""
    charset = string.ascii_uppercase + string.digits
    raw = ''.join(secrets.choice(charset) for _ in range(20))
    return '-'.join(raw[i:i + 4] for i in range(0, 20, 4))


def _normalise_account_key(account_key: str) -> str:
    """Normalise formatting without changing Account Key material."""
    return account_key.replace('-', '').replace(' ', '').upper()


# KEY DERIVATION

def generate_salt() -> str:
    return base64.urlsafe_b64encode(os.urandom(SALT_BYTES)).decode()


def _derive_key(master_password: str, account_key: str, salt_b64: str) -> bytes:
    salt = base64.urlsafe_b64decode(salt_b64.encode())
    combined_material = f"{master_password}::{_normalise_account_key(account_key)}"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw = kdf.derive(combined_material.encode('utf-8'))
    return base64.urlsafe_b64encode(raw)  # Fernet needs a urlsafe-b64 32-byte key


def make_verifier(master_password: str, account_key: str, salt_b64: str) -> str:
    """Create a one-way verifier for the combined vault credentials."""
    key = _derive_key(master_password, account_key, salt_b64)
    return hashlib.sha256(key).hexdigest()


def verify_master_password(master_password: str, account_key: str, salt_b64: str, verifier: str):
    """Return the derived key when both vault credentials are valid."""
    key = _derive_key(master_password, account_key, salt_b64)
    if hashlib.sha256(key).hexdigest() == verifier:
        return key
    return None


def encrypt_field(key: bytes, plaintext: str) -> str:
    if not plaintext:
        return ''
    return Fernet(key).encrypt(plaintext.encode('utf-8')).decode('utf-8')


def decrypt_field(key: bytes, token: str) -> str:
    if not token:
        return ''
    try:
        return Fernet(key).decrypt(token.encode('utf-8')).decode('utf-8')
    except InvalidToken:
        return '[decryption failed]'


# SERVER-SIDE VAULT SESSION KEY STORE

def _purge_expired():
    now = time.time()
    expired = [t for t, v in VAULT_KEY_STORE.items()
               if now - v['last_used'] > v.get('timeout', VAULT_SESSION_TIMEOUT)]
    for t in expired:
        del VAULT_KEY_STORE[t]


def store_vault_key(user_id: int, key: bytes,
                    timeout_minutes: Optional[int] = None) -> str:
    """timeout_minutes: per-user auto-lock preference (Settings > Vault).
    None falls back to VAULT_SESSION_TIMEOUT (15 min)."""
    _purge_expired()
    token = secrets.token_urlsafe(32)
    timeout_seconds = (timeout_minutes * 60) if timeout_minutes else VAULT_SESSION_TIMEOUT
    VAULT_KEY_STORE[token] = {
        "key": key, "user_id": user_id,
        "last_used": time.time(), "timeout": timeout_seconds
    }
    return token


def get_vault_key(token: str, user_id: int):
    _purge_expired()
    entry = VAULT_KEY_STORE.get(token)
    if not entry or entry['user_id'] != user_id:
        return None
    entry['last_used'] = time.time()
    return entry['key']


def clear_vault_key(token: str):
    VAULT_KEY_STORE.pop(token, None)
