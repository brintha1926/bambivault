"""SQLAlchemy models for accounts, analysis, sessions, and the vault."""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class PasswordLog(db.Model):
    __tablename__ = 'password_analysis_log'

    id             = db.Column(db.Integer,  primary_key=True, autoincrement=True)

    # First 5 chars of SHA-1 hash only — used for HIBP k-Anonymity lookup
    hash_prefix    = db.Column(db.String(5),   nullable=False)

    # ML classification result
    strength_label = db.Column(db.String(20),  nullable=False)

    # Comma-separated list of detected pattern types
    pattern_flags  = db.Column(db.String(255), nullable=True)

    # Dominant behavioural profile derived from pattern flags
    behaviour_profile = db.Column(db.String(30), nullable=True, default='Clean')

    entropy        = db.Column(db.Float,       nullable=False)
    breach_exposed = db.Column(db.Boolean,     default=False)
    breach_risk    = db.Column(db.String(20),  nullable=True, default='Unknown')
    submitted_at   = db.Column(db.DateTime,    default=datetime.utcnow)

    # Nullable — guests can still use the analyser without an account. Also
    # nulled out (not deleted) if the owning account is later deleted, so
    # institutional trend data isn't distorted by account deletions — see
    # /api/account/delete in vault_routes.py.
    user_id = db.Column(db.Integer, db.ForeignKey('app_user.id'), nullable=True)

    def to_dict(self):
        return {
            'id':                self.id,
            'hash_prefix':       self.hash_prefix,
            'strength_label':    self.strength_label,
            'pattern_flags':     self.pattern_flags or 'none_detected',
            'behaviour_profile': self.behaviour_profile or 'Clean',
            'entropy':           round(self.entropy, 2),
            'breach_exposed':    self.breach_exposed,
            'breach_risk':       self.breach_risk or 'Unknown',
            'submitted_at':      self.submitted_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class User(db.Model):
    __tablename__ = 'app_user'

    id            = db.Column(db.Integer,  primary_key=True, autoincrement=True)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    username      = db.Column(db.String(50),  unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)   # LOGIN password

    # Verification links use signed, expiring tokens.
    email_verified = db.Column(db.Boolean, default=False)

    # Only the vault salt and one-way verifier are persisted.
    vault_salt       = db.Column(db.String(64),  nullable=True)
    vault_verifier   = db.Column(db.String(128), nullable=True)
    vault_configured = db.Column(db.Boolean, default=False)

    # NULL uses the system auto-lock default.
    vault_auto_lock_minutes = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    password_logs = db.relationship('PasswordLog', backref='user', lazy='dynamic')

    def to_profile_dict(self):
        return {
            'id':                       self.id,
            'email':                    self.email,
            'username':                 self.username,
            'email_verified':           self.email_verified,
            'vault_configured':         self.vault_configured,
            'vault_auto_lock_minutes':  self.vault_auto_lock_minutes,
            'created_at':               self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        }


class VaultEntry(db.Model):
    __tablename__ = 'vault_entry'

    id      = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('app_user.id'), nullable=False)

    site_name = db.Column(db.String(120), nullable=False)

    enc_username = db.Column(db.Text, nullable=True)
    enc_email    = db.Column(db.Text, nullable=True)
    enc_password = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self, key):
        from vault_crypto import decrypt_field
        return {
            'id':         self.id,
            'site_name':  self.site_name,
            'username':   decrypt_field(key, self.enc_username),
            'email':      decrypt_field(key, self.enc_email),
            'password':   decrypt_field(key, self.enc_password),
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
        }


class UserOTP(db.Model):
    """TOTP configuration and hashed single-use recovery codes."""
    __tablename__ = 'user_otp'

    user_id        = db.Column(db.Integer, db.ForeignKey('app_user.id'), primary_key=True)
    secret         = db.Column(db.String(32), nullable=False)
    enabled        = db.Column(db.Boolean, default=False)
    recovery_codes = db.Column(db.Text, nullable=True)   # JSON list of hashed codes
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)


class UserSession(db.Model):
    """Tracked login session supporting immediate revocation."""
    __tablename__ = 'user_session'

    id             = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('app_user.id'), nullable=False)
    session_token  = db.Column(db.String(64), unique=True, nullable=False)
    ip_address     = db.Column(db.String(45), nullable=True)
    user_agent     = db.Column(db.String(255), nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self, current_token=None):
        return {
            'id':             self.id,
            'ip_address':     self.ip_address or 'Unknown',
            'user_agent':     self.user_agent or 'Unknown device',
            'created_at':     self.created_at.strftime('%Y-%m-%d %H:%M'),
            'last_activity':  self.last_activity.strftime('%Y-%m-%d %H:%M'),
            'is_current':     self.session_token == current_token,
        }


class AdminAccount(db.Model):
    """Persistent administrator credentials, separate from user accounts."""
    __tablename__ = 'admin_account'

    id            = db.Column(db.Integer, primary_key=True, default=1)
    email         = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at    = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AdminOTP(db.Model):
    """TOTP configuration and one-time recovery codes for the administrator."""
    __tablename__ = 'admin_otp'

    admin_id       = db.Column(db.Integer, db.ForeignKey('admin_account.id'), primary_key=True)
    secret         = db.Column(db.String(32), nullable=False)
    enabled        = db.Column(db.Boolean, default=False)
    recovery_codes = db.Column(db.Text, nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)


class RateLimitBucket(db.Model):
    """Database-backed counters for authentication and recovery endpoints."""
    __tablename__ = 'rate_limit_bucket'

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scope         = db.Column(db.String(40), nullable=False)
    identity_hash = db.Column(db.String(64), nullable=False)
    attempts      = db.Column(db.Integer, nullable=False, default=0)
    window_start  = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('scope', 'identity_hash', name='uq_rate_limit_scope_identity'),)
