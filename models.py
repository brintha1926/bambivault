"""
models.py  —  Database Models
==============================
Defines the SQLAlchemy ORM model for anonymised password analysis records.
No plaintext passwords or reversible representations are stored.
"""

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

    # FYP2 — Objective 3: dominant behavioural profile derived from pattern flags
    # e.g. "Keyboard-Walk Type", "Name+Year Type", "Substitution Type",
    #      "Dictionary-Word Type", "Clean"
    behaviour_profile = db.Column(db.String(30), nullable=True, default='Clean')

    entropy        = db.Column(db.Float,       nullable=False)
    breach_exposed = db.Column(db.Boolean,     default=False)
    breach_risk    = db.Column(db.String(20),  nullable=True, default='Unknown')
    submitted_at   = db.Column(db.DateTime,    default=datetime.utcnow)

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
