"""Shared validation and database-backed authentication throttling."""
import hashlib
import re
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError

from models import db, RateLimitBucket


EMAIL_RE = re.compile(r'^[^\s@]{1,64}@[^\s@]{1,190}\.[A-Za-z]{2,63}$')
USERNAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{2,49}$')


def valid_email(value: str) -> bool:
    return bool(value and len(value) <= 254 and EMAIL_RE.fullmatch(value))


def valid_username(value: str) -> bool:
    return bool(value and USERNAME_RE.fullmatch(value))


def consume_rate_limit(scope: str, identity: str, maximum: int, window_seconds: int) -> bool:
    """Return True when blocked; counters survive restarts and multiple workers."""
    identity_hash = hashlib.sha256((identity or 'unknown').encode('utf-8')).hexdigest()
    now = datetime.utcnow()
    bucket = RateLimitBucket.query.filter_by(
        scope=scope, identity_hash=identity_hash
    ).with_for_update().first()
    if not bucket:
        db.session.add(RateLimitBucket(scope=scope, identity_hash=identity_hash, attempts=1, window_start=now))
        try:
            db.session.commit()
            return False
        except IntegrityError:
            # Another worker created this unique bucket after our SELECT.
            # Roll back and process this request against that shared row.
            db.session.rollback()
            bucket = RateLimitBucket.query.filter_by(
                scope=scope, identity_hash=identity_hash
            ).with_for_update().first()
            if not bucket:
                raise
    if now - bucket.window_start >= timedelta(seconds=window_seconds):
        bucket.window_start = now
        bucket.attempts = 1
        db.session.commit()
        return False
    if bucket.attempts >= maximum:
        return True
    bucket.attempts += 1
    db.session.commit()
    return False


def clear_rate_limit(scope: str, identity: str) -> None:
    identity_hash = hashlib.sha256((identity or 'unknown').encode('utf-8')).hexdigest()
    RateLimitBucket.query.filter_by(scope=scope, identity_hash=identity_hash).delete()
    db.session.commit()
