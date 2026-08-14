"""Validated environment configuration for BambiVault."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


def _require_env(var_name: str) -> str:
    """Return a required environment variable or fail during startup."""
    value = os.environ.get(var_name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {var_name}. "
            f"Create a .env file (see .env.example) and set {var_name} "
            f"before starting the server."
        )
    return value


def _bool_env(var_name: str, default: bool) -> bool:
    raw = os.environ.get(var_name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int_env(var_name: str, default: int) -> int:
    raw = os.environ.get(var_name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "sqlite:///password_logs.db").strip()
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


@dataclass(frozen=True)
class Config:
    # Required settings
    SECRET_KEY: str
    ADMIN_PASSWORD: str

    # Application settings
    DATABASE_URL: str = "sqlite:///password_logs.db"
    FLASK_DEBUG: bool = True
    FLASK_ENV: str = "development"   # "development" | "production"

    # Cookie settings remain configurable for local HTTP development.
    SESSION_COOKIE_SECURE: bool = False
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"

    # Optional integrations
    GROQ_API_KEY: Optional[str] = None
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASS: Optional[str] = None
    SMTP_FROM: Optional[str] = None
    APP_BASE_URL: str = "http://127.0.0.1:5000"

    def __post_init__(self) -> None:
        # Production policy overrides unsafe local cookie/debug settings.
        if self.FLASK_ENV == "production" and not self.SESSION_COOKIE_SECURE:
            object.__setattr__(self, "SESSION_COOKIE_SECURE", True)
        if self.FLASK_ENV == "production" and self.FLASK_DEBUG:
            object.__setattr__(self, "FLASK_DEBUG", False)

    @property
    def is_production(self) -> bool:
        return self.FLASK_ENV == "production"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            SECRET_KEY=_require_env("SECRET_KEY"),
            ADMIN_PASSWORD=_require_env("ADMIN_PASSWORD"),
            DATABASE_URL=_database_url(),
            FLASK_DEBUG=_bool_env("FLASK_DEBUG", True),
            FLASK_ENV=os.environ.get("FLASK_ENV", "development"),
            SESSION_COOKIE_SECURE=_bool_env("SESSION_COOKIE_SECURE", False),
            SESSION_COOKIE_HTTPONLY=_bool_env("SESSION_COOKIE_HTTPONLY", True),
            SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
            GROQ_API_KEY=os.environ.get("GROQ_API_KEY") or None,
            SMTP_HOST=os.environ.get("SMTP_HOST") or None,
            SMTP_PORT=_int_env("SMTP_PORT", 587),
            SMTP_USER=os.environ.get("SMTP_USER") or None,
            SMTP_PASS=os.environ.get("SMTP_PASS") or None,
            SMTP_FROM=os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USER") or None,
            APP_BASE_URL=os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000"),
        )


config = Config.from_env()
