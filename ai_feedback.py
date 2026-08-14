"""Derived-feature recommendation service with caching and fallback."""

import os
import json
import sqlite3
import requests
from security_utils import consume_rate_limit

# CONFIG

GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.1-8b-instant"   # fast + free-tier friendly

AI_TIMEOUT_SECONDS  = 4
MAX_RECOMMENDATIONS = 3

CACHE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "data", "ai_feedback_cache.db")
CACHE_EXPIRY_SECONDS = 60 * 60 * 24 * 14   # 2 weeks — feature combos are stable

AI_RATE_LIMIT_MAX    = 8     # requests
AI_RATE_LIMIT_WINDOW = 60    # seconds

# Shared request throttling

def _is_ai_rate_limited(ip: str) -> bool:
    """Share the AI request budget across processes and restarts."""
    return consume_rate_limit('ai-feedback', ip or 'unknown',
                              AI_RATE_LIMIT_MAX, AI_RATE_LIMIT_WINDOW)


# Recommendation cache

def _cache_db_connect():
    os.makedirs(os.path.dirname(CACHE_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(CACHE_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_feedback_cache (
            cache_key   TEXT PRIMARY KEY,
            feedback    TEXT NOT NULL,
            cached_at   REAL NOT NULL
        )
    """)
    return conn


def _make_cache_key(label: str, profile: str, flags: list, breached: bool) -> str:
    flags_key = ','.join(sorted(flags)) if flags else 'none'
    return f"{label}|{profile}|{flags_key}|{'breached' if breached else 'clean'}"


def _get_cache(key: str):
    """Returns a list of strings, or None if not cached / expired."""
    try:
        conn = _cache_db_connect()
        row = conn.execute(
            "SELECT feedback, cached_at FROM ai_feedback_cache WHERE cache_key = ?",
            (key,)
        ).fetchone()
        conn.close()
        if row:
            feedback_json, cached_at = row
            if time.time() - cached_at < CACHE_EXPIRY_SECONDS:
                return json.loads(feedback_json)
    except Exception:
        pass
    return None


def _set_cache(key: str, recommendations: list):
    try:
        conn = _cache_db_connect()
        conn.execute(
            "INSERT OR REPLACE INTO ai_feedback_cache (cache_key, feedback, cached_at) "
            "VALUES (?, ?, ?)",
            (key, json.dumps(recommendations), time.time())
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# Prompt construction uses derived features only.

def _build_prompt(label: str, score: int, profile: str, flags: list,
                   entropy: float, length: int, breach_result: dict) -> str:
    flags_str = ', '.join(f for f in flags if f != 'none_detected') or 'none'
    breach_line = (
        f"Found in {breach_result['breach_count']:,} known breaches "
        f"(risk: {breach_result['risk_label']})."
        if breach_result.get('is_breached')
        else "Not found in known breach databases."
    )

    return (
        "You are a security awareness assistant for a university password "
        "training tool. Based ONLY on the following derived metrics (you are "
        "never shown the actual password), produce the TOP "
        f"{MAX_RECOMMENDATIONS} most important pieces of advice for THIS "
        "specific password, ordered by priority (most important first).\n\n"
        "STRICT RULES:\n"
        "- Each item must address a DIFFERENT weakness. Never restate the "
        "same point twice in different words.\n"
        "- One short sentence per item. No markdown, no numbering, no "
        "bullet symbols in the text itself.\n"
        "- Address the user directly as 'you'.\n"
        "- If the password genuinely only has 1 or 2 real issues, return "
        "fewer than 3 items rather than padding with generic advice.\n"
        "- If the password is already strong and clean, return exactly 1 "
        "short affirming item plus general hygiene advice (e.g. uniqueness "
        "across accounts).\n\n"
        f"Strength classification: {label} (score {score}/4)\n"
        f"Behavioural profile: {profile}\n"
        f"Detected pattern flags: {flags_str}\n"
        f"Password length: {length} characters\n"
        f"Entropy: {entropy} bits\n"
        f"Breach status: {breach_line}\n\n"
        "Respond with ONLY a JSON array of strings — no preamble, no "
        'explanation, no markdown code fences. Example: '
        '["First point.", "Second point."]'
    )


# GROQ API CALL

def _call_groq(prompt: str):
    """Returns a list of strings, or None on any failure."""
    if not GROQ_API_KEY:
        return None
    try:
        r = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 300,
                "temperature": 0.6,
            },
            timeout=AI_TIMEOUT_SECONDS,
        )
        if r.status_code != 200:
            return None

        raw = r.json()["choices"][0]["message"]["content"].strip()

        # Strip markdown code fences if the model added them anyway
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.lower().startswith("json"):
                raw = raw[4:].strip()

        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return None

        cleaned = [str(item).strip() for item in parsed if str(item).strip()]
        if not cleaned:
            return None

        return cleaned[:MAX_RECOMMENDATIONS]

    except requests.exceptions.Timeout:
        return None
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return None
    except Exception:
        return None


# Recommendation interface

def get_ai_recommendations(ip: str, label: str, score: int, profile: str,
                            flags: list, entropy: float, length: int,
                            breach_result: dict) -> dict:
    """Return cached or generated recommendations and their source."""
    cache_key = _make_cache_key(label, profile, flags, breach_result.get('is_breached', False))

    cached = _get_cache(cache_key)
    if cached:
        return {'recommendations': cached, 'source': 'cache'}

    if _is_ai_rate_limited(ip):
        return {'recommendations': None, 'source': 'fallback'}

    if not GROQ_API_KEY:
        return {'recommendations': None, 'source': 'fallback'}

    prompt = _build_prompt(label, score, profile, flags, entropy, length, breach_result)
    result = _call_groq(prompt)

    if result:
        _set_cache(cache_key, result)
        return {'recommendations': result, 'source': 'ai'}

    return {'recommendations': None, 'source': 'fallback'}
