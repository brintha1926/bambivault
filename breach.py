"""
breach.py — BambiVault Custom Breach Detection Module
=======================================================
Project : BambiVault — An Interactive System for Evaluating
          Password Behaviour and Security Awareness Among University Students
Author  : Brintha


What makes this module custom-developed:
------------------------------------------------------------------
1. LOCAL PATTERN DATABASE  — a built-in dictionary of commonly breached
   password structures. Passwords matching these patterns are flagged
   BEFORE the API is even called, providing instant feedback without
   any network dependency.

2. COMPOSITE RISK SCORING — the final breach risk score is computed from
   BOTH the HIBP API exposure count AND local pattern matching results.
   This means a password can be flagged as high risk even if it has not
   yet appeared in a known breach but matches a known dangerous structure.

3. CUSTOM 5-TIER RISK ENGINE — maps raw exposure count to labelled risk
   tiers (Safe / Low Risk / Moderate Risk / High Risk / Critical) with
   configurable thresholds. This classification logic is entirely custom.

4. RESULT CACHE — reduces redundant API calls with configurable TTL.

5. RATE LIMITER — prevents API abuse with a per-prefix call tracker.

6. BREACH AUDIT LOG — every check is recorded with timestamp and outcome.
"""

import hashlib
import time
import re
import os
import sqlite3
import requests
from functools import wraps
from datetime import datetime
from collections import defaultdict


# =============================================================================
# CUSTOMISATION SECTION 
# =============================================================================

# API settings
HIBP_API_URL        = "https://api.pwnedpasswords.com/range/{prefix}"
API_TIMEOUT_SECONDS = 5

# Cache settings — how long (seconds) before re-querying the API
CACHE_EXPIRY_SECONDS = 300

# Rate limiter — max API calls per prefix within the time window
RATE_LIMIT_MAX   = 5
RATE_LIMIT_WINDOW = 60

# CUSTOMISE: Adjust risk thresholds based on your own risk model
# Format: (min_count, max_count, label, score_0_to_100)
RISK_THRESHOLDS = [
    (0,       0,           "Safe",          0),
    (1,       9,           "Low Risk",      25),
    (10,      999,         "Moderate Risk", 50),
    (1000,    99999,       "High Risk",     75),
    (100000,  float('inf'),"Critical",      100),
]

RISK_COLOURS = {
    "Safe":          "#10b981",
    "Low Risk":      "#f59e0b",
    "Moderate Risk": "#f97316",
    "High Risk":     "#ef4444",
    "Critical":      "#a855f7",
}

# CUSTOMISE: Edit advice messages per risk level
RISK_ADVICE = {
    "Safe": (
        "No exposure found in known breach databases. "
        "Continue monitoring your accounts and change passwords periodically. "
        "Even 'safe' passwords should be unique per account."
    ),
    "Low Risk": (
        "This password has appeared in a small number of known breaches. "
        "Change it immediately and avoid reusing it across accounts."
    ),
    "Moderate Risk": (
        "This password has been exposed multiple times in known breach compilations. "
        "It should be treated as compromised ,  change it now on all platforms where it is used."
    ),
    "High Risk": (
        "This password appears thousands of times in breach databases and is actively "
        "used in credential stuffing attacks. Do not use it under any circumstances."
    ),
    "Critical": (
        "This password has been found over 100,000 times in known breaches. "
        "It is among the most targeted passwords in automated attacks. "
        "Change it immediately and enable multi-factor authentication."
    ),
}


# =============================================================================
# LOCAL PATTERN DATABASE
# Custom-developed component — independent of HIBP API
# =============================================================================

# Exact commonly breached passwords — seeded with a small hardcoded set,
# then expanded at import time with the public SecLists top-10k common
# password list (same file used for ML labeling in generate_training_data_v3.py).
# CUSTOMISE: Extend this list with institution-specific common passwords
LOCAL_KNOWN_BREACHED = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "iloveyou", "admin", "letmein", "monkey",
    "welcome", "dragon", "master", "sunshine", "princess",
    "football", "shadow", "superman", "michael", "jessica",
    "login", "hello", "12345", "12345678", "password123",
    "qwerty123", "111111", "1234567", "1234567890", "000000",
}

# CUSTOMISE: path to the SecLists-style top-10k common password list
COMMON_LIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "data", "top_10k_common.txt")


def _load_common_password_list(path: str) -> int:
    """
    Loads a plaintext, newline-separated common-password list into
    LOCAL_KNOWN_BREACHED. Returns the number of entries added.
    Silently no-ops if the file isn't present, so the app still runs
    with just the small hardcoded seed set.
    """
    if not os.path.exists(path):
        return 0
    added = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.strip().lower()
                if pw and pw not in LOCAL_KNOWN_BREACHED:
                    LOCAL_KNOWN_BREACHED.add(pw)
                    added += 1
    except Exception:
        return added
    return added


_ADDED_FROM_LIST = _load_common_password_list(COMMON_LIST_PATH)

# Pattern rules for structural risk detection
# Each rule: (pattern_name, regex_or_function, risk_boost)
# risk_boost adds to the composite score (0–30 range each)
LOCAL_PATTERN_RULES = [
    # Keyboard walks
    ("keyboard_walk_horizontal",
     lambda p: any(k in p.lower() for k in ['qwerty','asdfgh','zxcvbn','qwer','asdf','zxcv']),
     20),
    # Sequential numbers
    ("sequential_digits",
     lambda p: any(s in p for s in ['12345','23456','34567','45678','56789','01234']),
     15),
    # Repeating characters
    ("repeated_chars",
     lambda p: bool(re.search(r'(.)\1{3,}', p)),
     18),
    # Common name + year
    ("name_year_pattern",
     lambda p: bool(re.search(r'[a-zA-Z]{3,}(19|20)\d{2}$', p)),
     12),
    # Dictionary word only (no digits/symbols)
     ("pure_dictionary_word",
     lambda p: p.isalpha() and len(p) <= 10,
     15),
    # Common substitution masking a dictionary word
    ("substitution_masked",
     lambda p: bool(re.search(r'p[@4]ss|@dm[i1]n|l[0o]g[i1]n|w[e3]lc[o0]me', p.lower())),
     10),
    # All lowercase short password
    ("short_lowercase",
     lambda p: p.islower() and len(p) <= 8,
     10),
]


def _run_local_checks(password: str) -> dict:
    """
    Runs the local pattern database checks entirely offline.
    Returns: { is_locally_known, matched_patterns, local_risk_boost }
    """
    pw_lower = password.lower()

    # Exact match against known breached set
    is_exact_match = pw_lower in LOCAL_KNOWN_BREACHED

    # Pattern matching
    matched = []
    boost   = 0
    for name, check_fn, score in LOCAL_PATTERN_RULES:
        try:
            if check_fn(password):
                matched.append(name)
                boost += score
        except Exception:
            pass

    # Cap boost at 60 so it doesn't completely override API result
    boost = min(boost, 60)

    return {
        "is_locally_known":  is_exact_match,
        "matched_patterns":  matched,
        "local_risk_boost":  boost,
    }


# =============================================================================
# CACHE AND RATE LIMITER
# =============================================================================
#
# The breach result cache is now persistent (SQLite-backed) instead of a
# plain in-memory dict. This means the cache survives Flask restarts during
# development — previously, restarting the server wiped everything and the
# next lookups all had to hit the HIBP API again.

import json as _json

CACHE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "data", "breach_cache.db")

_rate_tracker = defaultdict(list)


def _cache_db_connect():
    os.makedirs(os.path.dirname(CACHE_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(CACHE_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS breach_cache (
            prefix     TEXT PRIMARY KEY,
            result_json TEXT NOT NULL,
            cached_at  REAL NOT NULL,
            first_seen REAL
        )
    """)
    # Migration for cache DBs created before first_seen existed
    try:
        conn.execute("ALTER TABLE breach_cache ADD COLUMN first_seen REAL")
    except sqlite3.OperationalError:
        pass  # column already exists
    return conn


def _is_rate_limited(prefix: str) -> bool:
    now   = time.time()
    start = now - RATE_LIMIT_WINDOW
    _rate_tracker[prefix] = [t for t in _rate_tracker[prefix] if t > start]
    if len(_rate_tracker[prefix]) >= RATE_LIMIT_MAX:
        return True
    _rate_tracker[prefix].append(now)
    return False


def _get_cache(prefix: str):
    try:
        conn = _cache_db_connect()
        row = conn.execute(
            "SELECT result_json, cached_at FROM breach_cache WHERE prefix = ?",
            (prefix,)
        ).fetchone()
        if row:
            result_json, cached_at = row
            if time.time() - cached_at < CACHE_EXPIRY_SECONDS:
                conn.close()
                return _json.loads(result_json)
            # expired — remove it
            conn.execute("DELETE FROM breach_cache WHERE prefix = ?", (prefix,))
            conn.commit()
        conn.close()
    except Exception:
        pass
    return None


def _set_cache(prefix: str, result: dict):
    try:
        conn = _cache_db_connect()
        existing = conn.execute(
            "SELECT first_seen FROM breach_cache WHERE prefix = ?", (prefix,)
        ).fetchone()
        first_seen = existing[0] if existing and existing[0] else time.time()
        conn.execute(
            "INSERT OR REPLACE INTO breach_cache (prefix, result_json, cached_at, first_seen) "
            "VALUES (?, ?, ?, ?)",
            (prefix, _json.dumps(result), time.time(), first_seen)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_breach_age(prefix: str) -> dict:
 
    try:
        conn = _cache_db_connect()
        row = conn.execute(
            "SELECT first_seen, cached_at FROM breach_cache WHERE prefix = ?",
            (prefix,)
        ).fetchone()
        conn.close()
        if row and row[0]:
            first_seen, cached_at = row
            days_ago = (time.time() - first_seen) / 86400
            return {
                "first_seen": datetime.fromtimestamp(first_seen).isoformat(),
                "days_ago":   round(days_ago, 1),
                "cached_at":  datetime.fromtimestamp(cached_at).isoformat(),
            }
    except Exception:
        pass
    return {"first_seen": None, "days_ago": None, "cached_at": None}


# =============================================================================
# HIBP API QUERY
# =============================================================================
#
# RETRY WITH BACKOFF
# "error"/"timeout" results during live demos on shaky connections.

RETRY_MAX_RETRIES = 2
RETRY_BASE_DELAY   = 1
RETRY_MAX_DELAY    = 5


def retry_with_backoff(max_retries=RETRY_MAX_RETRIES, base_delay=RETRY_BASE_DELAY,
                        max_delay=RETRY_MAX_DELAY):
    """
    Decorator for retrying API-calling functions with exponential backoff.
    Retries when the wrapped function returns a dict whose "status" isn't
    "ok", or when it raises. Gives up after max_retries and returns whatever
    the last attempt produced (or a failure placeholder on repeated errors).
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = base_delay
            last_result = None
            for attempt in range(max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                except Exception:
                    result = {"status": "error", "hashes": {}}
                if result.get("status") == "ok":
                    return result
                last_result = result
                if attempt < max_retries:
                    time.sleep(delay)
                    delay = min(delay * 2, max_delay)
            return last_result or {"status": "failed_after_retry", "hashes": {}}
        return wrapper
    return decorator


@retry_with_backoff()
def _query_hibp(prefix: str) -> dict:
    try:
        r = requests.get(
            HIBP_API_URL.format(prefix=prefix),
            headers={"Add-Padding": "true"},
            timeout=API_TIMEOUT_SECONDS
        )
        if r.status_code == 200:
            hashes = {}
            for line in r.text.splitlines():
                parts = line.split(":")
                if len(parts) == 2:
                    hashes[parts[0]] = int(parts[1])
            return {"status": "ok", "hashes": hashes}
        return {"status": f"http_{r.status_code}", "hashes": {}}
    except requests.exceptions.Timeout:
        return {"status": "timeout", "hashes": {}}
    except Exception:
        return {"status": "error", "hashes": {}}


# =============================================================================
# COMPOSITE RISK ENGINE
# Custom-developed — combines API result + local pattern analysis
# =============================================================================

def _compute_composite_risk(api_count: int, local_boost: int,
                             is_locally_known: bool) -> tuple:
    """
    Computes the final risk classification from multiple signals:
      - api_count:        raw HIBP exposure count
      - local_boost:      score from local pattern matching (0–60)
      - is_locally_known: exact match in local known-breached database

    This composite approach means:
    - A password with 0 API hits but dangerous patterns → still flagged
    - A password with high API hits but clean patterns → accurately classified
    - A locally known password → at minimum High Risk regardless of API count

    Returns: (risk_label, risk_score, colour, advice)
    """
    # Start from API-based tier
    base_score = 0
    for min_c, max_c, label, score in RISK_THRESHOLDS:
        if min_c <= api_count <= max_c:
            base_score = score
            break

    # Apply local boost — patterns add to the raw API score
    composite = min(100, base_score + (local_boost * 0.5))

    # Locally known passwords are always at least High Risk
    if is_locally_known:
        composite = max(composite, 75)

    # Map composite score back to label
    if composite == 0:
        label = "Safe"
    elif composite <= 30:
        label = "Low Risk"
    elif composite <= 55:
        label = "Moderate Risk"
    elif composite <= 80:
        label = "High Risk"
    else:
        label = "Critical"

    return (
        label,
        round(composite),
        RISK_COLOURS[label],
        RISK_ADVICE[label]
    )


# =============================================================================
# PUBLIC INTERFACE
# =============================================================================

def check_breach(password: str) -> dict:
    """
    Main breach detection function called by app.py.

    Process:
      1. Run local pattern checks (offline, instant)
      2. Check rate limiter
      3. Check cache
      4. Query HIBP API (k-Anonymity — only hash prefix sent)
      5. Local suffix match (full hash never sent to server)
      6. Composite risk scoring (API + local patterns combined)
      7. Return full result dict

    Returns dict with all fields needed by the frontend and database.
    """
    if not password:
        return _error_result("empty_password", "XXXXX")

    # Step 1 — Local checks (always run, no network needed)
    local = _run_local_checks(password)

    # Step 2 — Hash computation
    full_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix    = full_hash[:5]
    suffix    = full_hash[5:]

    # Step 3 — Rate limiter
    if _is_rate_limited(prefix):
        return _error_result("rate_limited", prefix)

    # Step 4 — Cache check
    cached = _get_cache(prefix)
    if cached:
        # Re-run local checks on cached result (they're free)
        cached["api_status"]       = "cached"
        cached["local_patterns"]   = local["matched_patterns"]
        cached["locally_known"]    = local["is_locally_known"]
        cached["breach_age"]       = get_breach_age(prefix)
        return cached

    # Step 5 — HIBP API query
    api_resp = _query_hibp(prefix)

    if api_resp["status"] != "ok":
        # API failed — fall back to local-only assessment
        risk_label, risk_score, risk_colour, risk_advice = _compute_composite_risk(
            0, local["local_risk_boost"], local["is_locally_known"]
        )
        return {
            "is_breached":    local["is_locally_known"],
            "breach_count":   0,
            "risk_label":     risk_label,
            "risk_score":     risk_score,
            "risk_colour":    risk_colour,
            "risk_advice":    risk_advice + " (Note: live breach check unavailable — local assessment only)",
            "hash_prefix":    prefix,
            "api_status":     api_resp["status"],
            "local_patterns": local["matched_patterns"],
            "locally_known":  local["is_locally_known"],
            "breach_age":     get_breach_age(prefix),
            "checked_at":     datetime.utcnow().isoformat()
        }

    # Step 6 — Local suffix matching
    breach_count = api_resp["hashes"].get(suffix, 0)
    is_breached  = breach_count > 0 or local["is_locally_known"]

    # Step 7 — Composite risk engine
    risk_label, risk_score, risk_colour, risk_advice = _compute_composite_risk(
        breach_count,
        local["local_risk_boost"],
        local["is_locally_known"]
    )

    result = {
        "is_breached":    is_breached,
        "breach_count":   breach_count,
        "risk_label":     risk_label,
        "risk_score":     risk_score,
        "risk_colour":    risk_colour,
        "risk_advice":    risk_advice,
        "hash_prefix":    prefix,
        "api_status":     "ok",
        "local_patterns": local["matched_patterns"],
        "locally_known":  local["is_locally_known"],
        "checked_at":     datetime.utcnow().isoformat()
    }

    _set_cache(prefix, result)
    result["breach_age"] = get_breach_age(prefix)
    return result


def get_cache_stats() -> dict:
    try:
        conn = _cache_db_connect()
        now = time.time()
        total = conn.execute("SELECT COUNT(*) FROM breach_cache").fetchone()[0]
        active = conn.execute(
            "SELECT COUNT(*) FROM breach_cache WHERE ? - cached_at < ?",
            (now, CACHE_EXPIRY_SECONDS)
        ).fetchone()[0]
        conn.close()
    except Exception:
        total, active = 0, 0
    return {
        "total_cached":  total,
        "active_cached": active,
        "cache_expiry":  CACHE_EXPIRY_SECONDS,
        "locally_known_passwords": len(LOCAL_KNOWN_BREACHED),
    }


def _error_result(status: str, prefix: str) -> dict:
    return {
        "is_breached":    False,
        "breach_count":   0,
        "risk_label":     "Unknown",
        "risk_score":     0,
        "risk_colour":    "#888888",
        "risk_advice":    "Breach check could not be completed. Please try again.",
        "hash_prefix":    prefix,
        "api_status":     status,
        "local_patterns": [],
        "locally_known":  False,
        "checked_at":     datetime.utcnow().isoformat()
    }
