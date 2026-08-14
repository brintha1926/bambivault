"""Generate distinct, human-readable stronger password variants."""

from __future__ import annotations

import secrets
import string
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from feature_extraction import FeatureDict

SPECIALS: str = "!@#$%^&*?-_"
FILLER_WORDS: list[str] = [
    "amber", "aurora", "bamboo", "breeze", "cedar", "cipher", "cobalt",
    "comet", "coral", "ember", "falcon", "forest", "granite", "harbor",
    "island", "jasmine", "lagoon", "lantern", "lunar", "maple", "meadow",
    "meteor", "ocean", "orbit", "pebble", "quartz", "raven", "river",
    "saffron", "summit", "thistle", "velvet", "willow", "zephyr"
]

ACTION_WORDS: list[str] = [
    "Builds", "Finds", "Follows", "Greets", "Keeps", "Likes",
    "Meets", "Sees", "Visits", "Walks", "Watches"
]

KEYBOARD_WALKS: list[str] = ['qwerty', 'asdfgh', 'zxcvbn', 'qwer', 'asdf', 'zxcv',
                              '1234', '12345', '123456', '654321']


def _random_special() -> str:
    return secrets.choice(SPECIALS)


def _random_digit() -> str:
    return secrets.choice(string.digits)


def _insert_at(s: str, pos: int, chunk: str) -> str:
    pos = max(0, min(pos, len(s)))
    return s[:pos] + chunk + s[pos:]


def _break_keyboard_walk(password: str) -> str:
    lower = password.lower()
    for walk in KEYBOARD_WALKS:
        idx = lower.find(walk)
        if idx != -1:
            mid = idx + len(walk) // 2
            chunk = _random_digit() + _random_special()
            return _insert_at(password, mid, chunk)
    return _insert_at(password, len(password) // 2, _random_digit() + _random_special())


def _pad_length(password: str, target: int = 12) -> str:
    needed = max(0, target - len(password))
    if needed == 0:
        needed = 4
    chunk = ''.join(secrets.choice(string.digits + SPECIALS) for _ in range(needed))
    pos = max(1, len(password) // 3)
    return _insert_at(password, pos, chunk)


def _add_special_char(password: str) -> str:
    pos = max(1, len(password) // 2)
    return _insert_at(password, pos, _random_special())


def _passphrase_restructure(password: str) -> str:
    """Create a memorable passphrase without preserving the weak source text."""
    words = secrets.SystemRandom().sample(FILLER_WORDS, 4)
    sep = secrets.choice("-_")
    return sep.join(word.capitalize() for word in words) + _random_special() + _random_digit()


def _compact_random_phrase() -> str:
    words = secrets.SystemRandom().sample(FILLER_WORDS, 3)
    return "".join(word.capitalize() for word in words) + _random_digit() + _random_digit() + _random_special()


def _separated_random_phrase() -> str:
    words = secrets.SystemRandom().sample(FILLER_WORDS, 3)
    separator = secrets.choice(".!-_@")
    return separator.join(word.capitalize() for word in words) + _random_digit() + _random_digit()


def _human_base(password: str) -> str:
    """Return a readable base without preserving a trailing year pattern."""
    base = re.sub(r'(?:19|20)\d{2}$', '', password).strip() or password
    base = ''.join(char for char in base if char.isalnum()) or 'Secure'
    return base[:12].capitalize()


def _transformed_base(password: str) -> str:
    base = _human_base(password)
    substitutions = str.maketrans({'a': '@', 'A': '@', 'e': '3', 'E': '3',
                                   'i': '!', 'I': '!', 'o': '0', 'O': '0',
                                   's': '$', 'S': '$'})
    transformed = base.translate(substitutions)
    return ''.join(
        char.upper() if index % 2 else char.lower()
        for index, char in enumerate(transformed)
    )


def _personalised_natural(password: str) -> str:
    base = _human_base(password)
    word = secrets.choice(FILLER_WORDS).capitalize()
    digits = ''.join(secrets.choice(string.digits) for _ in range(2))
    return f"{base}{_random_special()}{word}{_random_special()}{digits}"


def _personalised_phrase(password: str) -> str:
    base = _human_base(password)
    action = secrets.choice(ACTION_WORDS)
    word = secrets.choice(FILLER_WORDS).capitalize()
    digits = ''.join(secrets.choice(string.digits) for _ in range(2))
    return f"{base}{action}@{word}{digits}"


def _personalised_compact(password: str) -> str:
    base = _transformed_base(password)
    word = secrets.choice(FILLER_WORDS).capitalize()
    digits = ''.join(secrets.choice(string.digits) for _ in range(4))
    return f"{_random_special()}{base}{_random_special()}{digits}#{word}"


def suggest_stronger_variants(password: str, feats: "FeatureDict", max_variants: int = 3) -> list[str]:
    """Generate distinct candidates for subsequent strength ranking."""
    candidates: list[str] = []

    candidates.append(_personalised_natural(password))
    candidates.append(_personalised_phrase(password))
    candidates.append(_personalised_compact(password))

    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen and c != password:
            seen.add(c)
            unique.append(c)

    return unique[:max_variants]
