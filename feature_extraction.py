import math
import re

def extract_features(password):
    length     = len(password)
    num_upper  = sum(1 for c in password if c.isupper())
    num_lower  = sum(1 for c in password if c.islower())
    num_digits = sum(1 for c in password if c.isdigit())
    num_special= sum(1 for c in password if not c.isalnum())

    # Shannon entropy
    if length == 0:
        entropy = 0.0
    else:
        freq = {}
        for c in password:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((v / length) * math.log2(v / length)
                       for v in freq.values())

    # Pattern flags
    keyboard_walks = ['qwerty','asdfgh','zxcvbn','qwer','asdf',
                      'zxcv','1234','12345','123456','654321']
    has_keyboard_walk = any(k in password.lower() for k in keyboard_walks)
    has_year          = bool(re.search(r'(19|20)\d{2}', password))
    has_common_sub    = bool(re.search(r'[@][aA]|[3][eE]|[0][oO]|[1][iIlL]', password))
    has_dict_word     = bool(re.match(
        r'^(password|admin|login|welcome|letmein|monkey|dragon|master|qwerty|abc)',
        password, re.IGNORECASE))

    flags = []
    if has_keyboard_walk: flags.append('keyboard_walk')
    if has_year:          flags.append('name_year_combo')
    if has_common_sub:    flags.append('char_substitution')
    if has_dict_word:     flags.append('dict_word')

    return {
        'length':            length,
        'num_upper':         num_upper,
        'num_lower':         num_lower,
        'num_digits':        num_digits,
        'num_special':       num_special,
        'entropy':           round(entropy, 4),
        'has_keyboard_walk': int(has_keyboard_walk),
        'has_year':          int(has_year),
        'has_common_sub':    int(has_common_sub),
        'has_dict_word':     int(has_dict_word),
        'flags':             flags if flags else ['none_detected']
    }


def rule_based_strength(features):
    """
    Simple rule-based fallback classifier used BEFORE the ML model is ready.
    Returns 0=Very Weak, 1=Weak, 2=Medium, 3=Strong, 4=Very Strong
    """
    score = 0
    f = features

    if f['length'] >= 8:  score += 1
    if f['length'] >= 12: score += 1
    if f['num_upper'] > 0: score += 0.5
    if f['num_lower'] > 0: score += 0.5
    if f['num_digits'] > 0: score += 0.5
    if f['num_special'] > 0: score += 1
    if f['entropy'] > 2.5: score += 1
    if f['entropy'] > 3.5: score += 1

    # Penalties
    if f['has_keyboard_walk']: score -= 1.5
    if f['has_year']:          score -= 0.5
    if f['has_common_sub']:    score -= 0.3
    if f['has_dict_word']:     score -= 2.0
    if f['length'] < 6:        score  = 0

    score = max(0, min(4, round(score)))

    labels = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong']
    return score, labels[score]