"""
app.py — BambiVault Flask Backend Server
==========================================
An Interactive System for Evaluating Password Behaviour and Security
Awareness Among University Students

Author  : Brintha
"""

import csv
import io
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from ai_feedback import get_ai_recommendations
import joblib
import numpy as np
from dotenv import load_dotenv
from flask import (Flask, render_template, request, jsonify,
                    session, redirect, url_for, Response, send_file)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

from models import db, PasswordLog, User
from feature_extraction import extract_features, rule_based_strength
from breach import check_breach, get_cache_stats
from strengthen import suggest_stronger_variants
from vault_routes import vault_bp


# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT VARIABLES
# ─────────────────────────────────────────────────────────────────────────────
# Loads secrets from a local .env file (see .env.example for the template).
# Falls back to safe development defaults if .env is missing, so the app
# still runs out of the box — but you should always create a real .env
# before deploying anywhere public.

load_dotenv()


def _require_env(var_name: str) -> str:
    value = os.environ.get(var_name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {var_name}. "
            f"Create a .env file (see .env.example) and set {var_name} "
            f"before starting the server."
        )
    return value


SECRET_KEY      = _require_env('SECRET_KEY')
ADMIN_PASSWORD  = _require_env('ADMIN_PASSWORD')
SECRET_KEY      = os.environ.get('SECRET_KEY', 'dev-only-fallback-change-me')
ADMIN_PASSWORD  = os.environ.get('ADMIN_PASSWORD', 'bambi123')
SECRET_KEY = os.environ.get('SECRET_KEY')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

if not SECRET_KEY or not ADMIN_PASSWORD:
    raise RuntimeError(
        "SECRET_KEY and ADMIN_PASSWORD must be set as environment variables. "
        "Create a .env file locally (see README) or set them in your hosting platform's dashboard."
    )
DATABASE_URL    = os.environ.get('DATABASE_URL', 'sqlite:///password_logs.db')
FLASK_DEBUG     = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

os.makedirs('logs', exist_ok=True)

log_handler = RotatingFileHandler('logs/bambivault.log', maxBytes=1_000_000, backupCount=3)
log_handler.setFormatter(logging.Formatter(
    '%(asctime)s | %(levelname)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
))

logger = logging.getLogger('bambivault')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)


# ─────────────────────────────────────────────────────────────────────────────
# APP & CONFIG
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = SECRET_KEY

app.config['SQLALCHEMY_DATABASE_URI']        = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

app.register_blueprint(vault_bp)

with app.app_context():
    db.create_all()

ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


def login_required(f):
    """Gates a page/API route behind a logged-in USER account (not admin).
    Guests hitting a page route get bounced to /login; guests hitting an
    API route get a 401 JSON response instead of an HTML redirect, since
    the frontend fetch() call expects JSON either way."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Please log in to view this.'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return User.query.get(uid)


def parse_date_range():
    start_str = request.args.get('start', '').strip()
    end_str   = request.args.get('end', '').strip()

    start_dt = None
    end_dt   = None
    try:
        if start_str:
            start_dt = datetime.strptime(start_str, '%Y-%m-%d')
        if end_str:
            end_dt = datetime.strptime(end_str, '%Y-%m-%d') + timedelta(days=1, seconds=-1)
    except ValueError:
        pass

    return start_dt, end_dt


def apply_date_filter(query, start_dt, end_dt):
    if start_dt:
        query = query.filter(PasswordLog.submitted_at >= start_dt)
    if end_dt:
        query = query.filter(PasswordLog.submitted_at <= end_dt)
    return query


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITING — protects /analyse from abuse
# ─────────────────────────────────────────────────────────────────────────────

_rate_limiter = defaultdict(list)
RATE_LIMIT_MAX    = 10   # requests
RATE_LIMIT_WINDOW = 60   # seconds


def is_rate_limited(ip: str) -> bool:
    now = datetime.now()
    _rate_limiter[ip] = [t for t in _rate_limiter[ip]
                          if now - t < timedelta(seconds=RATE_LIMIT_WINDOW)]
    if len(_rate_limiter[ip]) >= RATE_LIMIT_MAX:
        return True
    _rate_limiter[ip].append(now)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# ML MODEL
# ─────────────────────────────────────────────────────────────────────────────

ML_MODEL = joblib.load('model/strength_model_rf_v3.pkl')

FEATURE_ORDER = [
    'length', 'num_upper', 'num_lower', 'num_digits', 'num_special',
    'entropy', 'has_keyboard_walk', 'has_year', 'has_common_sub', 'has_dict_word'
]

STRENGTH_LABELS = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong']


def classify_strength(feats: dict) -> tuple[int, str, float]:
    vector = np.array([[feats[k] for k in FEATURE_ORDER]])
    score = int(ML_MODEL.predict(vector)[0])
    label = STRENGTH_LABELS[score]
    probabilities = ML_MODEL.predict_proba(vector)[0]
    confidence = round(float(probabilities[score]) * 100, 1)
    return score, label, confidence


def classify_behaviour_profile(feats: dict) -> str:
    if feats['has_keyboard_walk']:
        return 'Keyboard-Walk Type'
    if feats['has_year']:
        return 'Name+Year Type'
    if feats['has_common_sub']:
        return 'Substitution Type'
    if feats['has_dict_word']:
        return 'Dictionary-Word Type'
    return 'Clean'


def build_recommendations(feats: dict, score: int, breach_result: dict, profile: str) -> list[str]:
    recs = []
    profile_advice = {
        'Keyboard-Walk Type': "Your password shows reliance on keyboard sequences "
                               "(like 'qwerty' or 'asdf') — these are the first patterns "
                               "tested in any dictionary attack. Try a random passphrase instead.",
        'Name+Year Type':     "Your password follows a name-plus-year pattern — highly "
                               "predictable to attackers who know basic details about you. "
                               "Avoid birth years and personal dates entirely.",
        'Substitution Type':  "Your password uses common character substitutions (like '@' "
                               "for 'a') — attackers' dictionaries already account for these "
                               "swaps, so they add little real protection.",
        'Dictionary-Word Type': "Your password is built around a common dictionary word — "
                                 "even with added numbers or symbols, this remains a predictable "
                                 "starting point for attackers.",
    }
    if profile in profile_advice:
        recs.append(profile_advice[profile])
    if feats['length'] < 8:
        recs.append("Increase your password length to at least 12 characters — "
                     "length is the single biggest factor in password strength.")
    if feats['num_special'] == 0:
        recs.append("Add special characters such as !, @, #, or $ to significantly "
                     "increase unpredictability.")
    if breach_result['is_breached']:
        recs.append(f"This password was found in known breach databases "
                     f"{breach_result['breach_count']:,} times — it must be "
                     f"changed immediately.")
    if score < 3:
        recs.append("Consider using a password manager to generate and store "
                     "high-entropy unique passwords.")
    if not recs:
        recs.append("Good password. Ensure it is unique across all your accounts "
                     "and not reused anywhere.")
    return recs


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC PAGE ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    # '/' is ALWAYS the landing/marketing page for anonymous visitors, and
    # ALWAYS redirects logged-in users straight to their dashboard. It no
    # longer branches on guest_mode — that branching is exactly what broke
    # the browser Back button: pressing Back replayed the old /guest ->
    # redirect -> '/' chain, and since guest_mode was still set in the
    # session, '/' kept re-showing the analyser instead of the landing
    # page. Now the analyser lives at its own URL (/analyser), so '/' is a
    # stable, single-purpose page and Back works the way it does on any
    # normal website.
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/analyser')
def analyser_page():
    """The actual password analyser page — separated from '/' so it has its
    own distinct browser-history entry. Guests and logged-in users both land
    here; only /dashboard, /database, and the vault stay behind login_required."""
    return render_template('index.html')


@app.route('/guest')
def guest():
    """Lets someone skip account creation entirely and use just the
    analyser. Sets a session flag purely so /dashboard, /database, and the
    vault API can tell 'anonymous guest' apart from 'never visited' — it no
    longer affects what '/' renders."""
    session['guest_mode'] = True
    return redirect(url_for('analyser_page'))


@app.route('/exit-guest')
def exit_guest():
    """Clears the guest flag and returns to the landing page. Kept as an
    explicit sidebar link ('Back to home') for users who want to fully
    reset out of guest mode, separate from just navigating to '/' (which
    now always shows the landing page for anonymous visitors regardless)."""
    session.pop('guest_mode', None)
    return redirect(url_for('index'))


@app.route('/login')
def login():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/register')
def register():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    """Page-level logout for the user account (separate from /admin/logout).
    Also clears the vault session key server-side, same as the vault's own
    /api/account/logout, so leaving via this link can't leave a stray
    unlocked vault key sitting in memory."""
    token = session.pop('vault_token', None)
    if token:
        import vault_crypto as vc
        vc.clear_vault_key(token)
    session.pop('user_id', None)
    session.pop('guest_mode', None)
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/database')
@login_required
def database():
    return render_template('database.html')


@app.route('/health')
def health():
    """Simple uptime check — useful once deployed to bambivault.com."""
    return jsonify({'status': 'ok', 'time': datetime.utcnow().isoformat()})


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN AUTH ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        pw = request.form.get('password', '')
        if check_password_hash(ADMIN_PASSWORD_HASH, pw):
            session['is_admin'] = True
            logger.info(f"Admin login success | ip={request.remote_addr}")
            return redirect(url_for('admin'))
        error = 'Incorrect password.'
        logger.warning(f"Admin login FAILED | ip={request.remote_addr}")
    return render_template('admin_login.html', error=error)


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html')


# ─────────────────────────────────────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/analyse', methods=['POST'])
def analyse():
    ip = request.remote_addr

    if is_rate_limited(ip):
        logger.warning(f"Rate limit hit | ip={ip}")
        return jsonify({'error': 'Too many requests. Please wait a minute and try again.'}), 429

    data     = request.get_json(silent=True) or {}
    password = data.get('password', '').strip()

    if not password:
        return jsonify({'error': 'No password provided'}), 400

    feats = extract_features(password)
    score, label, confidence = classify_strength(feats)
    profile = classify_behaviour_profile(feats)
    breach_result = check_breach(password)
    ai_result = get_ai_recommendations(
        ip=ip,
        label=label,
        score=score,
        profile=profile,
        flags=feats['flags'],
        entropy=feats['entropy'],
        length=feats['length'],
        breach_result=breach_result
    )

    if ai_result['recommendations']:
        recs = ai_result['recommendations']
    else:
        # Fallback to the rule-based system, capped to 3 for a consistent
        # frontend experience whether or not the AI call succeeded.
        recs = build_recommendations(feats, score, breach_result, profile)[:3]

    log = PasswordLog(
        hash_prefix       = breach_result['hash_prefix'],
        strength_label    = label,
        pattern_flags     = ', '.join(feats['flags']),
        behaviour_profile = profile,
        entropy           = feats['entropy'],
        breach_exposed    = breach_result['is_breached'],
        breach_risk       = breach_result['risk_label'],
        user_id           = session.get('user_id')  # None for guests
    )
    db.session.add(log)
    db.session.commit()

    logger.info(f"Analyse | ip={ip} | strength={label} | profile={profile} | "
                f"breached={breach_result['is_breached']} | api_status={breach_result['api_status']}")

    return jsonify({
        'strength_label':    label,
        'strength_score':    score,
        'model_confidence':  confidence,
        'behaviour_profile': profile,
        'entropy':           feats['entropy'],
        'features':          feats,
        'flags':             feats['flags'],
        'breach_found':      breach_result['is_breached'],
        'breach_count':      breach_result['breach_count'],
        'breach_risk':       breach_result['risk_label'],
        'breach_score':      breach_result['risk_score'],
        'breach_colour':     breach_result['risk_colour'],
        'breach_advice':     breach_result['risk_advice'],
        'api_status':        breach_result['api_status'],
        'breach_age':        breach_result.get('breach_age'),
        'recommendations':   recs,
        'ai_feedback_source': ai_result['source']
    })


@app.route('/strengthen', methods=['POST'])
def strengthen():
    ip = request.remote_addr

    if is_rate_limited(ip):
        logger.warning(f"Rate limit hit (strengthen) | ip={ip}")
        return jsonify({'error': 'Too many requests. Please wait a minute and try again.'}), 429

    data     = request.get_json(silent=True) or {}
    password = data.get('password', '').strip()

    if not password:
        return jsonify({'error': 'No password provided'}), 400

    feats    = extract_features(password)
    variants = suggest_stronger_variants(password, feats)

    variants_report = []
    for v in variants:
        v_feats = extract_features(v)
        v_score, v_label, v_confidence = classify_strength(v_feats)
        variants_report.append({
            'password':         v,
            'entropy':          v_feats['entropy'],
            'strength_label':   v_label,
            'strength_score':   v_score,
            'model_confidence': v_confidence,
        })

    # Rank strongest-first so the top suggestion is always the best option,
    # not just whichever strategy happened to run first.
    variants_report.sort(key=lambda v: (v['strength_score'], v['entropy']), reverse=True)

    logger.info(f"Strengthen | ip={ip} | variants_generated={len(variants_report)}")

    return jsonify({'variants': variants_report})


@app.route('/api/stats')
@login_required
def api_stats():
    uid = session['user_id']
    base_query = PasswordLog.query.filter_by(user_id=uid)

    total    = base_query.count()
    breached = base_query.filter_by(breach_exposed=True).count()

    dist = db.session.query(
        PasswordLog.strength_label, func.count(PasswordLog.id)
    ).filter(PasswordLog.user_id == uid).group_by(PasswordLog.strength_label).all()

    patterns_raw   = db.session.query(PasswordLog.pattern_flags) \
                        .filter(PasswordLog.user_id == uid).all()
    pattern_counts = {}
    for row in patterns_raw:
        if row.pattern_flags:
            for flag in row.pattern_flags.split(', '):
                flag = flag.strip()
                if flag and flag != 'none_detected':
                    pattern_counts[flag] = pattern_counts.get(flag, 0) + 1

    risk_dist = db.session.query(
        PasswordLog.breach_risk, func.count(PasswordLog.id)
    ).filter(PasswordLog.user_id == uid).group_by(PasswordLog.breach_risk).all()

    avg_entropy = db.session.query(func.avg(PasswordLog.entropy)) \
                    .filter(PasswordLog.user_id == uid).scalar() or 0
    cache_info  = get_cache_stats()

    return jsonify({
        'total':        total,
        'breached':     breached,
        'avg_entropy':  round(avg_entropy, 2),
        'breach_rate':  round((breached / total * 100), 1) if total else 0,
        'distribution': [{'label': r[0], 'count': r[1]} for r in dist],
        'top_patterns': sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:6],
        'risk_dist':    [{'label': r[0], 'count': r[1]} for r in risk_dist],
        'cache_info':   cache_info
    })

def _generate_institutional_insight(stats: dict) -> str:
    """
    Plain-English synthesis of the aggregated behavioural profile data —
    the admin-side equivalent of the personalised feedback a single user
    sees, but scoped to the whole institution's submission patterns for
    the selected date range.
    """
    total = stats['total']
    if not total:
        return "No submissions in this range yet."

    profile_map = {p['label']: p['count'] for p in stats['profile_dist']}
    dominant_profile = max(profile_map, key=profile_map.get) if profile_map else 'Clean'
    dominant_pct = round((profile_map.get(dominant_profile, 0) / total) * 100, 1)

    profile_lines = {
        'Keyboard-Walk Type': (
            f"{dominant_pct}% of submissions this period show keyboard-walk "
            f"patterns (e.g. 'qwerty', 'asdf') — this is the single easiest "
            f"pattern for automated cracking tools to catch first. Consider "
            f"targeted awareness content on this specific weakness."
        ),
        'Name+Year Type': (
            f"{dominant_pct}% of submissions follow a name-plus-year "
            f"structure — highly predictable when an attacker has any "
            f"personal detail (birth year, graduation year). Worth flagging "
            f"in orientation-week security briefings."
        ),
        'Substitution Type': (
            f"{dominant_pct}% rely on common character substitutions "
            f"(e.g. '@' for 'a') — modern cracking dictionaries already "
            f"account for these swaps, so this population may believe "
            f"they're more secure than they are."
        ),
        'Dictionary-Word Type': (
            f"{dominant_pct}% are built around a single dictionary word — "
            f"the most common and most crackable pattern observed. This is "
            f"the highest-priority group for follow-up awareness efforts."
        ),
        'Clean': (
            f"{dominant_pct}% of submissions show no detected weak pattern "
            f"— the institution's overall behavioural profile looks "
            f"comparatively healthy for this period."
        ),
    }

    base = profile_lines.get(dominant_profile, f"Dominant profile: {dominant_profile} ({dominant_pct}%).")

    if stats['breach_rate'] > 30:
        base += (f" Separately, {stats['breach_rate']}% of submissions were "
                 f"found in known breach databases — notably high and worth "
                 f"escalating regardless of behavioural profile.")

    return base

def _compute_admin_stats(start_dt, end_dt):
    """Shared by /api/admin/stats and /api/admin/compare — one source of truth."""
    base = apply_date_filter(PasswordLog.query, start_dt, end_dt)
    total    = base.count()
    breached = apply_date_filter(PasswordLog.query.filter_by(breach_exposed=True), start_dt, end_dt).count()

    dist_q = apply_date_filter(
        db.session.query(PasswordLog.strength_label, func.count(PasswordLog.id)),
        start_dt, end_dt
    ).group_by(PasswordLog.strength_label).all()

    risk_q = apply_date_filter(
        db.session.query(PasswordLog.breach_risk, func.count(PasswordLog.id)),
        start_dt, end_dt
    ).group_by(PasswordLog.breach_risk).all()

    profile_q = apply_date_filter(
        db.session.query(PasswordLog.behaviour_profile, func.count(PasswordLog.id)),
        start_dt, end_dt
    ).group_by(PasswordLog.behaviour_profile).all()

    avg_entropy_q = apply_date_filter(
        db.session.query(func.avg(PasswordLog.entropy)), start_dt, end_dt
    ).scalar() or 0

    return {
        'total':        total,
        'breached':     breached,
        'avg_entropy':  round(avg_entropy_q, 2),
        'breach_rate':  round((breached / total * 100), 1) if total else 0,
        'distribution': [{'label': r[0], 'count': r[1]} for r in dist_q],
        'risk_dist':    [{'label': r[0], 'count': r[1]} for r in risk_q],
        'profile_dist': [{'label': r[0] or 'Clean', 'count': r[1]} for r in profile_q],
    }


@app.route('/api/admin/stats')
@admin_required
def api_admin_stats():
    start_dt, end_dt = parse_date_range()
    stats = _compute_admin_stats(start_dt, end_dt)
    stats['institutional_insight'] = _generate_institutional_insight(stats)

    day_expr = func.strftime('%Y-%m-%d', PasswordLog.submitted_at)
    trend_q = apply_date_filter(
        db.session.query(
            day_expr.label('day'),
            func.count(PasswordLog.id).label('total'),
            func.sum(func.cast(PasswordLog.breach_exposed, db.Integer)).label('breached')
        ),
        start_dt, end_dt
    ).group_by('day').order_by('day').limit(60).all()

    stats['breach_trend']  = [{'day': r[0], 'total': r[1], 'breached': r[2] or 0} for r in trend_q]
    stats['cache_info']    = get_cache_stats()
    stats['range_applied'] = {'start': start_dt.strftime('%Y-%m-%d') if start_dt else None,
                               'end':   end_dt.strftime('%Y-%m-%d') if end_dt else None}
    return jsonify(stats)


@app.route('/api/admin/compare')
@admin_required
def api_admin_compare():
    """
    Week-over-week (or custom range vs the immediately preceding equal-length
    period) comparison. If ?start=&end= given, the "previous" window is the
    same number of days immediately before start.
    """
    start_dt, end_dt = parse_date_range()

    if not start_dt or not end_dt:
        # default: current window = last 7 days, previous = the 7 before that
        end_dt   = datetime.utcnow()
        start_dt = end_dt - timedelta(days=7)

    window_len = end_dt - start_dt
    prev_end   = start_dt - timedelta(seconds=1)
    prev_start = prev_end - window_len

    current  = _compute_admin_stats(start_dt, end_dt)
    previous = _compute_admin_stats(prev_start, prev_end)

    return jsonify({
        'current':  current,
        'previous': previous,
        'current_range':  {'start': start_dt.strftime('%Y-%m-%d'), 'end': end_dt.strftime('%Y-%m-%d')},
        'previous_range': {'start': prev_start.strftime('%Y-%m-%d'), 'end': prev_end.strftime('%Y-%m-%d')},
    })


def _gather_export_data(start_dt, end_dt):
    strength = apply_date_filter(
        db.session.query(PasswordLog.strength_label, func.count(PasswordLog.id)),
        start_dt, end_dt
    ).group_by(PasswordLog.strength_label).all()

    profile = apply_date_filter(
        db.session.query(PasswordLog.behaviour_profile, func.count(PasswordLog.id)),
        start_dt, end_dt
    ).group_by(PasswordLog.behaviour_profile).all()

    risk = apply_date_filter(
        db.session.query(PasswordLog.breach_risk, func.count(PasswordLog.id)),
        start_dt, end_dt
    ).group_by(PasswordLog.breach_risk).all()

    total    = apply_date_filter(PasswordLog.query, start_dt, end_dt).count()
    breached = apply_date_filter(PasswordLog.query.filter_by(breach_exposed=True), start_dt, end_dt).count()

    return {
        'total': total,
        'breached': breached,
        'strength': strength,
        'profile': profile,
        'risk': risk,
        'range': f"{start_dt.strftime('%Y-%m-%d') if start_dt else 'All time'} to "
                 f"{end_dt.strftime('%Y-%m-%d') if end_dt else 'present'}",
        'range_suffix': f"{start_dt.strftime('%Y%m%d') if start_dt else 'all'}_"
                        f"{end_dt.strftime('%Y%m%d') if end_dt else 'present'}"
    }


def _generate_chart_png(data) -> bytes:
    """Renders strength + risk distribution as a single PNG for PDF embedding."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(10, 3.5))
    fig.patch.set_facecolor('white')

    s_labels = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong']
    s_map = {l: c for l, c in data['strength']}
    s_vals = [s_map.get(l, 0) for l in s_labels]
    s_colors = ['#ef4444', '#f97316', '#f59e0b', '#10b981', '#00ffc8']
    axes[0].bar(s_labels, s_vals, color=s_colors)
    axes[0].set_title('Strength Distribution', fontsize=10)
    axes[0].tick_params(axis='x', rotation=30, labelsize=7)

    r_labels = ['Safe', 'Low Risk', 'Moderate Risk', 'High Risk', 'Critical']
    r_map = {l: c for l, c in data['risk']}
    r_vals = [r_map.get(l, 0) for l in r_labels]
    r_colors = ['#10b981', '#f59e0b', '#f97316', '#ef4444', '#a855f7']
    axes[1].bar(r_labels, r_vals, color=r_colors)
    axes[1].set_title('Breach Risk Distribution', fontsize=10)
    axes[1].tick_params(axis='x', rotation=30, labelsize=7)

    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=140)
    plt.close(fig)
    buf.seek(0)
    return buf.read()


@app.route('/api/admin/export')
@admin_required
def api_admin_export():
    fmt = request.args.get('format', 'csv').lower()
    start_dt, end_dt = parse_date_range()
    data = _gather_export_data(start_dt, end_dt)

    logger.info(f"Admin export | format={fmt} | range={data['range']}")

    if fmt == 'pdf':
        return _export_pdf(data)
    elif fmt == 'docx':
        return _export_docx(data)
    elif fmt == 'txt':
        return _export_txt(data)
    else:
        return _export_csv(data)


def _export_csv(data):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['BambiVault — Statistics Report'])
    writer.writerow(['Range', data['range']])
    writer.writerow(['Total submissions', data['total']])
    writer.writerow(['Breached submissions', data['breached']])
    writer.writerow([])
    writer.writerow(['Strength Label', 'Count'])
    writer.writerows(data['strength'])
    writer.writerow([])
    writer.writerow(['Behaviour Profile', 'Count'])
    writer.writerows(data['profile'])
    writer.writerow([])
    writer.writerow(['Breach Risk Level', 'Count'])
    writer.writerows(data['risk'])

    return Response(
        output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=bambivault_stats_{data["range_suffix"]}.csv'}
    )


def _export_txt(data):
    lines = [
        "BAMBIVAULT — STATISTICS REPORT",
        "=" * 45,
        f"Range: {data['range']}",
        f"Total submissions: {data['total']}",
        f"Breached submissions: {data['breached']}",
        "",
        "STRENGTH DISTRIBUTION",
        "-" * 25,
    ]
    for label, count in data['strength']:
        lines.append(f"  {label:<15} {count}")
    lines += ["", "BEHAVIOUR PROFILE DISTRIBUTION", "-" * 32]
    for label, count in data['profile']:
        lines.append(f"  {(label or 'Clean'):<20} {count}")
    lines += ["", "BREACH RISK DISTRIBUTION", "-" * 27]
    for label, count in data['risk']:
        lines.append(f"  {label:<15} {count}")

    text = "\n".join(lines)
    return Response(
        text, mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename=bambivault_stats_{data["range_suffix"]}.txt'}
    )


def _export_pdf(data):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("BambiVault — Statistics Report", styles['Title']),
        Paragraph(f"Range: {data['range']}", styles['Normal']),
        Paragraph(f"Total submissions: {data['total']} &nbsp;&nbsp; "
                  f"Breached: {data['breached']}", styles['Normal']),
        Spacer(1, 16),
    ]

    # Chart image — embedded so the PDF is a self-contained visual report
    try:
        chart_bytes = _generate_chart_png(data)
        chart_buf = io.BytesIO(chart_bytes)
        story.append(Image(chart_buf, width=16*cm, height=5.6*cm))
        story.append(Spacer(1, 14))
    except Exception as e:
        logger.warning(f"Chart embed failed in PDF export: {e}")

    def make_table(title, rows):
        story.append(Paragraph(title, styles['Heading2']))
        table_data = [['Label', 'Count']] + [[str(r[0] or 'Clean'), str(r[1])] for r in rows]
        t = Table(table_data, colWidths=[8*cm, 4*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))

    make_table("Strength Distribution", data['strength'])
    make_table("Behaviour Profile Distribution", data['profile'])
    make_table("Breach Risk Distribution", data['risk'])

    doc.build(story)
    buf.seek(0)
    return send_file(buf, mimetype='application/pdf', as_attachment=True,
                      download_name=f'bambivault_stats_{data["range_suffix"]}.pdf')


def _export_docx(data):
    from docx import Document
    from docx.shared import Cm

    doc = Document()
    doc.add_heading('BambiVault — Statistics Report', level=1)
    doc.add_paragraph(f"Range: {data['range']}")
    doc.add_paragraph(f"Total submissions: {data['total']}    Breached: {data['breached']}")

    try:
        chart_bytes = _generate_chart_png(data)
        chart_buf = io.BytesIO(chart_bytes)
        doc.add_picture(chart_buf, width=Cm(16))
    except Exception as e:
        logger.warning(f"Chart embed failed in DOCX export: {e}")

    def make_table(title, rows):
        doc.add_heading(title, level=2)
        table = doc.add_table(rows=1, cols=2)
        table.style = 'Light Grid Accent 1'
        hdr = table.rows[0].cells
        hdr[0].text, hdr[1].text = 'Label', 'Count'
        for label, count in rows:
            cells = table.add_row().cells
            cells[0].text = str(label or 'Clean')
            cells[1].text = str(count)
        doc.add_paragraph()

    make_table("Strength Distribution", data['strength'])
    make_table("Behaviour Profile Distribution", data['profile'])
    make_table("Breach Risk Distribution", data['risk'])

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return send_file(buf,
                      mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                      as_attachment=True, download_name=f'bambivault_stats_{data["range_suffix"]}.docx')


@app.route('/api/records')
@login_required
def api_records():
    page       = request.args.get('page', 1, type=int)
    per_page   = min(request.args.get('per_page', 15, type=int), 100)  # capped to prevent overload
    strength_f = request.args.get('strength', '')
    breach_f   = request.args.get('breach', '')
    profile_f  = request.args.get('profile', '')

    query = PasswordLog.query.filter_by(user_id=session['user_id'])
    if strength_f:
        query = query.filter_by(strength_label=strength_f)
    if breach_f == 'yes':
        query = query.filter_by(breach_exposed=True)
    elif breach_f == 'no':
        query = query.filter_by(breach_exposed=False)
    if profile_f:
        if profile_f == 'Clean':
            query = query.filter(
                (PasswordLog.behaviour_profile == 'Clean') |
                (PasswordLog.behaviour_profile.is_(None))
            )
        else:
            query = query.filter_by(behaviour_profile=profile_f)

    records = query.order_by(PasswordLog.submitted_at.desc()) \
                    .paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'records': [r.to_dict() for r in records.items],
        'total':   records.total,
        'pages':   records.pages,
        'page':    page
    })


if __name__ == '__main__':
    logger.info("BambiVault starting up")
    app.run(debug=FLASK_DEBUG)
