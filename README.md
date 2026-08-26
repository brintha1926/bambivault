# BambiVault

[BambiVault](https://bambivault.com) is a password-security assessment and encrypted credential-management platform. It combines experimental machine-learning classification with explicit behavioural-pattern detection, privacy-preserving breach intelligence, personalised guidance, account security controls, and anonymised administrative reporting.

Production health: [`https://bambivault.com/healthz`](https://bambivault.com/healthz)

## Capabilities

- Five-tier experimental password classification using a Random Forest model trained on derived structural labels
- Detection of keyboard walks, name-and-year patterns, substitutions, and dictionary words
- Have I Been Pwned range queries using only the first five characters of a SHA-1 hash
- Stronger-password variants derived from the submitted structure without sending plaintext passwords to an AI service
- Encrypted credential vault protected by a master password and separate Account Key
- Email verification, password recovery, tracked sessions, recovery codes, and TOTP authentication
- Aggregated administrative analytics with CSV, PDF, DOCX, and text exports
- Responsive public, account, vault, dashboard, and administrator interfaces

## Analysis boundaries

The classifier is an experimental indicator rather than a guarantee of password security. Its output is presented alongside observable pattern evidence, breach exposure, length, character composition, and estimated resistance. The displayed entropy-related value is a model feature and is not presented as the password's complete information-theoretic entropy.

Submitted plaintext passwords are processed for the current analysis and are not written to analysis history. Breach lookups use the Have I Been Pwned k-anonymity range protocol: the full password and full hash are not transmitted to the provider.

## Production architecture

| Layer | Production implementation |
|---|---|
| Domain and TLS | `bambivault.com`, Nginx, Let's Encrypt |
| Compute | IPServerOne NovaCloud, Ubuntu 24.04 LTS |
| Application server | Gunicorn managed by systemd |
| Backend | Python 3, Flask, Flask-SQLAlchemy |
| Database | Neon PostgreSQL with Alembic migrations |
| Machine learning | scikit-learn Random Forest loaded with joblib |
| Transactional email | Brevo HTTPS API |
| Breach intelligence | Have I Been Pwned Pwned Passwords API |
| Frontend | Server-rendered Jinja, compiled Tailwind CSS, JavaScript, Alpine.js CSP build |
| Testing | pytest and mypy |

Nginx terminates HTTPS and forwards requests to Gunicorn on `127.0.0.1:8000`. Gunicorn is not exposed directly to the public network. PostgreSQL remains externally managed by Neon; no database port is opened on the application server.

## Security controls

- Secure, HTTP-only, SameSite session cookies in production
- CSRF protection for state-changing browser requests
- Database-backed throttling for authentication and analysis endpoints
- Revocable tracked user sessions
- Case-normalised username identity and bounded input validation
- TOTP secrets encrypted at rest, replay protection, and hashed recovery codes
- Password resets revoke active user sessions
- Global request-body size limit
- Sensitive responses marked to prevent browser caching
- Strict Content Security Policy with per-request script nonces
- Vault keys derived from the master password and Account Key using PBKDF2-HMAC-SHA256
- Authenticated Fernet encryption for stored vault fields
- Password-protected PDF and AES-encrypted ZIP account exports
- Aggregated administrator reporting without submitted plaintext passwords

## Public and protected routes

| Method | Route | Access | Purpose |
|---|---|---|---|
| `GET` | `/` | Public | Product and methodology overview |
| `GET` | `/analyser` | Public | Password-analysis interface |
| `POST` | `/analyse` | Public, rate-limited | Evaluate structure, patterns, and breach exposure |
| `GET` | `/api/stats` | Authenticated user | Personal analysis statistics |
| `GET`, `POST` | `/api/vault/entries` | Authenticated user, unlocked vault | List metadata or create an encrypted vault entry |
| `GET` | `/api/admin/stats` | Authenticated administrator | Aggregated security statistics |
| `GET` | `/healthz` | Public | Application and database readiness |
| `GET` | `/robots.txt` | Public | Search-crawler directives |
| `GET` | `/sitemap.xml` | Public | Canonical public-page sitemap |

Account, vault, dashboard, history, settings, and administrator templates default to `noindex, nofollow`. Only the landing page and public analyser are included in the sitemap.

## Local development

Requirements:

- Python 3.12 or later
- Node.js only when rebuilding the compiled Tailwind stylesheet

```powershell
git clone https://github.com/brintha1926/bambivault.git
cd bambivault
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Create `.env` in the repository root. Never commit this file.

```dotenv
SECRET_KEY="replace-with-a-random-secret"
ADMIN_PASSWORD="replace-with-a-strong-administrator-password"
ADMIN_EMAIL="administrator@example.com"
DATABASE_URL="sqlite:///password_logs.db"
FLASK_ENV="development"
FLASK_DEBUG="True"
APP_BASE_URL="http://127.0.0.1:5000"
TRUSTED_PROXY_HOPS="0"
```

Generate a Flask session secret with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Start the development server:

```powershell
python app.py
```

Open `http://127.0.0.1:5000`.

## Optional integrations

Use Brevo's HTTPS transactional API where direct SMTP is restricted:

```dotenv
BREVO_API_KEY="replace-with-a-Brevo-API-key"
EMAIL_FROM="verified-sender@example.com"
EMAIL_FROM_NAME="BambiVault"
```

`EMAIL_FROM` must be verified by Brevo. SMTP variables remain supported as a fallback in environments that permit outbound SMTP. `GROQ_API_KEY` enables the optional AI recommendation integration; password data is not sent to that integration.

## Database preparation and migration

Initialise or upgrade the configured database schema:

```powershell
python -m flask --app app bootstrap
```

For PostgreSQL, use a TLS-enabled connection string:

```powershell
$env:DATABASE_URL="postgresql+psycopg://USER:PASSWORD@HOST/DATABASE?sslmode=require"
python -m flask --app app bootstrap
```

To migrate existing SQLite records to an empty PostgreSQL schema:

```powershell
$env:POSTGRES_DATABASE_URL=$env:DATABASE_URL
python migrate_sqlite_to_postgres.py --source instance/password_logs.db --dry-run
python migrate_sqlite_to_postgres.py --source instance/password_logs.db
```

The migration validates row counts and vault ownership, preserves encrypted vault ciphertext, and updates PostgreSQL identity sequences.

## Model assets

The compressed trained model is versioned at `model/strength_model_rf_v3.pkl`. Source datasets and generated training files are intentionally excluded from Git.

To rebuild the model:

```powershell
python clean_data.py
python generate_training_data_v3.py
python train_model_v3.py
```

## Frontend assets

Production uses the compiled stylesheet at `static/tailwind.css`; it does not load the Tailwind browser CDN. After changing utility classes in templates:

```powershell
npm install
npm run build:css
```

## Verification

Install development dependencies and run the automated checks:

```powershell
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -v
python -m mypy feature_extraction.py strengthen.py config.py security_utils.py migrate_sqlite_to_postgres.py
```

The suite covers analysis contracts, breach-cache isolation, behavioural classification, authentication boundaries, session revocation, email delivery, PostgreSQL transfer validation, stronger-password variants, vault cryptography, protected exports, and SEO boundaries.

## Production operations

The active deployment uses `/opt/bambivault`, a virtual environment at `/opt/bambivault/.venv`, and the `bambivault.service` systemd unit. Production secrets are stored in `/opt/bambivault/.env` with restricted permissions.

Deploy a merged update from `main`:

```bash
cd /opt/bambivault
git pull --ff-only origin main
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m flask --app app bootstrap
sudo systemctl restart bambivault
sudo systemctl status bambivault --no-pager
curl https://bambivault.com/healthz
```

Follow application logs:

```bash
sudo journalctl -u bambivault -f
```

The repository retains a Dockerfile as an alternative packaging option, but the active NovaCloud deployment runs directly under systemd and Gunicorn.

## Repository structure

```text
app.py                         Flask application and primary HTTP routes
vault_routes.py                Account, session, export, and vault endpoints
models.py                      SQLAlchemy models
config.py                      Validated environment configuration
feature_extraction.py          Structural and behavioural feature extraction
ml_classifier.py               Experimental strength classification
strengthen.py                  Personalised stronger-password generation
breach.py                      Breach intelligence, cache, and risk scoring
security_utils.py              Validation, TOTP, and shared throttling
email_utils.py                 Verification and recovery email delivery
migrations/                    Alembic database revisions
model/                         Versioned compressed classifier
templates/                     Active Jinja templates
static/                        Compiled styles, scripts, and image assets
tests/                         Automated test suite
```

## Maintainer

Developed and maintained by [Brintha Subramoney](https://www.linkedin.com/in/brintha-subra/) as a final-year Bachelor of Information Technology (Honours), Communications and Networking project at Universiti Tunku Abdul Rahman.
