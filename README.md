# BambiVault

BambiVault is a password-security assessment and encrypted credential-management platform. It combines machine-learning classification, behavioural pattern detection, privacy-preserving breach intelligence, personalised guidance, account security controls, and anonymised administrative reporting.

## Core capabilities

- Five-tier password-strength classification using a Random Forest model
- Detection of keyboard walks, name-and-year patterns, substitutions, and dictionary words
- Have I Been Pwned range queries using a five-character SHA-1 prefix
- Personalised stronger-password variants generated without sending plaintext passwords to an AI service
- Encrypted credential vault protected by a master password and Account Key
- Email verification, password recovery, session management, and TOTP authentication
- Aggregated administrative analytics with CSV, PDF, DOCX, and text exports

### API reference

| Method | Route | Access | Purpose |
|---|---|---|---|
| `POST` | `/analyse` | Public, rate-limited | Evaluate password strength, patterns, and breach exposure |
| `GET` | `/api/stats` | Authenticated user | Retrieve personal analysis statistics |
| `GET`, `POST` | `/api/vault/entries` | Authenticated user with an unlocked vault | List metadata or create an encrypted vault entry |
| `GET` | `/api/admin/stats` | Administrator | Retrieve aggregated institutional statistics |

## Technology

| Layer | Technology |
|---|---|
| Backend | Python, Flask, Flask-SQLAlchemy |
| Database | SQLite for development; PostgreSQL/Neon for production |
| Machine learning | scikit-learn, Random Forest, joblib |
| Frontend | Jinja, HTML, CSS, JavaScript, Alpine.js |
| Breach intelligence | Have I Been Pwned Pwned Passwords API |
| Database migrations | Alembic, Flask-Migrate |
| Testing and typing | pytest, mypy |

## Security boundaries

- Submitted passwords are not stored in plaintext.
- Breach queries transmit only a five-character SHA-1 prefix.
- Analysis history contains derived attributes rather than submitted passwords.
- Vault fields are encrypted before database storage.
- Vault decryption requires the master password and Account Key.
- Recovery codes are stored as password hashes.
- Authentication and analysis throttling uses shared database counters.
- Administrative reporting contains aggregated, anonymised statistics.

## Local development

```powershell
git clone https://github.com/brintha1926/bambivault.git
cd bambivault
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

The application is available at `http://127.0.0.1:5000`.

## Configuration

Create `.env` in the repository root. Do not commit this file.

```dotenv
SECRET_KEY="replace-with-a-random-secret"
ADMIN_PASSWORD="replace-with-a-strong-administrator-password"
DATABASE_URL="sqlite:///password_logs.db"
FLASK_ENV="development"
FLASK_DEBUG="True"
APP_BASE_URL="http://127.0.0.1:5000"
```

Optional integrations use `GROQ_API_KEY`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM`.

Generate a Flask session secret with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

## Model assets

The compressed trained model is included for reproducible deployment. Source datasets remain excluded from Git. To rebuild the model:

```powershell
python clean_data.py
python generate_training_data_v3.py
python train_model_v3.py
```

The resulting model must be saved at `model/strength_model_rf_v3.pkl`. Use Joblib compression when preparing it for source control.

## PostgreSQL migration

Set the direct PostgreSQL connection string and initialise the schema:

```powershell
$env:DATABASE_URL="postgresql+psycopg://USER:PASSWORD@HOST/DATABASE?sslmode=require"
python -m flask --app app bootstrap
```

To transfer existing SQLite data:

```powershell
$env:POSTGRES_DATABASE_URL=$env:DATABASE_URL
python migrate_sqlite_to_postgres.py --source instance/password_logs.db --dry-run
python migrate_sqlite_to_postgres.py --source instance/password_logs.db
```

The transfer validates row counts, checks vault ownership, and updates PostgreSQL identity sequences. Vault ciphertext is copied without decryption.

## Testing

```powershell
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -v
python -m mypy feature_extraction.py strengthen.py config.py security_utils.py migrate_sqlite_to_postgres.py
```

The automated suite covers analysis responses, breach fallbacks, caching, behavioural classification, authentication boundaries, PostgreSQL transfer validation, Unicode input, stronger-password variants, vault cryptography, and secure exports.

## Production deployment

Set `FLASK_ENV=production` and configure secrets through the hosting provider. Run database preparation once as the release or pre-deploy command:

```bash
flask --app app bootstrap
```

The Docker image starts Gunicorn automatically and uses the platform-provided `PORT`. For a native Python deployment, start the workers with:

```bash
gunicorn --bind 0.0.0.0:${PORT:-5000} --workers ${WEB_CONCURRENCY:-1} --threads ${GUNICORN_THREADS:-4} --timeout 60 app:app
```

The single-worker default prevents the in-memory model from being duplicated on smaller instances. Increase `WEB_CONCURRENCY` only when the deployment has sufficient memory. Database migrations must not run independently inside each worker.

## Repository structure

```text
app.py                         Flask application and API routes
vault_routes.py                Account, session, export, and vault endpoints
models.py                      SQLAlchemy models
feature_extraction.py          Password feature extraction
ml_classifier.py               Strength classification
strengthen.py                  Stronger-password generation
breach.py                      Breach intelligence and risk scoring
security_utils.py              Validation and shared throttling
migrations/                    Alembic database revisions
templates/                     Active Jinja templates
static/                        Styles and image assets
tests/                         Automated test suite
```

## Interface preview

The landing-page product preview is maintained at `static/img/landing-product.svg`. Production screenshots should be captured from the deployed build without local accounts or test records.

## Project provenance

BambiVault was developed by Brintha  Subramoney as a Bachelor of Information Technology (Honours), Communications and Networking 
