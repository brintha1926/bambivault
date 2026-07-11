# BambiVault

An Interactive System for Evaluating Password Behaviour and Security Awareness Among University Students.

Final Year Project (FYP) by **Brintha A/P Subramoney** (23ACB05162)
Supervisor: Nor'Afifah Binti Sabri
Universiti Tunku Abdul Rahman (UTAR) — Bachelor of Information Technology (Honours), Communications and Networking

## Overview

Rule-based password checkers only evaluate surface-level complexity (length, symbols, digits), which means predictable but "compliant" passwords like `P@ssw0rd1` pass every rule while still being trivially crackable. BambiVault addresses this by combining:

- **ML-based strength classification** — a Random Forest model trained on real-world leaked password data, classifying passwords into five tiers (Very Weak → Very Strong) and identifying *why* a password is weak, not just a score.
- **Real-time breach detection** — integration with the Have I Been Pwned (HIBP) Pwned Passwords API using the k-Anonymity protocol, so the full password or hash is never transmitted over the network.
- **Personalised behavioural feedback** — pattern detection for keyboard walks, name+year combinations, character substitutions, and dictionary words, mapped to targeted recommendations.
- **Anonymised admin dashboard** — aggregated, anonymised institutional statistics for university staff, with no plaintext passwords or user-identifying data ever stored.

## Features

- Student-facing password analyser with live strength meter
- Custom breach detection engine (`breach.py`) combining HIBP API results with local pattern-matching rules, a composite 5-tier risk score, and a persistent SQLite-backed cache
- Behavioural profile classification (Keyboard-Walk, Name+Year, Substitution, Dictionary-Word, Clean)
- Admin dashboard with strength distribution, breach risk levels, behavioural profile trends, period-over-period comparison, and CSV/PDF/DOCX/TXT export
- Anonymised, filterable database records view
- Rate limiting and structured logging on the backend

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask, Flask-SQLAlchemy |
| Machine Learning | scikit-learn (Random Forest), joblib |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite |
| Breach Detection | Have I Been Pwned (HIBP) Pwned Passwords API |
| Training Data | RockYou leaked password corpus |

## Project Structure

```
fyp_password/
├── app.py                     # Flask application and API routes
├── breach.py                  # Breach detection module (HIBP + local rules)
├── feature_extraction.py      # Password feature/entropy extraction
├── models.py                  # SQLAlchemy database model
├── train_model_v3.py          # Model training script
├── generate_training_data_v3.py
├── clean_data.py               # Dataset cleaning pipeline
├── templates/                 # HTML pages (analyser, dashboard, admin, database)
├── static/                    # CSS
├── data/                      # Datasets (not fully included — see below)
└── model/                     # Trained model file (not included — see below)
```

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/brintha1926/bambivault.git
cd bambivault
```

### 2. Create a virtual environment and install dependencies

```bash
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 3. Create your `.env` file

Create a file named `.env` in the project root:

```
SECRET_KEY=your-random-secret-key-here
ADMIN_PASSWORD=your-admin-password-here
DATABASE_URL=sqlite:///password_logs.db
FLASK_DEBUG=True
```

Generate a secure random key with:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Regenerate the dataset and model (not included in this repo)

Due to GitHub's file size limits, the following are **not** included:
- `data/rockyou.txt`, `data/rockyou_clean.txt` (raw and cleaned RockYou corpus)
- `data/training_data_v3.csv` (generated training features)
- `model/strength_model_rf_v3.pkl` (trained Random Forest model)

To regenerate them:

```bash
# 1. Place a copy of rockyou.txt in data/
python clean_data.py
python generate_training_data_v3.py
python train_model_v3.py
```

This produces `model/strength_model_rf_v3.pkl`, which `app.py` loads on startup.

### 5. Run the app

```bash
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.

## Notes on Privacy

- No plaintext passwords or complete password hashes are ever stored.
- Only the first 5 characters of a password's SHA-1 hash are sent to the HIBP API (k-Anonymity).
- Database records store only strength labels, detected pattern flags, entropy scores, and breach status — no user-identifying information.

## Status

This project is under active development as part of FYP II. See the project report for full methodology, literature review, and system design details.
