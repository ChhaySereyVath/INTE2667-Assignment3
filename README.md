# INTE2667 Assignment 3 - Electronic Voting System

A secure Python web application for Electronic Voting, built with Flask, featuring REST API services, JWT authentication, password hashing, and Docker deployment.

This application will contain the following subsystems
- Enrollment / Registration
- Voting
- Audit / Logs

## 🏗️ Architecture
This is a full stack application with:

- **Backend**: Flask REST API with SQLite database
- **Frontend**: HTML/CSS/JavaScript with Bootstrap
- **Security**: JWT authentication, bcrypt password hashing
- **Deployment**: Docker containerized
- **Database**: SQLite with SQLAlchemy ORM

## 🚀 Features

## 📁 Project Structure

evp/                                    ← root of the group repo
.
├── app/
│   ├── __init__.py                 app factory, config, fail-closed secrets
│   ├── models/
│   │   ├── user.py                 shared User model
│   │   ├── auth_models.py          sessions, tokens, throttles, MFA keys, recovery, outbox
│   │   ├── enrollment_models.py    enrolments and their change history
│   │   ├── election_models.py      elections, contests, candidates
│   │   ├── voting_models.py        entitlements and ballots
│   │   ├── audit_models.py         tamper-evident audit log
│   │   └── results_models.py
│   ├── routes/
│   │   ├── auth.py                 /auth: register, login, MFA, admin
│   │   ├── recovery.py             /auth/recovery
│   │   ├── enrollment.py           /enrollment and its pages
│   │   ├── elections.py, candidates.py, voting.py, results.py, audit.py
│   │   └── pages.py                HTML pages (login, register, admin, ...)
│   ├── security/
│   │   ├── shared_security.py      errors, headers, clock, sessions, permissions
│   │   ├── auth_security.py        login, tokens, throttling, staff accounts
│   │   ├── mfa_security.py         WebAuthn
│   │   ├── recovery_security.py    account recovery
│   │   ├── crypto.py, validators.py, signing.py
│   │   ├── enrollment_security.py, voting_security.py, election_security.py
│   │   └── audit_security.py, backup.py, counting.py, integrity.py, ...
│   ├── templates/                  base.html and one folder per area
│   │   ├── auth/  admin/  recovery/  enrollment/
│   │   └── elections/  voting/  results/  audit/
│   └── static/
│       ├── css/app.css
│       └── js/                     one script per page, no inline scripts (CSP)
├── tests/                          pytest suite, one file per area
├── .github/workflows/security-tests.yml   CI: pytest, Bandit, pip-audit, gitleaks
├── requirements.txt
├── run.py
└── .env.example                    copy to .env and fill in every key


## Subsytems 🛠🛠

Enrollment subsystem          Voting subsystem
─────────────────────         ────────────────────────
Creates Voter record          Reads Voter record
Sets is_enrolled = True  →→→  Checks is_enrolled
Sets has_voted = False        Sets has_voted = True
Stores electorate/state  →→→  Uses to serve correct ballot

## Setup (Windows)

1. Install **Python 3.12** (newer versions fail to install some pinned packages).
2. In the project folder:
```
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   copy .env.example .env
```
3. Fill every key in `.env` with its own value:
   `python -c "import secrets; print(secrets.token_hex(32))"`
4. Optional, for HTTPS: `flask make-cert`

## Run
```
python run.py
```
Open https://localhost:5000. The database is created in `instance\evp.db`.

## Accounts and email
- Staff accounts: `flask create-user dana --role commissioner_delegate`
  (roles: citizen, aec_employee, commissioner_delegate, administrator, auditor)
- Email is simulated. `flask outbox` prints activation and recovery links.
- Staff must add a security key at first sign-in (Chrome DevTools → WebAuthn → virtual authenticator works).

## Tests
```
pytest -q
```

## Demo data and checks
| Command | What it does |
|---|---|
| `flask seed-election --creator dana` | demo election with candidates |
| `flask demo-voters --count 12` / `flask demo-votes --election <id>` | demo voters and ballots |
| `flask backup`, `flask verify-backup`, `flask restore-status` | encrypted backups and restore tests |
| `flask audit-anchor`, `flask audit-verify`, `flask verify-actions` | audit trail and signed-action checks |
| `flask load-test --url https://localhost:5000` | prototype load test |
