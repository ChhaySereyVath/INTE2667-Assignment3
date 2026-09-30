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

voting-subsystem/
│
├── app/
│   ├── __init__.py
│   ├── routes/
│   │   ├── auth.py          # voter authentication, token issuance
│   │   ├── ballot.py        # ballot presentation
│   │   ├── vote.py          # vote submission
│   │   └── verify.py        # vote verification
│   │
│   ├── models/
│   │   ├── voter.py         # voter record, has_voted flag
│   │   ├── ballot.py        # ballot structure
│   │   └── vote.py          # encrypted vote record
│   │
│   ├── security/
│   │   ├── token.py         # one-time voting token generation/validation
│   │   ├── csrf.py          # CSRF token management
│   │   ├── encryption.py    # vote encryption at rest
│   │   └── rate_limiter.py  # rate limiting
│   │
│   └── database/
│       └── db.py            # parameterised query helpers
│
├── tests/
│   ├── test_token.py        # one-time token tests
│   ├── test_double_vote.py  # prevent voting twice
│   ├── test_csrf.py         # CSRF protection tests
│   ├── test_sql_injection.py # parameterised query tests
│   └── test_ballot.py       # ballot validation tests
│
├── requirements.txt
├── README.md
└── .github/
    └── workflows/
        └── security-tests.yml  # CI/CD pipeline

## 🛠️ Installation and Setup

### Prerequisites

- Python 3.8+
- Docker (optional, for containerized deployment)
- Git

### Method 1: Local Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd PythonRestBankingApp
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env file with your configuration
   ```

5. **Initialize the database**
   ```bash
   python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"
   ```

6. **Run the application**
   ```bash
   python run.py
   ```

7. **Access the application**
   - Web Interface: http://localhost:3000
   - API Documentation: http://localhost:3000/health

### Method 2: Docker Deployment

1. **Using Docker Compose (Recommended)**
   ```bash
   docker-compose up -d
   ```

2. **Using Docker directly**
   ```bash
   docker build -t inte2667_electronic_vote .
   docker run -p 3000:3000 inte2667_electronic_vote
   ```
