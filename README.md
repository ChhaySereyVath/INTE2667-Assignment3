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
│
├── app/
│   ├── __init__.py                     ← shared app factory — registers BOTH blueprints
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py                     ← shared Voter/User model (enrollment creates it,
│   │   │                                  voting reads it — ONE source of truth)
│   │   ├── enrollment_models.py        ← enrollment-specific models
│   │   └── voting_models.py            ← your voting-specific models
│   │
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── enrollment.py               ← enrollment blueprint (/enrollment/...)
│   │   ├── auth.py                     ← shared auth blueprint (/auth/...)
│   │   └── voting.py                   ← your voting blueprint (/voting/...)
│   │
│   ├── security/
│   │   ├── __init__.py
│   │   ├── shared_security.py          ← shared: JWT validation, rate limiter, CSRF
│   │   ├── enrollment_security.py      ← enrollment-specific security
│   │   └── voting_security.py          ← your voting-specific security
│   │
│   └── templates/
│       ├── base.html                   ← shared base template
│       ├── enrollment/                 ← enrollment templates
│       │   ├── register.html
│       │   └── status.html
│       └── voting/                     ← your voting templates
│           ├── ballot_house.html
│           ├── ballot_senate.html
│           └── confirmation.html
│
├── tests/
│   ├── test_enrollment_security.py     ← enrollment tests
│   └── test_voting_security.py         ← your voting tests
│
├── .github/
│   └── workflows/
│       └── security-tests.yml          ← CI/CD runs ALL tests
│
├── requirements.txt                    ← shared dependencies
├── run.py                              ← single entry point for both subsystems
├── docker-compose.yml
└── .env

## Subsytems 🛠🛠

Enrollment subsystem          Voting subsystem
─────────────────────         ────────────────────────
Creates Voter record          Reads Voter record
Sets is_enrolled = True  →→→  Checks is_enrolled
Sets has_voted = False        Sets has_voted = True
Stores electorate/state  →→→  Uses to serve correct ballot

