"""R13/R14: the audit trail records security events and shows any tampering (Keane)."""
import json

import pytest
from sqlalchemy.exc import IntegrityError

from app import db
from app.models.audit_models import AuditEvent
from tests.conftest import csrf_headers, verify_mfa
from tests.test_auth_login import login, make_user


def three_events(app):
    """A short trail to tamper with: three events by one user."""
    from app.security.audit_security import append_event

    with app.app_context():
        alice = make_user()
        for number in range(3):
            append_event("access_denied", "denied", alice, "enrolment", f"record-{number}")
        db.session.commit()


def as_dba(app, *statements):
    """Run SQL the way someone with the sqlite3 tool would: triggers removed first.
    This is the attacker R14 is about: someone with direct access to the database."""
    with app.app_context(), db.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS audit_events_no_update")
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS audit_events_no_delete")
        for statement in statements:
            connection.exec_driver_sql(statement)


def events(app):
    with app.app_context():
        return [event.to_dict() for event in AuditEvent.query.order_by(AuditEvent.seq)]


# --- KE01 ---

def test_an_audit_event_has_the_fields_r13_asks_for():
    """R13: 'Logs record actor, action, target, result and timestamp.'"""
    columns = {c.name for c in AuditEvent.__table__.columns}
    assert {"actor_id", "action", "target_type", "target_id", "result", "occurred_at"} <= columns
    assert {"seq", "prev_hash", "record_hash"} <= columns  # for the chain (KE02)


def test_the_trail_starts_empty_with_its_end_marker_at_zero(app):
    from app.models.audit_models import AuditHead

    with app.app_context():
        head = db.session.get(AuditHead, 1)
        assert (head.seq, head.record_hash) == (0, "0" * 64)
        assert AuditEvent.query.count() == 0