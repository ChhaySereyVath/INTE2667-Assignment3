import uuid

from app import db
from app.security.shared_security import utcnow

# R13: one fixed list of action names, so every event is spelt the same way
AUDIT_ACTIONS = (
    "login_success", "login_failed", "login_locked", "logout",
    "mfa_success", "mfa_failed",
    "access_denied",
    "enrolment_change",
    "role_granted", "staff_created", "recovery_decision",
    "election_transition", "eligibility_decision", "ballot_accepted",
    "candidate_change", "count_run", "integrity_failed", "result_approved",
    "exclusion_proposed", "exclusion_confirmed",
    "audit_verified", "audit_verify_failed",
)
RESULTS = ("success", "denied", "failure")

GENESIS_HASH = "0" * 64  # the "previous hash" of the very first event


class AuditEvent(db.Model):
    """R13/R14: one security or administrative event, chained to the one before it."""

    __tablename__ = "audit_events"

    seq = db.Column(db.Integer, primary_key=True, autoincrement=False)
    occurred_at = db.Column(db.DateTime, nullable=False)
    actor_id = db.Column(db.String(36))  # None for anonymous events (an unknown user's login)
    actor_role = db.Column(db.String(30))
    action = db.Column(db.String(40), nullable=False)
    target_type = db.Column(db.String(30))
    target_id = db.Column(db.String(64))
    result = db.Column(db.String(10), nullable=False)
    details = db.Column(db.Text, nullable=False, default="{}")  # JSON, allowlisted keys only
    prev_hash = db.Column(db.String(64), nullable=False)
    record_hash = db.Column(db.String(64), nullable=False, unique=True)

    def to_dict(self):
        import json

        return {
            "seq": self.seq,
            "occurred_at": self.occurred_at.isoformat(),
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "result": self.result,
            "details": json.loads(self.details),
            "record_hash": self.record_hash,
        }


class AuditHead(db.Model):
    """R14: one row that says where the trail ends (last seq and its hash).

    Every append first UPDATEs this row. That makes the database hand out one write
    lock at a time, so two requests logging at the same moment get seq 5 and seq 6,
    never both seq 5 (a fork in the chain). It also lets verification notice events
    cut off the end of the trail.
    """

    __tablename__ = "audit_head"

    id = db.Column(db.Integer, primary_key=True)
    seq = db.Column(db.Integer, nullable=False)
    record_hash = db.Column(db.String(64), nullable=False)

APPEND_ONLY_TABLES = ("audit_events",)

def protect_audit(engine):
    """R14/R15: the DATABASE refuses to change or delete audit and signed records.

    The application never needs to, so nothing is lost. Someone with the sqlite3 tool
    can still drop these triggers; that is what the hash chain and the signatures
    catch (verify_chain, verify_actions).
    """
    statements = []
    for table in APPEND_ONLY_TABLES:
        statements += [
            f"DROP TRIGGER IF EXISTS {table}_no_update",
            f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} "
            f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END",
            f"DROP TRIGGER IF EXISTS {table}_no_delete",
            f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} "
            f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END",
        ]
    # the head row starts at "nothing yet"; OR IGNORE keeps an existing one
    statements.append("INSERT OR IGNORE INTO audit_head (id, seq, record_hash) "
                      f"VALUES (1, 0, '{GENESIS_HASH}')")
    with engine.begin() as connection:
        for statement in statements:
            connection.exec_driver_sql(statement)

class SecurityAlert(db.Model):
    """R14: raised when verification finds the audit trail (or other evidence) altered."""

    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(40), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)