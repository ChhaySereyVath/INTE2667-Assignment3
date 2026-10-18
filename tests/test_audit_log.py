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

# --- KE02 ---

def test_an_event_records_actor_action_target_result_and_time(app, frozen_clock):
    from app.security.audit_security import append_event

    with app.app_context():
        alice = make_user()
        append_event("access_denied", "denied", alice, "enrolment", "record-1")
        db.session.commit()
        event = AuditEvent.query.one()
        assert event.actor_id == alice.id and event.actor_role == "citizen"
        assert (event.action, event.target_type, event.target_id, event.result) == (
            "access_denied", "enrolment", "record-1", "denied")
        assert event.occurred_at == frozen_clock.now()


def test_only_known_actions_and_results_are_accepted(app):
    from app.security.audit_security import append_event

    with app.app_context():
        with pytest.raises(ValueError):
            append_event("made_up_action", "success")
        with pytest.raises(ValueError):
            append_event("logout", "maybe")


def test_two_events_can_never_share_a_number(app):
    """R14: the head row hands out numbers one at a time, so the chain never forks."""
    from app.models.audit_models import AuditHead

    three_events(app)
    with app.app_context():
        head = db.session.get(AuditHead, 1)
        last = AuditEvent.query.order_by(AuditEvent.seq.desc()).first()
        assert (head.seq, head.record_hash) == (3, last.record_hash)


def test_each_event_carries_the_hash_of_the_one_before(app):
    three_events(app)
    first, second, third = events(app)
    assert (first["seq"], second["seq"], third["seq"]) == (1, 2, 3)
    with app.app_context():
        rows = AuditEvent.query.order_by(AuditEvent.seq).all()
        assert rows[0].prev_hash == "0" * 64
        assert rows[1].prev_hash == rows[0].record_hash
        assert rows[2].prev_hash == rows[1].record_hash
        assert len({row.record_hash for row in rows}) == 3

# --- KE03 ---

def test_secrets_and_ballot_choices_never_reach_the_trail(app):
    """R13: 'Passwords, tokens, keys and ballot choices are excluded from logs.'"""
    from app.security.audit_security import append_event

    with app.app_context():
        append_event("login_failed", "failure", None, "account", None,
                     password="Correct-Horse-42", token="eyJabc.def.ghi", key="00ff" * 16,
                     preferences=["cand-1", "cand-2"], reason="wrong password")
        db.session.commit()
        details = json.loads(AuditEvent.query.one().details)
    assert details == {"reason": "wrong password"}


def test_detail_values_are_cut_short(app):
    from app.security.audit_security import append_event

    with app.app_context():
        append_event("access_denied", "denied", reason="x" * 5000)
        db.session.commit()
        assert len(json.loads(AuditEvent.query.one().details)["reason"]) == 100

# --- KE04 ---

def test_an_untouched_trail_verifies(app):
    from app.security.audit_security import verify_chain

    three_events(app)
    with app.app_context():
        assert verify_chain() == []


def test_changing_an_event_is_detected(app):
    from app.security.audit_security import verify_chain

    three_events(app)
    as_dba(app, "UPDATE audit_events SET result = 'success' WHERE seq = 2")
    with app.app_context():
        assert "event 2 has been altered" in verify_chain()


def test_deleting_an_event_is_detected(app):
    from app.security.audit_security import verify_chain

    three_events(app)
    as_dba(app, "DELETE FROM audit_events WHERE seq = 2")
    with app.app_context():
        problems = verify_chain()
    assert "event 2 is missing" in problems
    assert "event 3 does not follow the event before it" in problems


def test_reordering_events_is_detected(app):
    from app.security.audit_security import verify_chain

    three_events(app)
    as_dba(app, "UPDATE audit_events SET seq = 99 WHERE seq = 1",
           "UPDATE audit_events SET seq = 1 WHERE seq = 3",
           "UPDATE audit_events SET seq = 3 WHERE seq = 99")
    with app.app_context():
        assert verify_chain() != []

# --- KE05 ---

def test_the_database_refuses_to_change_or_delete_events(app):
    """R14: 'Audit records are append-only for ordinary application and administrator roles.'"""
    three_events(app)
    with app.app_context():
        for statement in ("UPDATE audit_events SET result = 'success' WHERE seq = 1",
                          "DELETE FROM audit_events WHERE seq = 1"):
            with pytest.raises(IntegrityError), db.engine.begin() as connection:
                connection.exec_driver_sql(statement)
        assert AuditEvent.query.count() == 3


def test_there_is_no_endpoint_that_changes_the_trail(app):
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/audit"):
            assert not ({"PUT", "PATCH", "DELETE"} & rule.methods), rule.rule

# --- KE06 ---

def test_canonical_json_is_the_same_whatever_the_key_order():
    from app.security.signing import canonical_json

    assert canonical_json({"b": 1, "a": [2, "x"]}) == canonical_json({"a": [2, "x"], "b": 1}) == '{"a":[2,"x"],"b":1}'


def test_a_signature_verifies_only_for_the_exact_data(app):
    from app.security.signing import public_key_hex, sign, verify

    with app.app_context():
        public = public_key_hex("ACTION_SIGNING_KEY")
        signature = sign({"action": "candidate_create", "name": "Morgan"}, "ACTION_SIGNING_KEY")
        assert verify({"name": "Morgan", "action": "candidate_create"}, signature, public)
        assert not verify({"action": "candidate_create", "name": "Morgen"}, signature, public)
        other = public_key_hex("AUDIT_SIGNING_KEY")
        assert not verify({"action": "candidate_create", "name": "Morgan"}, signature, other)


def test_a_rebuilt_chain_is_caught_by_the_signed_anchor(app):
    """Someone who rewrites an event AND recomputes every hash after it fools the
    chain. The anchor, signed with a key the database never sees, still catches it."""
    from app.security.audit_security import verify_anchors, verify_chain, write_anchor
    from app.security.audit_security import compute_hash

    three_events(app)
    with app.app_context():
        write_anchor()
    as_dba(app, "UPDATE audit_events SET result = 'success' WHERE seq = 2")
    with app.app_context():
        rows = AuditEvent.query.order_by(AuditEvent.seq).all()
        prev = rows[0].record_hash
        for row in rows[1:]:  # the attacker "fixes" the chain
            new_hash = compute_hash(prev, row)
            with db.engine.begin() as connection:
                connection.exec_driver_sql(
                    "UPDATE audit_events SET prev_hash = ?, record_hash = ? WHERE seq = ?",
                    (prev, new_hash, row.seq))
            prev = new_hash
        with db.engine.begin() as connection:
            connection.exec_driver_sql("UPDATE audit_head SET record_hash = ?", (prev,))
        db.session.expire_all()
        assert verify_chain() == []  # the chain alone is fooled...
        assert verify_anchors() == ["anchor 1: event 3 no longer matches"]  # ...the anchor is not


def test_cutting_events_off_the_end_is_caught(app):
    from app.security.audit_security import verify_anchors, verify_chain, write_anchor

    three_events(app)
    with app.app_context():
        write_anchor()
    as_dba(app, "DELETE FROM audit_events WHERE seq = 3")
    with app.app_context():
        assert verify_chain() == ["the trail should end at event 3 but ends at event 2"]
    # a careful attacker moves the end marker back too: the chain alone is fooled...
    as_dba(app, "UPDATE audit_head SET seq = 2, record_hash = "
                "(SELECT record_hash FROM audit_events WHERE seq = 2)")
    with app.app_context():
        assert verify_chain() == []
        assert verify_anchors() == ["anchor 1: event 3 is gone"]  # ...the signed anchor is not


def test_a_forged_anchor_is_rejected(app):
    from app.security.audit_security import verify_anchors, write_anchor

    three_events(app)
    with app.app_context():
        write_anchor()
        path = app.config["AUDIT_ANCHOR_FILE"]
    with open(path, encoding="utf-8") as handle:
        anchor = json.loads(handle.readline())
    anchor["seq"] = 2  # point the anchor somewhere else without the private key
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(anchor) + "\n")
    with app.app_context():
        assert verify_anchors() == ["anchor 1 has an invalid signature"]