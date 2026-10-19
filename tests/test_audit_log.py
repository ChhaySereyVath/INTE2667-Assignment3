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

# --- KE07 ---

def test_a_failed_verification_raises_an_alert(app, caplog):
    """R14: 'Verification failures generate an alert.'"""
    from app.models.audit_models import SecurityAlert
    from app.security.audit_security import verify_audit_trail

    three_events(app)
    as_dba(app, "UPDATE audit_events SET result = 'success' WHERE seq = 2")
    with app.app_context():
        assert verify_audit_trail() != []
        alert = SecurityAlert.query.one()
        assert alert.kind == "audit_tampering"
        assert AuditEvent.query.order_by(AuditEvent.seq.desc()).first().action == "audit_verify_failed"
    assert any(record.levelname == "CRITICAL" for record in caplog.records)


def test_a_clean_verification_raises_no_alert(app):
    from app.models.audit_models import SecurityAlert
    from app.security.audit_security import verify_audit_trail

    three_events(app)
    with app.app_context():
        assert verify_audit_trail() == []
        assert SecurityAlert.query.count() == 0


def test_the_audit_commands_anchor_and_verify(app):
    three_events(app)
    runner = app.test_cli_runner()
    assert "Anchored event 3." in runner.invoke(args=["audit-anchor"]).output
    assert "Audit trail intact." in runner.invoke(args=["audit-verify"]).output
    as_dba(app, "DELETE FROM audit_events WHERE seq = 2")
    result = runner.invoke(args=["audit-verify"])
    assert result.exit_code == 1 and "FAIL" in result.output

# --- KE10 ---

def actions(app):
    return [event["action"] for event in events(app)]


def test_logins_logouts_and_lockouts_are_recorded(app, client):
    with app.app_context():
        alice_id = make_user().id
    login(client, "alice", "wrong-password-1")
    login(client, "nobody-here", "Correct-Horse-42")
    login(client, "alice", "Correct-Horse-42")
    client.post("/auth/logout", headers=csrf_headers(client))
    recorded = events(app)
    assert [e["action"] for e in recorded] == ["login_failed", "login_failed", "login_success", "logout"]
    assert recorded[0]["actor_id"] == alice_id
    assert recorded[1]["actor_id"] is None  # the unknown username itself is not stored
    assert "nobody-here" not in json.dumps(recorded)


def test_logins_at_the_same_moment_keep_one_chain(tmp_path):
    """R14: twenty failed logins at the same instant still make one unbroken chain,
    because the head row hands out one number at a time. Uses a database FILE so the
    threads really do run at once."""
    import threading

    from app import create_app
    from app.security.audit_security import verify_chain
    from tests.conftest import make_test_config

    app = create_app(make_test_config(SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'chain.db'}"))
    statuses = []

    def attempt(number):
        response = app.test_client().post("/auth/login", json={"username": f"user{number}",
                                                                "password": "wrong-password-1"})
        statuses.append(response.status_code)

    threads = [threading.Thread(target=attempt, args=(number,)) for number in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert statuses == [401] * 20
    with app.app_context():
        assert AuditEvent.query.count() == 20
        assert verify_chain() == []
        db.engine.dispose()


def test_a_locked_login_is_recorded(app, client):
    with app.app_context():
        make_user()
    for _ in range(app.config["LOGIN_MAX_FAILURES_PER_IP"] + 1):
        login(client, "alice", "wrong-password-1")
    assert actions(app)[-1] == "login_locked"

def test_a_refused_permission_is_recorded(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    assert client.get("/enrollment/pending").status_code == 403  # a staff-only list
    event = events(app)[-1]
    assert event["action"] == "access_denied" and event["result"] == "denied"
    assert event["details"] == {"permission": "enrolment:staff:read", "reason": "no permission"}

# --- KE11 ---

def test_austins_refused_record_access_is_recorded(app):
    from tests.test_enrollment_access import staff_client
    from tests.test_enrollment_hardening import vic_record

    record_id = vic_record(app)

    nsw = staff_client(app, "nick.nsw", "aec_employee", ["NSW"])
    assert nsw.get(f"/enrollment/{record_id}").status_code == 404
    event = events(app)[-1]
    assert (event["action"], event["target_type"], event["target_id"]) == (
        "access_denied", "enrolment", record_id)

# --- KE12 ---

def test_enrolment_changes_are_recorded_without_their_values(app):
    from tests.test_enrollment_access import citizen_client, enrol

    client = citizen_client(app)
    enrol(client)
    event = [e for e in events(app) if e["action"] == "enrolment_change"][0]
    assert event["details"] == {"field": "enrolment", "reason": "created"}
    assert "Testperson" not in json.dumps(events(app))


def test_role_changes_are_recorded(app):
    from tests.test_auth_recovery import admin_client

    admin = admin_client(app)
    with app.app_context():
        emma_id = make_user(username="emma").id
    admin.post("/auth/admin/roles", json={"user_id": emma_id, "role": "aec_employee"},
               headers=csrf_headers(admin))
    event = events(app)[-1]
    assert event["action"] == "role_granted" and event["target_id"] == emma_id
    assert event["details"] == {"previous_role": "citizen", "new_role": "aec_employee"}

# --- KE13 ---

def auditor_client(app, username="audrey"):
    with app.app_context():
        make_user(username=username, role="auditor")
    client = app.test_client()
    login(client, username, "Correct-Horse-42")
    verify_mfa(app)
    return client


def test_an_auditor_reads_the_trail_newest_first(app):
    three_events(app)
    auditor = auditor_client(app)
    body = auditor.get("/audit/events").get_json()
    assert [e["seq"] for e in body["events"]] == [4, 3, 2, 1]  # 4 is the auditor's own login
    only = auditor.get("/audit/events?action=access_denied").get_json()["events"]
    assert {e["action"] for e in only} == {"access_denied"}
    assert auditor.get("/audit/events?action=<script>").status_code == 400


def test_the_trail_needs_the_auditor_role_and_mfa(app):
    with app.app_context():
        make_user(username="audrey", role="auditor")
        make_user(username="admin1", role="administrator")
    auditor = app.test_client()
    login(auditor, "audrey", "Correct-Horse-42")
    assert auditor.get("/audit/events").status_code == 403  # password only: not enough (R08)
    admin = app.test_client()
    login(admin, "admin1", "Correct-Horse-42")
    verify_mfa(app)
    assert admin.get("/audit/events").status_code == 403  # admins are not auditors (R12)


def test_an_auditor_can_verify_the_trail(app):
    three_events(app)
    auditor = auditor_client(app)
    response = auditor.post("/audit/verify", headers=csrf_headers(auditor))
    assert response.get_json() == {"intact": True, "problems": []}
    as_dba(app, "UPDATE audit_events SET result = 'success' WHERE seq = 2")
    response = auditor.post("/audit/verify", headers=csrf_headers(auditor))
    assert response.get_json()["intact"] is False

# --- KE14 ---

def test_the_audit_page_is_for_auditors_only(app):
    from tests.test_auth_pages import INLINE_SCRIPT

    auditor = auditor_client(app)
    response = auditor.get("/audit")
    body = response.get_data(as_text=True)
    assert response.status_code == 200 and INLINE_SCRIPT.search(body) is None
    assert 'id="verify-button"' in body
    assert 'href="/audit"' in auditor.get("/dashboard").get_data(as_text=True)

    citizen = app.test_client()
    with app.app_context():
        make_user(username="carl")
    login(citizen, "carl", "Correct-Horse-42")
    assert citizen.get("/audit").headers["Location"].endswith("/dashboard")
    assert 'href="/audit"' not in citizen.get("/dashboard").get_data(as_text=True)