"""R15: privileged actions are attributable, signed and independently verifiable (Keane)."""
from datetime import timedelta

from app import db
from app.models.audit_models import AuditEvent, SignedAction
from app.models.election_models import Candidate
from app.security.shared_security import clock, utcnow
from tests.conftest import csrf_headers
from tests.test_elections import contest_of, delegate_client, make_election


def add(client, contest_id, name="Morgan Ellis", party="Independent"):
    return client.post(f"/contests/{contest_id}/candidates", headers=csrf_headers(client),
                       json={"name": name, "party": party})


def signed(app):
    with app.app_context():
        return [row.to_dict() for row in SignedAction.query.order_by(SignedAction.signed_at)]


# --- KE15 ---

def add_signing_route(app):
    """A throwaway route that signs one action, so KE15 and KE16 can be tested before
    the candidate endpoints exist (the same trick as Ken's permission tests)."""
    from flask import jsonify

    from app.security.shared_security import permission_required
    from app.security.signed_actions import record_signed_action

    @app.route("/t/sign", methods=["POST"])
    @permission_required("candidate:manage")
    def t_sign(current_user):
        record_signed_action(current_user, "candidate_create", "candidate", "candidate-1",
                             {"name": "Morgan Ellis"}, "success")
        db.session.commit()
        return jsonify({"ok": True})


def test_a_signed_record_names_the_verified_person_and_verifies(app):
    from app.models.auth_models import UserSession
    from app.models.user import User
    from app.security.signed_actions import verify_actions

    add_signing_route(app)
    dana = delegate_client(app)
    assert dana.post("/t/sign", headers=csrf_headers(dana)).status_code == 200
    (record,) = signed(app)
    with app.app_context():
        dana_user = User.query.filter_by(username="dana.vic").one()
        session = UserSession.query.filter_by(user_id=dana_user.id).one()
        assert verify_actions() == []
        assert AuditEvent.query.filter_by(action="candidate_change").count() == 1
    assert (record["actor_id"], record["actor_role"], record["session_id"]) == (
        dana_user.id, "commissioner_delegate", session.id)
    assert (record["action"], record["outcome"], record["payload"]) == (
        "candidate_create", "success", {"name": "Morgan Ellis"})


def test_signed_records_cannot_be_changed_in_the_database(app):
    import pytest
    from sqlalchemy.exc import IntegrityError

    add_signing_route(app)
    dana = delegate_client(app)
    dana.post("/t/sign", headers=csrf_headers(dana))
    with app.app_context():
        with pytest.raises(IntegrityError), db.engine.begin() as connection:
            connection.exec_driver_sql("UPDATE signed_actions SET outcome = 'denied'")

# --- KE16 ---

def add_fresh_mfa_route(app):
    from flask import jsonify

    from app.security.shared_security import permission_required
    from app.security.signed_actions import recent_mfa_required

    @app.route("/t/fresh", methods=["POST"])
    @permission_required("candidate:manage")
    @recent_mfa_required
    def t_fresh(current_user):
        return jsonify({"ok": True})


def test_signing_needs_a_recent_security_key_check(app):
    add_fresh_mfa_route(app)
    dana = delegate_client(app)  # passed MFA just now
    assert dana.post("/t/fresh", headers=csrf_headers(dana)).status_code == 200
    clock.freeze(utcnow() + timedelta(minutes=11))
    try:
        stale = dana.post("/t/fresh", headers=csrf_headers(dana))
    finally:
        clock.unfreeze()
    # the session is still alive (inside the 15-minute idle limit), but the MFA is 11 minutes old
    assert stale.status_code == 401 and stale.get_json()["reauthenticate"] is True


def test_a_password_only_session_cannot_sign_anything(app):
    from tests.test_auth_login import login, make_user

    add_fresh_mfa_route(app)
    with app.app_context():
        make_user(username="dana2", role="commissioner_delegate")
    client = app.test_client()
    login(client, "dana2", "Correct-Horse-42")  # no MFA
    assert client.post("/t/fresh", headers=csrf_headers(client)).status_code == 403

# --- KE17 ---

def test_a_delegate_adds_candidates_only_in_their_states(app):
    election_id = make_election(app)
    dana = delegate_client(app)  # VIC only
    assert add(dana, contest_of(app, election_id, "house", "VIC")).status_code == 201
    refused = add(dana, contest_of(app, election_id, "house", "NSW"))
    assert refused.status_code == 404
    outcomes = [(r["outcome"], r["payload"].get("reason")) for r in signed(app)]
    assert outcomes == [("success", None), ("denied", "outside your states")]  # R15: refusals are signed too


def test_candidates_cannot_change_once_polling_opens(app):
    election_id = make_election(app, status="polling_open")
    dana = delegate_client(app)
    response = add(dana, contest_of(app, election_id, "house"))
    assert response.status_code == 409
    assert signed(app)[-1]["payload"]["reason"] == "nominations closed"


def test_candidate_details_are_validated(app):
    election_id = make_election(app)
    dana = delegate_client(app)
    contest_id = contest_of(app, election_id, "house")
    for name, party in (("<script>alert(1)</script>", "Independent"), ("Morgan", "x" * 61),
                        ("Robert'); DROP TABLE candidates;--", "Independent")):
        assert add(dana, contest_id, name, party).status_code == 400
    assert signed(app) == []

# --- KE18 ---

def test_edits_and_withdrawals_are_signed_with_before_and_after(app):
    election_id = make_election(app)
    dana = delegate_client(app)
    candidate_id = add(dana, contest_of(app, election_id, "house")).get_json()["candidate"]["id"]
    edit = dana.patch(f"/candidates/{candidate_id}", headers=csrf_headers(dana),
                      json={"name": "Morgan Ellis-Shaw", "party": "Civic Union"})
    assert edit.status_code == 200
    assert dana.post(f"/candidates/{candidate_id}/withdraw", headers=csrf_headers(dana)).status_code == 200
    create, update, withdraw = signed(app)
    assert update["payload"] == {"before": {"name": "Morgan Ellis", "party": "Independent"},
                                 "after": {"name": "Morgan Ellis-Shaw", "party": "Civic Union"}}
    assert withdraw["action"] == "candidate_withdraw"
    with app.app_context():
        assert db.session.get(Candidate, candidate_id).withdrawn is True