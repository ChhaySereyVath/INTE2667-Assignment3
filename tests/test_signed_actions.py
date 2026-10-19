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