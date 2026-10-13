"""R03/R05: staff registration, approval rules and the protected change history."""
from app.models.enrollment_models import Enrolment, EnrolmentHistory
from app.models.user import User
from tests.conftest import csrf_headers
from tests.test_auth_login import make_user
from tests.test_enrollment_access import ENROLMENT, citizen_client, staff_client


def citizen_without_a_login(app, username="citizen1"):
    with app.app_context():
        return make_user(username=username).id


def staff_register(client, user_id, **overrides):
    body = dict(ENROLMENT, user_id=user_id)
    body.update(overrides)
    return client.post("/enrollment/staff/register", json=body, headers=csrf_headers(client))


# --- A14: staff registration ----------------------------------------------------

def test_an_employee_registers_a_citizen_in_their_own_state(app):
    user_id = citizen_without_a_login(app)
    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    response = staff_register(emma, user_id)
    assert response.status_code == 201
    body = response.get_json()["enrolment"]
    # R02: the staff response carries no personal details
    assert set(body) == {"id", "state", "status"}
    with app.app_context():
        row = Enrolment.query.one()
        assert row.status == "pending"
        assert row.registered_by == User.query.filter_by(username="emma.vic").one().id


def test_an_employee_cannot_register_outside_their_states(app):
    user_id = citizen_without_a_login(app)
    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    assert staff_register(emma, user_id, state="NSW").status_code == 403
    with app.app_context():
        assert Enrolment.query.count() == 0


def test_a_citizen_cannot_use_the_staff_endpoint(app):
    user_id = citizen_without_a_login(app)
    alice = citizen_client(app)
    assert staff_register(alice, user_id).status_code == 403

# --- A15: approval rules --------------------------------------------------------

def test_a_delegate_approves_and_the_decision_is_recorded(app):
    user_id = citizen_without_a_login(app)
    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    staff_register(emma, user_id)
    with app.app_context():
        record_id = Enrolment.query.one().id

    delegate = staff_client(app, "dana.vic", "commissioner_delegate", ["VIC"])
    response = delegate.post(f"/enrollment/{record_id}/decision",
                             json={"decision": "approved"}, headers=csrf_headers(delegate))
    assert response.status_code == 200
    with app.app_context():
        row = Enrolment.query.one()
        assert row.status == "approved"
        assert row.approved_by == User.query.filter_by(username="dana.vic").one().id
        assert EnrolmentHistory.query.filter_by(action="status_approved").count() == 1


def test_the_person_who_registered_someone_cannot_approve_them(app):
    """R03 separation of duties: the maker is not the checker."""
    user_id = citizen_without_a_login(app)
    dana = staff_client(app, "dana.vic", "commissioner_delegate", ["VIC"])
    staff_register(dana, user_id)  # a delegate may also register
    with app.app_context():
        record_id = Enrolment.query.one().id
    assert dana.post(f"/enrollment/{record_id}/decision", json={"decision": "approved"},
                     headers=csrf_headers(dana)).status_code == 403
    with app.app_context():
        assert Enrolment.query.one().status == "pending"

    # a different delegate may approve it
    sam = staff_client(app, "sam.vic", "commissioner_delegate", ["VIC"])
    assert sam.post(f"/enrollment/{record_id}/decision", json={"decision": "approved"},
                    headers=csrf_headers(sam)).status_code == 200


def test_an_employee_cannot_approve_at_all(app):
    user_id = citizen_without_a_login(app)
    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    staff_register(emma, user_id)
    with app.app_context():
        record_id = Enrolment.query.one().id
    noah = staff_client(app, "noah.vic", "aec_employee", ["VIC"])
    assert noah.post(f"/enrollment/{record_id}/decision", json={"decision": "approved"},
                     headers=csrf_headers(noah)).status_code == 403


def test_an_approved_record_cannot_be_moved_again(app):
    """R03: 'Unauthorised workflow transitions are rejected.'"""
    user_id = citizen_without_a_login(app)
    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    staff_register(emma, user_id)
    with app.app_context():
        record_id = Enrolment.query.one().id
    dana = staff_client(app, "dana.vic", "commissioner_delegate", ["VIC"])
    assert dana.post(f"/enrollment/{record_id}/decision", json={"decision": "approved"},
                     headers=csrf_headers(dana)).status_code == 200
    for decision in ("rejected", "approved"):
        assert dana.post(f"/enrollment/{record_id}/decision", json={"decision": decision},
                         headers=csrf_headers(dana)).status_code == 403
    assert dana.post(f"/enrollment/{record_id}/decision", json={"decision": "deleted"},
                     headers=csrf_headers(dana)).status_code == 400

# --- A16: the change history ----------------------------------------------------

def test_the_history_hides_values_from_roles_that_may_not_see_them(app):
    alice = citizen_client(app)
    alice.post("/enrollment/me", json=ENROLMENT, headers=csrf_headers(alice))
    alice.patch("/enrollment/me/address", headers=csrf_headers(alice),
                json={"address_line": "99 New Road", "suburb": "Fitzroy",
                      "postcode": "3065", "state": "VIC"})
    with app.app_context():
        record_id = Enrolment.query.one().id

    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    rows = emma.get(f"/enrollment/{record_id}/history").get_json()["history"]
    assert rows and all("old_value" not in row for row in rows)
    assert all({"actor_user_id", "action", "field", "created_at"} <= set(row) for row in rows)

    dana = staff_client(app, "dana.vic", "commissioner_delegate", ["VIC"])
    rows = dana.get(f"/enrollment/{record_id}/history").get_json()["history"]
    postcode = next(row for row in rows if row["field"] == "postcode")
    assert (postcode["old_value"], postcode["new_value"]) == ("3053", "3065")


def test_history_values_are_encrypted_in_the_database(app):
    alice = citizen_client(app)
    alice.post("/enrollment/me", json=ENROLMENT, headers=csrf_headers(alice))
    alice.patch("/enrollment/me/address", headers=csrf_headers(alice),
                json={"address_line": "99 New Road", "suburb": "Fitzroy",
                      "postcode": "3065", "state": "VIC"})
    with app.app_context():
        row = EnrolmentHistory.query.filter_by(field="address_line").one()
        assert "Example Street" not in (row.old_value_enc or "")
        assert "New Road" not in (row.new_value_enc or "")
        assert row.values() == ("12 Example Street", "99 New Road")