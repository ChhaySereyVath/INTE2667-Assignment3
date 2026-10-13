"""R03/R05/R11: enrolment workflows, record-level access and change history."""
from app import db
from app.models.auth_models import StaffAssignment
from app.models.enrollment_models import Enrolment, EnrolmentHistory
from app.models.user import User
from tests.conftest import csrf_headers, verify_mfa
from tests.test_auth_login import login, make_user

ENROLMENT = {
    "given_name": "Alex",
    "family_name": "Testperson",
    "date_of_birth": "1990-04-12",
    "address_line": "12 Example Street",
    "suburb": "Carlton",
    "postcode": "3053",
    "state": "VIC",
}


def staff_client(app, username, role, states, password="Correct-Horse-42"):
    """Sign in a staff member assigned to the given states."""
    with app.app_context():
        admin = User.query.filter_by(role="administrator").first() or make_user(
            username="admin-seed", role="administrator")
        person = make_user(username=username, role=role)
        for state in states:
            db.session.add(StaffAssignment(user_id=person.id, state=state, granted_by=admin.id))
        db.session.commit()
    client = app.test_client()
    login(client, username, password)
    verify_mfa(app)
    return client


def citizen_client(app, username="alice"):
    with app.app_context():
        make_user(username=username)
    client = app.test_client()
    login(client, username, "Correct-Horse-42")
    return client


def enrol(client, **overrides):
    body = dict(ENROLMENT)
    body.update(overrides)
    return client.post("/enrollment/me", json=body, headers=csrf_headers(client))


# --- A11: self-service ----------------------------------------------------------

def test_a_citizen_enrols_and_reads_their_own_record(app):
    client = citizen_client(app)
    assert client.get("/enrollment/me").status_code == 404  # nothing yet
    response = enrol(client)
    assert response.status_code == 201
    assert response.get_json()["enrolment"]["status"] == "pending"
    read = client.get("/enrollment/me")
    assert read.status_code == 200
    assert read.get_json()["enrolment"]["family_name"] == "Testperson"


def test_personal_details_are_encrypted_in_the_database(app):
    client = citizen_client(app)
    enrol(client)
    with app.app_context():
        row = Enrolment.query.one()
        assert "Testperson" not in row.family_name_enc
        assert "12 Example Street" not in row.address_line_enc
        assert row.get_field("family_name") == "Testperson"
        assert row.state == "VIC"  # kept readable on purpose, for staff scoping


def test_one_person_cannot_enrol_twice(app):
    client = citizen_client(app)
    assert enrol(client).status_code == 201
    assert enrol(client).status_code == 409
    # the same person under a second account is also refused
    other = citizen_client(app, username="alias")
    assert enrol(other).status_code == 409
    with app.app_context():
        assert Enrolment.query.count() == 1

# --- A12: address update --------------------------------------------------------

def test_a_citizen_updates_their_own_address_and_the_change_is_recorded(app):
    client = citizen_client(app)
    enrol(client)
    response = client.patch("/enrollment/me/address", headers=csrf_headers(client),
                            json={"address_line": "99 New Road", "suburb": "Fitzroy",
                                  "postcode": "3065", "state": "VIC"})
    assert response.status_code == 200
    assert response.get_json()["enrolment"]["address_line"] == "99 New Road"
    with app.app_context():
        rows = EnrolmentHistory.query.filter_by(action="address_update").all()
        changed = {row.field for row in rows}
        assert changed == {"address_line", "suburb", "postcode"}  # state did not change
        old, new = next(r for r in rows if r.field == "postcode").values()
        assert (old, new) == ("3053", "3065")

# --- A13: record-level access control -------------------------------------------

def test_changing_the_record_id_does_not_expose_another_citizen(app):
    alice = citizen_client(app)
    enrol(alice)
    with app.app_context():
        record_id = Enrolment.query.one().id

    bob = citizen_client(app, username="bob")
    # a citizen has no staff:read permission at all
    assert bob.get(f"/enrollment/{record_id}").status_code == 403


def test_staff_see_only_the_states_they_are_assigned_to(app):
    alice = citizen_client(app)
    enrol(alice)  # a VIC record
    with app.app_context():
        record_id = Enrolment.query.one().id

    vic_staff = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    nsw_staff = staff_client(app, "noah.nsw", "aec_employee", ["NSW"])
    assert vic_staff.get(f"/enrollment/{record_id}").status_code == 200
    # R11: a record outside their scope looks exactly like one that does not exist
    assert nsw_staff.get(f"/enrollment/{record_id}").status_code == 404
    assert nsw_staff.get("/enrollment/00000000-0000-0000-0000-000000000000").status_code == 404


def test_an_administrator_cannot_read_enrolment_records(app):
    alice = citizen_client(app)
    enrol(alice)
    with app.app_context():
        record_id = Enrolment.query.one().id
    admin = staff_client(app, "admin1", "administrator", ["VIC"])
    # R12 least privilege: managing accounts does not include reading enrolments
    assert admin.get(f"/enrollment/{record_id}").status_code == 403