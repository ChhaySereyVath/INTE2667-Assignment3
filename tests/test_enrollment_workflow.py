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