"""R12/R21: only an administrator manages accounts, never their own role."""
from app import db
from app.models.auth_models import Notification, StaffAssignment, UserSession, user_states
from app.models.user import User
from tests.conftest import csrf_headers, verify_mfa
from tests.test_auth_login import login, make_user

NEW_STAFF = {
    "username": "emma.staff",
    "email": "emma@aec.example.gov.au",
    "role": "aec_employee",
    "states": ["VIC"],
    "temporary_password": "Correct-Horse-42",
}


def sign_in_admin(app, client):
    with app.app_context():
        make_user(username="admin1", role="administrator")
    login(client, "admin1", "Correct-Horse-42")
    verify_mfa(app)


def test_an_administrator_creates_a_staff_account(app, client):
    sign_in_admin(app, client)
    response = client.post("/auth/admin/staff", json=NEW_STAFF, headers=csrf_headers(client))
    assert response.status_code == 201
    with app.app_context():
        emma = User.query.filter_by(username="emma.staff").one()
        assert emma.role == "aec_employee"
        assert emma.status == "pending_activation"  # they activate it themselves
        assert user_states(emma) == ("VIC",)
        assert Notification.query.filter_by(user_id=emma.id, template="activation").count() == 1


def test_a_citizen_cannot_create_staff(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    response = client.post("/auth/admin/staff", json=NEW_STAFF, headers=csrf_headers(client))
    assert response.status_code == 403
    assert response.get_json() == {"error": "Access denied"}


def test_an_employee_cannot_create_staff_either(app, client):
    with app.app_context():
        make_user(username="emma", role="aec_employee")
    login(client, "emma", "Correct-Horse-42")
    verify_mfa(app)
    assert client.post("/auth/admin/staff", json=NEW_STAFF,
                       headers=csrf_headers(client)).status_code == 403


def test_an_administrator_without_mfa_is_refused(app, client):
    with app.app_context():
        make_user(username="admin1", role="administrator")
    login(client, "admin1", "Correct-Horse-42")  # password only, no verify_mfa
    assert client.post("/auth/admin/staff", json=NEW_STAFF,
                       headers=csrf_headers(client)).status_code == 403


def test_bad_staff_details_are_rejected(app, client):
    sign_in_admin(app, client)
    for change in ({"role": "citizen"}, {"role": "wizard"}, {"states": []},
                   {"states": ["XYZ"]}, {"email": "nope"}, {"temporary_password": "administrator"}):
        body = {**NEW_STAFF, **change}
        assert client.post("/auth/admin/staff", json=body,
                           headers=csrf_headers(client)).status_code == 400
    with app.app_context():
        assert User.query.filter_by(username="emma.staff").first() is None


def test_granting_a_role_ends_the_other_person_s_sessions(app, client):
    with app.app_context():
        emma = make_user(username="emma", role="citizen")
        emma_id = emma.id
    # Emma signs in as a citizen
    emma_client = app.test_client()
    login(emma_client, "emma", "Correct-Horse-42")
    assert emma_client.get("/auth/me").status_code == 200

    sign_in_admin(app, client)
    response = client.post("/auth/admin/roles", json={"user_id": emma_id, "role": "aec_employee"},
                           headers=csrf_headers(client))
    assert response.status_code == 200
    assert response.get_json()["user"]["role"] == "aec_employee"

    # R21: her old token carried the old privileges, so it must stop working
    assert emma_client.get("/auth/me").status_code == 401
    with app.app_context():
        row = UserSession.query.filter_by(user_id=emma_id).one()
        assert row.revoke_reason == "role_changed"
        assert Notification.query.filter_by(user_id=emma_id, template="role_changed").count() == 1


def test_an_administrator_cannot_change_their_own_role(app, client):
    sign_in_admin(app, client)
    with app.app_context():
        admin_id = User.query.filter_by(username="admin1").one().id
    response = client.post("/auth/admin/roles", json={"user_id": admin_id, "role": "administrator"},
                           headers=csrf_headers(client))
    assert response.status_code == 403


def test_an_unknown_user_id_is_a_plain_not_found(app, client):
    import uuid

    sign_in_admin(app, client)
    response = client.post("/auth/admin/roles",
                           json={"user_id": str(uuid.uuid4()), "role": "citizen"},
                           headers=csrf_headers(client))
    assert response.status_code == 404
    assert response.get_json() == {"error": "Not found"}