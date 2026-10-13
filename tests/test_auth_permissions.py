"""R12: roles, least privilege and deny by default, checked on the server."""
from flask import jsonify

from app.security.shared_security import (ROLE_PERMISSIONS, has_permission, permission_required,
                                          privileged_required)
from tests.conftest import csrf_headers, verify_mfa
from tests.test_auth_login import login, make_user


def add_routes(app):
    """Three throwaway routes that only check permissions, so the tests stay focused."""

    @app.route("/t/self-read")
    @permission_required("enrolment:self:read")
    def t_self_read(current_user):
        return jsonify({"ok": current_user.username})

    @app.route("/t/staff-register", methods=["POST"])
    @permission_required("enrolment:staff:register")
    def t_staff_register(current_user):
        return jsonify({"ok": current_user.username})

    @app.route("/t/any-staff")
    @privileged_required
    def t_any_staff(current_user):
        return jsonify({"ok": current_user.username})


# --- K23: the permission matrix ---

def test_every_role_is_listed_and_nothing_is_shared_by_accident():
    assert set(ROLE_PERMISSIONS) == {
        "citizen", "aec_employee", "commissioner_delegate", "administrator", "auditor",
    }
    # R12: an administrator manages accounts and cannot read enrolment records
    assert "enrolment:staff:read" not in ROLE_PERMISSIONS["administrator"]
    # and an employee cannot create accounts or grant roles
    assert "admin:role:grant" not in ROLE_PERMISSIONS["aec_employee"]


def test_unknown_role_has_no_permissions(app):
    with app.app_context():
        stranger = make_user(username="stranger", role="not-a-real-role")
        assert not has_permission(stranger, "enrolment:self:read")
        assert not has_permission(stranger, "admin:role:grant")



# --- K24: permission_required ---

def test_citizen_can_use_its_own_permission(app, client):
    add_routes(app)
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    assert client.get("/t/self-read").status_code == 200


def test_citizen_is_denied_a_staff_permission(app, client):
    add_routes(app)
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    response = client.post("/t/staff-register", headers=csrf_headers(client))
    assert response.status_code == 403
    assert response.get_json() == {"error": "Access denied"}


def test_permission_routes_still_need_a_login(app, client):
    add_routes(app)
    assert client.get("/t/self-read").status_code == 401



# --- K25: staff state assignments ---

def test_staff_assignments_scope_a_role_to_states(app):
    from app import db
    from app.models.auth_models import StaffAssignment, user_states

    with app.app_context():
        admin = make_user(username="admin1", role="administrator")
        emma = make_user(username="emma", role="aec_employee")
        # a role alone gives no records to work on until a state is assigned (R12)
        assert user_states(emma) == ()
        db.session.add(StaffAssignment(user_id=emma.id, state="VIC", granted_by=admin.id))
        db.session.commit()
        assert user_states(emma) == ("VIC",)


def test_the_same_state_cannot_be_assigned_twice(app):
    import pytest
    from sqlalchemy.exc import IntegrityError

    from app import db
    from app.models.auth_models import StaffAssignment

    with app.app_context():
        admin = make_user(username="admin1", role="administrator")
        emma = make_user(username="emma", role="aec_employee")
        db.session.add(StaffAssignment(user_id=emma.id, state="VIC", granted_by=admin.id))
        db.session.commit()
        db.session.add(StaffAssignment(user_id=emma.id, state="VIC", granted_by=admin.id))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()



# --- K26: privileged_required and the MFA gate ---

def test_staff_needs_the_permission_and_mfa(app, client):
    add_routes(app)
    with app.app_context():
        make_user(username="emma", role="aec_employee")
    login(client, "emma", "Correct-Horse-42")
    # R08: password only is not enough for a privileged action
    assert client.post("/t/staff-register", headers=csrf_headers(client)).status_code == 403
    verify_mfa(app)
    assert client.post("/t/staff-register", headers=csrf_headers(client)).status_code == 200


def test_privileged_required_blocks_citizens_entirely(app, client):
    add_routes(app)
    with app.app_context():
        make_user()
        make_user(username="emma", role="aec_employee")
    login(client, "alice", "Correct-Horse-42")
    assert client.get("/t/any-staff").status_code == 403
    client.post("/auth/logout", headers=csrf_headers(client))
    login(client, "emma", "Correct-Horse-42")
    verify_mfa(app)
    assert client.get("/t/any-staff").status_code == 200