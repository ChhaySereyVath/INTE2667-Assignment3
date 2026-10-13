"""R11/R05/R01: logging of refused access, protected history, and data at rest."""
import logging

from tests.conftest import csrf_headers
from tests.test_auth_login import make_user
from tests.test_enrollment_access import ENROLMENT, citizen_client, enrol, staff_client


def vic_record(app):
    from app.models.enrollment_models import Enrolment

    alice = citizen_client(app)
    enrol(alice)
    with app.app_context():
        return Enrolment.query.one().id


# --- A22 ---

def test_a_refused_record_access_is_logged_without_personal_details(app, caplog):
    record_id = vic_record(app)
    nsw = staff_client(app, "noah.nsw", "aec_employee", ["NSW"])
    caplog.set_level(logging.WARNING, logger="evp.security")
    assert nsw.get(f"/enrollment/{record_id}").status_code == 404

    lines = [r.getMessage() for r in caplog.records if r.name == "evp.security"]
    assert len(lines) == 1
    assert "access_denied" in lines[0] and f"target=enrolment:{record_id}" in lines[0]
    assert "action=read" in lines[0] and "result=denied" in lines[0]
    for detail in ("Testperson", "Example Street", "1990-04-12", "3053"):
        assert detail not in lines[0]  # R02: ids only


def test_an_allowed_access_writes_no_denial(app, caplog):
    record_id = vic_record(app)
    vic = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    caplog.set_level(logging.WARNING, logger="evp.security")
    assert vic.get(f"/enrollment/{record_id}").status_code == 200
    assert not [r for r in caplog.records if r.name == "evp.security"]


def test_a_crafted_record_id_cannot_forge_a_log_line(app, caplog):
    """Log injection: a newline in the id must not start a fake second entry."""
    nsw = staff_client(app, "noah.nsw", "aec_employee", ["NSW"])
    caplog.set_level(logging.WARNING, logger="evp.security")
    nsw.get("/enrollment/x%0Aaccess_granted%20actor=admin")
    line = [r.getMessage() for r in caplog.records if r.name == "evp.security"][0]
    assert "\n" not in line
    assert "target=enrolment:invalid-id" in line


def test_registering_outside_your_states_is_logged(app, caplog):
    with app.app_context():
        user_id = make_user(username="citizen1").id
    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    caplog.set_level(logging.WARNING, logger="evp.security")
    emma.post("/enrollment/staff/register", json=dict(ENROLMENT, state="NSW", user_id=user_id),
              headers=csrf_headers(emma))
    assert any("action=register" in r.getMessage() for r in caplog.records if r.name == "evp.security")

# --- A23 ---

def history_rows(app):
    from app.models.enrollment_models import EnrolmentHistory

    with app.app_context():
        return EnrolmentHistory.query.count()


def raw_sql(app, statement):
    """Run SQL straight at the database, the way a stray script or the sqlite3 tool would."""
    from sqlalchemy import text

    from app import db

    with app.app_context():
        try:
            db.session.execute(text(statement))
            db.session.commit()
            return "allowed"
        except Exception as error:  # noqa: BLE001
            db.session.rollback()
            return str(error.orig) if hasattr(error, "orig") else str(error)


def test_the_database_refuses_to_edit_history(app):
    vic_record(app)
    assert history_rows(app) == 1
    result = raw_sql(app, "UPDATE enrolment_history SET actor_user_id = 'someone-else'")
    assert "append-only" in result


def test_the_database_refuses_to_delete_recent_history(app):
    vic_record(app)
    result = raw_sql(app, "DELETE FROM enrolment_history")
    assert "retention period" in result
    assert history_rows(app) == 1


def test_there_is_no_endpoint_that_changes_history(app):
    record_id = vic_record(app)
    dana = staff_client(app, "dana.vic", "commissioner_delegate", ["VIC"])
    for method in ("put", "patch", "delete", "post"):
        response = getattr(dana, method)(f"/enrollment/{record_id}/history", headers=csrf_headers(dana))
        assert response.status_code == 405

# --- A24 ---

def test_history_can_only_describe_enrolment_fields(app):
    import pytest

    from app.models.enrollment_models import Enrolment
    from app.models.user import User
    from app.security.enrollment_security import record_change

    vic_record(app)
    with app.app_context():
        row, alice = Enrolment.query.one(), User.query.filter_by(username="alice").one()
        for field in ("ballot_choice", "vote", "preferences", "password"):
            with pytest.raises(ValueError):
                record_change(row, alice, "address_update", field, "a", "b")


def test_the_history_table_has_no_voting_columns(app):
    from app.models.enrollment_models import EnrolmentHistory

    columns = {column.name for column in EnrolmentHistory.__table__.columns}
    assert not {name for name in columns if "vote" in name or "ballot" in name}