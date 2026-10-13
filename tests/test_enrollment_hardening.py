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