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

# --- A25 ---

def test_purge_removes_only_history_past_the_retention_period(app):
    from datetime import datetime

    from app import db
    from app.models.enrollment_models import Enrolment, EnrolmentHistory
    from app.models.user import User
    from app.security.enrollment_security import record_change

    vic_record(app)  # writes one current history row
    with app.app_context():
        row, alice = Enrolment.query.one(), User.query.filter_by(username="alice").one()
        old = record_change(row, alice, "address_update", "postcode", "3000", "3053")
        old.created_at = datetime(2019, 1, 1)  # set before the insert, so no UPDATE happens
        db.session.commit()
    assert history_rows(app) == 2

    result = app.test_cli_runner().invoke(args=["purge-history"])
    assert "Removed 1 history rows" in result.output
    with app.app_context():
        remaining = EnrolmentHistory.query.one()
        assert remaining.field == "enrolment"  # the recent row is still there

# --- A26 ---

def test_the_queue_lists_only_pending_records_in_your_states(app):
    from tests.test_enrollment_workflow import citizen_without_a_login, staff_register

    vic_id = citizen_without_a_login(app, "citizen1")
    nsw_id = citizen_without_a_login(app, "citizen2")
    vic_staff = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    nsw_staff = staff_client(app, "noah.nsw", "aec_employee", ["NSW"])
    staff_register(vic_staff, vic_id)
    staff_register(nsw_staff, nsw_id, given_name="Sam", family_name="Other", state="NSW")

    queue = vic_staff.get("/enrollment/pending").get_json()["enrolments"]
    assert [item["state"] for item in queue] == ["VIC"]
    # ids, states and dates only: nobody's details are in the list (R02)
    assert set(queue[0]) == {"id", "state", "status", "received_at", "registered_by_you"}
    assert queue[0]["registered_by_you"] is True


def test_decided_records_leave_the_queue(app):
    from tests.test_enrollment_workflow import citizen_without_a_login, staff_register

    user_id = citizen_without_a_login(app)
    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    staff_register(emma, user_id)
    record_id = emma.get("/enrollment/pending").get_json()["enrolments"][0]["id"]
    dana = staff_client(app, "dana.vic", "commissioner_delegate", ["VIC"])
    assert dana.get("/enrollment/pending").get_json()["enrolments"][0]["registered_by_you"] is False
    dana.post(f"/enrollment/{record_id}/decision", json={"decision": "approved"},
              headers=csrf_headers(dana))
    assert dana.get("/enrollment/pending").get_json()["enrolments"] == []


def test_citizens_cannot_see_the_queue(app):
    alice = citizen_client(app)
    assert alice.get("/enrollment/pending").status_code == 403

# --- A27 ---

def test_staff_get_the_queue_page_and_citizens_do_not(app):
    from tests.test_auth_pages import INLINE_SCRIPT

    alice = citizen_client(app)
    assert alice.get("/staff/enrolments").headers["Location"].endswith("/dashboard")
    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    response = emma.get("/staff/enrolments")
    body = response.get_data(as_text=True)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    assert INLINE_SCRIPT.search(body) is None
    assert 'id="approve-button"' not in body  # employees register; only delegates decide
    assert 'href="/staff/enrolments"' in emma.get("/dashboard").get_data(as_text=True)


def test_delegates_get_the_decision_buttons(app):
    dana = staff_client(app, "dana.vic", "commissioner_delegate", ["VIC"])
    assert 'id="approve-button"' in dana.get("/staff/enrolments").get_data(as_text=True)

# --- A28 ---

def test_https_responses_carry_hsts_and_plain_http_does_not(client):
    secure = client.get("/", base_url="https://localhost")
    assert secure.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    # HSTS is only meaningful over HTTPS; browsers ignore it on plain HTTP
    assert "Strict-Transport-Security" not in client.get("/", base_url="http://localhost").headers


def test_make_cert_writes_a_localhost_certificate_and_a_private_key(app, tmp_path):
    import os
    import stat

    from cryptography import x509

    from app.security.tls import make_dev_certificate

    with app.app_context():
        cert_path, key_path = make_dev_certificate(tmp_path)
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in names.get_values_for_type(x509.DNSName)
    assert b"PRIVATE KEY" in key_path.read_bytes()
    if os.name == "posix":  # Windows has no owner-only mode bits to check
        assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600


def test_session_cookies_are_never_sent_over_plain_http(app, client):
    """R01: the login cookie is marked Secure, so the browser keeps it off HTTP."""
    from tests.test_auth_login import login, make_user

    with app.app_context():
        make_user()
    cookies = login(client, "alice", "Correct-Horse-42").headers.getlist("Set-Cookie")
    assert all("Secure" in cookie for cookie in cookies)

