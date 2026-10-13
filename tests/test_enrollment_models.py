"""R01/R03/R05: the enrolment row and the rules that guard it, tested on their own."""
import pytest

from app import db
from app.models.auth_models import StaffAssignment
from app.models.enrollment_models import ALLOWED_TRANSITIONS, Enrolment, EnrolmentHistory
from app.security.enrollment_security import can_access, identity_key, record_change
from tests.test_auth_login import make_user


def new_enrolment(owner, state="VIC", family_name="Testperson"):
    row = Enrolment(user_id=owner.id, state=state, status="pending",
                    identity_bidx=identity_key("Alex", family_name, "1990-04-12"),
                    given_name_enc="", family_name_enc="", date_of_birth_enc="",
                    address_line_enc="", suburb_enc="", postcode_enc="")
    db.session.add(row)
    db.session.flush()
    row.set_field("given_name", "Alex")
    row.set_field("family_name", family_name)
    row.set_field("date_of_birth", "1990-04-12")
    row.set_field("address_line", "12 Example Street")
    row.set_field("suburb", "Carlton")
    row.set_field("postcode", "3053")
    db.session.commit()
    return row


# --- A09: the model -------------------------------------------------------------

def test_fields_go_in_encrypted_and_come_back_out_readable(app):
    with app.app_context():
        row = new_enrolment(make_user())
        assert "Testperson" not in row.family_name_enc
        assert row.family_name_enc.startswith("v1:")
        assert row.get_field("family_name") == "Testperson"
        assert row.to_dict()["suburb"] == "Carlton"
        # R02: the staff summary carries no personal details
        assert set(row.summary()) == {"id", "state", "status"}


def test_a_ciphertext_moved_to_another_row_will_not_decrypt(app):
    with app.app_context():
        alice = new_enrolment(make_user(username="alice"))
        bob = new_enrolment(make_user(username="bob"), family_name="Other")
        bob.family_name_enc = alice.family_name_enc  # steal Alice's encrypted name
        db.session.commit()
        with pytest.raises(ValueError):
            bob.get_field("family_name")


def test_only_the_listed_status_moves_are_possible():
    assert ALLOWED_TRANSITIONS["pending"] == ("approved", "rejected")
    assert ALLOWED_TRANSITIONS["approved"] == ()
    assert ALLOWED_TRANSITIONS["rejected"] == ()

# --- A10: the access rule and the history writer --------------------------------

def test_can_access_decides_owner_staff_and_everyone_else(app):
    with app.app_context():
        alice = make_user(username="alice")
        admin = make_user(username="admin1", role="administrator")
        emma = make_user(username="emma", role="aec_employee")
        nick = make_user(username="nick", role="aec_employee")
        row = new_enrolment(alice, state="VIC")
        db.session.add(StaffAssignment(user_id=emma.id, state="VIC", granted_by=admin.id))
        db.session.add(StaffAssignment(user_id=nick.id, state="NSW", granted_by=admin.id))
        db.session.commit()

        assert can_access(alice, "read", row) is True       # the owner
        assert can_access(emma, "read", row) is True        # staff in VIC
        assert can_access(nick, "read", row) is False       # staff in the wrong state
        assert can_access(admin, "read", row) is False      # no enrolment permission at all
        assert can_access(alice, "approve", row) is False   # citizens never approve
        assert can_access(emma, "read", None) is False      # a record that does not exist


def test_record_change_stores_both_values_encrypted(app):
    with app.app_context():
        alice = make_user()
        row = new_enrolment(alice)
        record_change(row, alice, "address_update", "postcode", "3053", "3065")
        db.session.commit()
        history = EnrolmentHistory.query.one()
        assert history.actor_user_id == alice.id
        assert "3053" not in (history.old_value_enc or "")
        assert history.values() == ("3053", "3065")

# --- A19: identity evidence for Ken's recovery ------------------------------------

def test_verify_enrolment_details_needs_both_to_match(app):
    from app.security.enrollment_security import verify_enrolment_details

    with app.app_context():
        alice = make_user()
        new_enrolment(alice)  # born 1990-04-12, postcode 3053
        assert verify_enrolment_details(alice, "1990-04-12", "3053") is True
        assert verify_enrolment_details(alice, " 1990-04-12 ", "3053 ") is True  # spaces ignored
        assert verify_enrolment_details(alice, "1990-04-13", "3053") is False
        assert verify_enrolment_details(alice, "1990-04-12", "3000") is False
        assert verify_enrolment_details(alice, None, "3053") is False


def test_verify_enrolment_details_is_false_without_an_enrolment(app):
    from app.security.enrollment_security import verify_enrolment_details

    with app.app_context():
        nobody = make_user(username="nobody")
        assert verify_enrolment_details(nobody, "1990-04-12", "3053") is False