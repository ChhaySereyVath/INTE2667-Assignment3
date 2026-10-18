"""R16 eligibility, R17 one vote per contest, R18 ballot secrecy (Yufei)."""
import json
import uuid
from datetime import datetime

from app import db
from app.models.election_models import Election
from app.models.enrollment_models import Enrolment
from app.models.voting_models import VoteEntitlement
from app.security.election_security import change_election_status
from app.security.enrollment_security import identity_key
from app.security.shared_security import clock
from tests.conftest import csrf_headers
from tests.test_auth_login import login, make_user
from tests.test_elections import candidate_ids, contest_of, make_election

DURING_POLLING = datetime(2026, 5, 2, 12, 0, 0)


def approved_voter(app, username="alice", state="VIC", date_of_birth="1990-04-12"):
    """A citizen with an APPROVED enrolment (Austin's model), signed in. Returns the client."""
    with app.app_context():
        user = make_user(username=username)
        enrolment = Enrolment(id=str(uuid.uuid4()), user_id=user.id, state=state, status="approved",
                              identity_bidx=identity_key(username, "Voter", date_of_birth))
        for field, value in (("given_name", username), ("family_name", "Voter"),
                             ("date_of_birth", date_of_birth), ("address_line", "1 Test Street"),
                             ("suburb", "Carlton"), ("postcode", "3053")):
            enrolment.set_field(field, value)
        db.session.add(enrolment)
        db.session.commit()
    client = app.test_client()
    login(client, username, "Correct-Horse-42")
    return client


def open_polling(app, election_id):
    with app.app_context():
        election = db.session.get(Election, election_id)
        delegate = make_user(username="opener", role="commissioner_delegate")
        assert change_election_status(election, delegate, "polling_open")
        db.session.commit()


def polling_election(app, *voters):
    """Voters enrolled first, then polling opens (the roll closes), clock in polling hours."""
    election_id = make_election(app)
    clients = [approved_voter(app, name) for name in voters]
    open_polling(app, election_id)
    clock.freeze(DURING_POLLING)
    return election_id, clients


def check(client, election_id, contest_type="house", **extra):
    return client.post("/voting/eligibility", headers=csrf_headers(client),
                       json=dict(election_id=election_id, contest_type=contest_type, **extra))


def vote(client, app, election_id, contest_type="house", key=None, preferences=None):
    contest_id = contest_of(app, election_id, contest_type)
    headers = dict(csrf_headers(client), **{"Idempotency-Key": key or str(uuid.uuid4())})
    return client.post("/voting/ballots", headers=headers, json={
        "election_id": election_id, "contest_type": contest_type,
        "preferences": preferences if preferences is not None else candidate_ids(app, contest_id)})


def ballots(app):
    from app.models.voting_models import Ballot

    with app.app_context():
        return Ballot.query.count()


# --- Y09 ---

def test_opening_polling_gives_each_enrolled_voter_one_entitlement_per_contest(app):
    election_id = make_election(app)
    approved_voter(app, "alice")
    with app.app_context():
        user = make_user(username="pending-person")
        db.session.add(Enrolment(user_id=user.id, state="VIC", status="pending",
                                 identity_bidx="x" * 64, given_name_enc="-", family_name_enc="-",
                                 date_of_birth_enc="-", address_line_enc="-", suburb_enc="-",
                                 postcode_enc="-"))
        db.session.commit()
    open_polling(app, election_id)
    with app.app_context():
        rows = VoteEntitlement.query.all()
        assert sorted(r.contest_type for r in rows) == ["house", "senate"]  # alice only
        assert {r.status for r in rows} == {"unused"}


def test_the_database_allows_one_entitlement_per_contest(app):
    import pytest
    from sqlalchemy.exc import IntegrityError

    election_id, _ = polling_election(app, "alice")
    clock.unfreeze()
    with app.app_context():
        existing = VoteEntitlement.query.filter_by(contest_type="house").one()
        db.session.add(VoteEntitlement(user_id=existing.user_id, election_id=election_id,
                                       contest_id=existing.contest_id, contest_type="house"))
        with pytest.raises(IntegrityError):
            db.session.commit()


# --- Y10 ---

def test_an_enrolled_adult_is_eligible_during_polling(app):
    from app.models.user import User
    from app.security.voting_security import check_eligibility

    election_id, _ = polling_election(app, "alice")
    try:
        with app.app_context():
            decision = check_eligibility(User.query.filter_by(username="alice").one(),
                                         db.session.get(Election, election_id), "house")
            assert decision.eligible and decision.reason == "eligible"
    finally:
        clock.unfreeze()


def test_each_rule_gives_its_own_reason(app):
    from app.models.user import User
    from app.security.voting_security import check_eligibility

    election_id = make_election(app)
    approved_voter(app, "alice")
    approved_voter(app, "teen", date_of_birth="2009-01-01")  # 17 on polling day
    open_polling(app, election_id)
    approved_voter(app, "late")  # enrolled after the roll closed
    with app.app_context():
        make_user(username="nobody")
        election = db.session.get(Election, election_id)
        person = {u.username: u for u in User.query.all()}
        try:
            clock.freeze(datetime(2026, 5, 2, 7, 0, 0))
            assert check_eligibility(person["alice"], election, "house").reason == "outside_polling_hours"
            clock.freeze(DURING_POLLING)
            assert check_eligibility(person["nobody"], election, "house").reason == "not_enrolled"
            assert check_eligibility(person["teen"], election, "house").reason == "under_18"
            assert check_eligibility(person["late"], election, "house").reason == "not_on_roll_for_this_election"
            election.status = "polling_closed"
            assert check_eligibility(person["alice"], election, "house").reason == "polling_not_open"
        finally:
            clock.unfreeze()


# --- Y11 ---

def test_the_eligibility_endpoint_answers_and_records_the_decision(app):
    from app.models.audit_models import AuditEvent

    election_id, (alice,) = polling_election(app, "alice")
    try:
        body = check(alice, election_id).get_json()
        assert body["eligible"] is True and body["reason"] == "eligible"
        with app.app_context():
            event = AuditEvent.query.filter_by(action="eligibility_decision").one()
            assert json.loads(event.details) == {"contest_type": "house", "reason": "eligible"}
    finally:
        clock.unfreeze()


def test_a_client_cannot_declare_itself_eligible(app):
    """R16: 'A client-supplied eligibility flag is not trusted.'"""
    election_id = make_election(app)  # polling not even open
    alice = approved_voter(app, "alice")
    assert check(alice, election_id, eligible=True).status_code == 400
    assert check(alice, election_id).get_json()["eligible"] is False


def test_staff_cannot_use_the_voter_endpoints(app):
    from tests.test_elections import delegate_client

    election_id = make_election(app)
    dana = delegate_client(app)
    assert check(dana, election_id).status_code == 403


# --- Y12 ---

def test_a_ballot_row_has_nothing_that_identifies_the_voter(app):
    """R18: 'Ballot records do not contain a direct voter identifier.'"""
    from app.models.voting_models import Ballot

    columns = {c.name for c in Ballot.__table__.columns}
    assert columns == {"id", "election_id", "contest_id", "preferences_enc", "signature"}
    for word in ("user", "voter", "session", "ip", "time", "seq", "created", "key"):
        assert not any(word in column for column in columns), word
