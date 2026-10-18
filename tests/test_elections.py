"""Elections, contests and candidates, and the election workflow (Yufei)."""
from datetime import datetime

from app import db
from app.models.election_models import Candidate, Contest, Election
from app.models.user import User
from app.security.election_security import create_election
from tests.conftest import csrf_headers
from tests.test_auth_login import make_user
from tests.test_enrollment_access import staff_client

OPENS = datetime(2026, 5, 2, 8, 0, 0)
CLOSES = datetime(2026, 5, 2, 18, 0, 0)


def delegate_client(app, username="dana.vic", states=("VIC",)):
    return staff_client(app, username, "commissioner_delegate", list(states))


def make_election(app, status="nominations_open", candidates=("Avery Lin", "Blake Okafor", "Casey Nguyen")):
    """An election with candidates in the VIC House and Senate contests. Returns its id."""
    with app.app_context():
        creator = User.query.filter_by(role="commissioner_delegate").first() or make_user(
            username="dana-seed", role="commissioner_delegate")
        election = create_election(creator, "Test Election", OPENS, CLOSES)
        db.session.flush()
        for contest in election.contests:
            if contest.state == "VIC":
                for position, name in enumerate(candidates, start=1):
                    db.session.add(Candidate(contest_id=contest.id, name=name, ballot_position=position))
        election.status = status
        db.session.commit()
        return election.id


def contest_of(app, election_id, contest_type, state="VIC"):
    with app.app_context():
        return Contest.query.filter_by(election_id=election_id, contest_type=contest_type,
                                       state=state).one().id


def candidate_ids(app, contest_id):
    with app.app_context():
        return [c.id for c in db.session.get(Contest, contest_id).candidates]


# --- Y01 ---

def test_an_election_has_a_house_and_a_senate_contest_in_every_state(app):
    election_id = make_election(app, status="draft")
    with app.app_context():
        contests = db.session.get(Election, election_id).contests
        assert len(contests) == 16
        assert {(c.contest_type, c.state) for c in contests if c.state == "VIC"} == {
            ("house", "VIC"), ("senate", "VIC")}
        seats = {(c.contest_type, c.state): c.seats for c in contests}
        assert seats[("house", "NSW")] == 1
        assert seats[("senate", "NSW")] == 6 and seats[("senate", "ACT")] == 2


def test_candidates_are_listed_in_ballot_order_and_hold_no_voter_data(app):
    election_id = make_election(app)
    with app.app_context():
        contest = Contest.query.filter_by(election_id=election_id, contest_type="house", state="VIC").one()
        assert [c["name"] for c in contest.to_dict()["candidates"]] == [
            "Avery Lin", "Blake Okafor", "Casey Nguyen"]
        columns = {c.name for c in Candidate.__table__.columns}
        assert not {"user_id", "voter_id", "votes"} & columns
