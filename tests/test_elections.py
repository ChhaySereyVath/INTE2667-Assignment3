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


# --- Y02 ---

def test_an_election_moves_one_step_at_a_time(app):
    from app.security.election_security import change_election_status

    election_id = make_election(app, status="draft")
    with app.app_context():
        election, actor = db.session.get(Election, election_id), User.query.first()
        assert not change_election_status(election, actor, "polling_open")  # skipping a step
        assert change_election_status(election, actor, "nominations_open")
        assert change_election_status(election, actor, "polling_open")
        assert not change_election_status(election, actor, "nominations_open")  # no going back
        assert election.status == "polling_open"


# --- Y03 ---

def test_a_delegate_creates_an_election(app):
    dana = delegate_client(app)
    response = dana.post("/elections", headers=csrf_headers(dana), json={
        "name": "2026 Federal Election",
        "polling_opens_at": "2026-05-02T08:00:00", "polling_closes_at": "2026-05-02T18:00:00"})
    assert response.status_code == 201
    election = response.get_json()["election"]
    assert election["status"] == "draft"
    detail = dana.get(f"/elections/{election['id']}").get_json()["election"]
    assert len(detail["contests"]) == 16


def test_bad_election_details_are_refused(app):
    dana = delegate_client(app)
    times = {"polling_opens_at": "2026-05-02T08:00:00", "polling_closes_at": "2026-05-02T18:00:00"}
    for body in (dict(times, name="X"),  # name too short
                 dict(name="Late close", polling_opens_at="2026-05-02T18:00:00",
                      polling_closes_at="2026-05-02T08:00:00"),
                 dict(times, name="Bad date", polling_opens_at="tomorrow"),
                 dict(times, name="Sneaky", status="polling_open")):  # unknown field
        assert dana.post("/elections", headers=csrf_headers(dana), json=body).status_code == 400
    with app.app_context():
        assert Election.query.count() == 0


def test_only_delegates_create_or_change_elections(app):
    from tests.test_enrollment_access import citizen_client

    election_id = make_election(app, status="draft")
    alice = citizen_client(app)
    emma = staff_client(app, "emma.vic", "aec_employee", ["VIC"])
    for client in (alice, emma):
        assert client.post(f"/elections/{election_id}/status", headers=csrf_headers(client),
                           json={"status": "nominations_open"}).status_code == 403
    assert alice.get(f"/elections/{election_id}").status_code == 200  # reading is fine


def test_the_status_endpoint_refuses_steps_out_of_order(app):
    election_id = make_election(app, status="draft")
    dana = delegate_client(app)
    bad = dana.post(f"/elections/{election_id}/status", headers=csrf_headers(dana),
                    json={"status": "polling_open"})
    assert bad.status_code == 409
    good = dana.post(f"/elections/{election_id}/status", headers=csrf_headers(dana),
                     json={"status": "nominations_open"})
    assert good.status_code == 200 and good.get_json()["election"]["status"] == "nominations_open"


# --- Y04 ---

def test_seed_election_creates_a_demo_election_with_candidates(app):
    with app.app_context():
        make_user(username="dana", role="commissioner_delegate")
    result = app.test_cli_runner().invoke(args=["seed-election", "--creator", "dana"])
    assert "with 16 contests" in result.output
    with app.app_context():
        election = Election.query.one()
        assert election.status == "nominations_open"
        house = Contest.query.filter_by(contest_type="house", state="VIC").one()
        assert len(house.candidates) == 4


def test_seed_election_needs_a_delegate(app):
    with app.app_context():
        make_user(username="alice")
    result = app.test_cli_runner().invoke(args=["seed-election", "--creator", "alice"])
    assert result.exit_code != 0
    with app.app_context():
        assert Election.query.count() == 0
