"""R19 tamper detection before counting, and R15 approvals and exclusions (Keane)."""
import pytest

from app import db
from app.models.audit_models import SecurityAlert
from app.models.election_models import Contest, Election
from app.models.voting_models import Ballot
from app.security.election_security import change_election_status
from app.security.shared_security import clock
from tests.conftest import csrf_headers
from tests.test_elections import candidate_ids, contest_of, delegate_client
from tests.test_voting import polling_election, vote


def closed_election(app, voters=("alice", "bob", "carol")):
    """Three voters vote in the VIC House contest, then polling closes (sealing it)."""
    election_id, clients = polling_election(app, *voters)
    contest_id = contest_of(app, election_id, "house")
    a, b, c = candidate_ids(app, contest_id)
    choices = ([a, b], [a, c], [b, a])
    try:
        for client, preferences in zip(clients, choices):
            assert vote(client, app, election_id, preferences=preferences).status_code == 201
    finally:
        clock.unfreeze()
    with app.app_context():
        from app.models.user import User

        election = db.session.get(Election, election_id)
        delegate = User.query.filter_by(role="commissioner_delegate").first()
        assert change_election_status(election, delegate, "polling_closed")  # this seals it
        db.session.commit()
    return election_id, contest_id


def as_dba(app, *statements):
    """Someone with the sqlite3 tool: the append-only triggers are dropped first."""
    with app.app_context(), db.engine.begin() as connection:
        for table in ("ballots", "ballot_seals"):
            for change in ("update", "delete"):
                connection.exec_driver_sql(f"DROP TRIGGER IF EXISTS {table}_no_{change}")
        for statement in statements:
            connection.exec_driver_sql(statement)


def problems(app, contest_id):
    from app.security.integrity import verify_contest

    with app.app_context():
        return verify_contest(db.session.get(Contest, contest_id))


def count(client, contest_id):
    return client.post(f"/contests/{contest_id}/count", headers=csrf_headers(client))


# --- KE21 ---

def test_every_accepted_ballot_is_signed(app):
    election_id, (alice,) = polling_election(app, "alice")
    try:
        vote(alice, app, election_id)
    finally:
        clock.unfreeze()
    from app.security.integrity import ballot_digest
    from app.security.signing import public_key_hex, verify

    with app.app_context():
        ballot = Ballot.query.one()
        assert verify({"ballot": ballot_digest(ballot)}, ballot.signature, public_key_hex("AUDIT_SIGNING_KEY"))

# --- KE22 ---

def test_closing_polling_seals_every_contest(app):
    from app.models.results_models import BallotSeal

    _, contest_id = closed_election(app)
    with app.app_context():
        seal = db.session.get(BallotSeal, contest_id)
        assert seal.ballot_count == 3
        assert BallotSeal.query.count() == 16  # every contest, even those with no ballots


def test_the_merkle_root_ignores_arrival_order_but_not_content():
    from app.security.integrity import merkle_root

    leaves = ["a" * 64, "b" * 64, "c" * 64]
    assert merkle_root(leaves) == merkle_root(list(reversed(leaves)))  # R18: no order leak
    assert merkle_root(leaves) != merkle_root(leaves[:2])
    assert merkle_root(leaves) != merkle_root(leaves[:2] + ["d" * 64])


def test_the_database_refuses_to_change_ballots_or_seals(app):
    from sqlalchemy.exc import IntegrityError

    _, contest_id = closed_election(app)
    with app.app_context():
        for statement in ("DELETE FROM ballots", "UPDATE ballots SET signature = '00'",
                          f"UPDATE ballot_seals SET ballot_count = 0 WHERE contest_id = '{contest_id}'"):
            with pytest.raises(IntegrityError), db.engine.begin() as connection:
                connection.exec_driver_sql(statement)
        assert Ballot.query.count() == 3

# --- KE23 ---

def test_untouched_ballots_verify(app):
    _, contest_id = closed_election(app)
    assert problems(app, contest_id) == []


def test_an_altered_ballot_is_detected(app):
    _, contest_id = closed_election(app)
    as_dba(app, "UPDATE ballots SET preferences_enc = preferences_enc || 'x' "
                "WHERE id = (SELECT MIN(id) FROM ballots)")
    found = problems(app, contest_id)
    assert any("is not signed correctly" in p for p in found)
    assert "the ballots no longer match the seal" in found


def test_a_deleted_ballot_is_detected(app):
    _, contest_id = closed_election(app)
    as_dba(app, "DELETE FROM ballots WHERE id = (SELECT MIN(id) FROM ballots)")
    found = problems(app, contest_id)
    assert "2 ballots, but the seal says 3" in found
    assert "2 ballots, but 3 voters are marked as voted" in found


def test_an_inserted_ballot_is_detected(app):
    _, contest_id = closed_election(app)
    with app.app_context():
        election_id = db.session.get(Contest, contest_id).election_id
    as_dba(app, f"INSERT INTO ballots (id, election_id, contest_id, preferences_enc, signature) "
                f"VALUES ('ffffffff-0000-4000-8000-000000000000', '{election_id}', '{contest_id}', 'forged', '00')")
    found = problems(app, contest_id)
    assert "ballot ffffffff is not signed correctly" in found
    assert "4 ballots, but the seal says 3" in found


def test_a_ballot_copied_onto_another_row_is_detected(app):
    """Copying one voter's encrypted ballot over another's: the AAD and the signature
    are both tied to the row's id, so the copy is caught."""
    _, contest_id = closed_election(app)
    as_dba(app, "UPDATE ballots SET preferences_enc = (SELECT preferences_enc FROM ballots ORDER BY id LIMIT 1), "
                "signature = (SELECT signature FROM ballots ORDER BY id LIMIT 1) "
                "WHERE id = (SELECT MAX(id) FROM ballots)")
    found = problems(app, contest_id)
    assert any("is not signed correctly" in p for p in found)


def test_a_forged_seal_is_detected(app):
    _, contest_id = closed_election(app)
    as_dba(app, f"UPDATE ballot_seals SET ballot_count = 4 WHERE contest_id = '{contest_id}'")
    assert "the seal's signature is invalid" in problems(app, contest_id)