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