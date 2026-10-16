"""Election set-up and the election workflow (R16, R17 groundwork)."""
from datetime import timedelta

import click
from flask.cli import with_appcontext

from app import db
from app.models.election_models import (ELECTION_TRANSITIONS, SENATE_SEATS, Candidate, Contest,
                                        Election)
from app.security.shared_security import utcnow
from app.security.validators import STATES


def create_election(actor, name, polling_opens_at, polling_closes_at):
    """A new election with a House and a Senate contest in every state."""
    election = Election(name=name, polling_opens_at=polling_opens_at,
                        polling_closes_at=polling_closes_at, created_by=actor.id)
    db.session.add(election)
    db.session.flush()
    for state in STATES:
        db.session.add(Contest(election_id=election.id, contest_type="house", state=state, seats=1))
        db.session.add(Contest(election_id=election.id, contest_type="senate", state=state,
                               seats=SENATE_SEATS[state]))
    return election
