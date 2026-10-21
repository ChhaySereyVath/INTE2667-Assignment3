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


def change_election_status(election, actor, new_status):
    """Move an election along its workflow. Returns True if the move was allowed.

    Opening polling hands out entitlements (R17): one per approved enrolment per
    contest in that person's state. The electoral roll closes at that moment, as it
    does in a real election before polling day.
    """
    if new_status not in ELECTION_TRANSITIONS.get(election.status, ()):
        return False
    previous, election.status = election.status, new_status
    if new_status == "polling_open":
        issue_entitlements(election)
    if new_status == "polling_closed":
        from app.security.integrity import seal_contest

        for contest in election.contests:  # Keane, R19: seal every contest's ballots
            seal_contest(contest)
    from app.security.audit_security import append_event

    append_event("election_transition", "success", actor, "election", election.id,
                 from_status=previous, to_status=new_status)
    return True


# --- demo data --------------------------------------------------------------

DEMO_CANDIDATES = {
    "house": [("Avery Lin", "Harbour Party"), ("Blake Okafor", "Green Valley Party"),
              ("Casey Nguyen", "Independent"), ("Dana Russo", "Civic Union")],
    "senate": [("Ellis Park", "Harbour Party"), ("Finley Shaw", "Harbour Party"),
               ("Gray Molina", "Green Valley Party"), ("Harper Doyle", "Green Valley Party"),
               ("Indy Tran", "Civic Union"), ("Jules Becker", "Civic Union"),
               ("Kai Moreno", "Independent"), ("Lane Fraser", "Independent")],
}


@click.command("seed-election")
@click.option("--creator", required=True, help="Username of the delegate creating it")
@with_appcontext
def seed_election_command(creator):
    """Create a demo election open for nominations, with invented candidates.

    These are fictional names for a demonstration. In use, delegates add candidates
    through the candidate API, which signs every change (Keane's R15).
    """
    from app.models.user import User

    actor = User.query.filter_by(username=creator).first()
    if actor is None or actor.role != "commissioner_delegate":
        raise click.ClickException("--creator must be an existing commissioner delegate")
    now = utcnow().replace(microsecond=0)
    election = create_election(actor, "Demo Federal Election", now, now + timedelta(days=14))
    election.status = "nominations_open"
    for contest in election.contests:
        for position, (name, party) in enumerate(DEMO_CANDIDATES[contest.contest_type], start=1):
            db.session.add(Candidate(contest_id=contest.id, name=name, party=party,
                                     ballot_position=position))
    db.session.commit()
    click.echo(f"Created election {election.id} with {len(election.contests)} contests.")


def issue_entitlements(election):
    """R17: create every voter's 'unused' entitlements in one go."""
    from app.models.enrollment_models import Enrolment
    from app.models.voting_models import VoteEntitlement

    contests = {(c.contest_type, c.state): c for c in election.contests}
    for user_id, state in db.session.query(Enrolment.user_id, Enrolment.state).filter_by(status="approved"):
        for contest_type in ("house", "senate"):
            contest = contests[(contest_type, state)]
            db.session.add(VoteEntitlement(user_id=user_id, election_id=election.id,
                                           contest_id=contest.id, contest_type=contest_type))
