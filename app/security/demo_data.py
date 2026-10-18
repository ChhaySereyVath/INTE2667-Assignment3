"""Demo data for the presentation (Yufei). Invented people, invented votes.

flask demo-voters --count 30 --state VIC   enrolled, approved demo voters (before polling opens)
flask demo-votes --election ID             each demo voter casts random House and Senate ballots

Ballots go through submit_ballot, the same code the API uses, so every rule
(eligibility, one vote per contest, signing, the audit trail) applies to them too.
"""
import random
import uuid

import click
from flask.cli import with_appcontext

from app import db

DEMO_PASSWORD = "Demo-Voter-Password-1"  # demo accounts only; never used for a real account


@click.command("demo-voters")
@click.option("--count", default=30, show_default=True)
@click.option("--state", default="VIC", show_default=True)
@with_appcontext
def demo_voters_command(count, state):
    """Create demo citizens with approved enrolments. Run BEFORE polling opens."""
    from app.models.enrollment_models import Enrolment
    from app.models.user import User
    from app.security.enrollment_security import identity_key

    for number in range(1, count + 1):
        username = f"demo-voter-{uuid.uuid4().hex[:8]}"
        user = User(username=username, role="citizen", status="active")
        user.set_password(DEMO_PASSWORD)
        db.session.add(user)
        db.session.flush()
        enrolment = Enrolment(id=str(uuid.uuid4()), user_id=user.id, state=state, status="approved",
                              identity_bidx=identity_key(username, "Demo", "1980-01-01"))
        for field, value in (("given_name", "Demo"), ("family_name", f"Voter {number}"),
                             ("date_of_birth", "1980-01-01"), ("address_line", "1 Demo Street"),
                             ("suburb", "Demotown"), ("postcode", "3000")):
            enrolment.set_field(field, value)
        db.session.add(enrolment)
    db.session.commit()
    click.echo(f"Created {count} demo voters in {state}.")


@click.command("demo-votes")
@click.option("--election", "election_id", required=True)
@with_appcontext
def demo_votes_command(election_id):
    """Every demo voter votes once in each of their contests (polling must be open)."""
    from app.models.election_models import Election
    from app.models.user import User
    from app.security.voting_security import submit_ballot

    election = db.session.get(Election, election_id)
    if election is None:
        raise click.ClickException("No such election")
    rng = random.Random()  # nosec B311: invented demo votes, not security
    outcomes = {}
    for user in User.query.filter(User.username.like("demo-voter-%")).all():
        for contest_type in ("house", "senate"):
            contest = next((c for c in election.contests if c.contest_type == contest_type
                            and c.state == _state_of(user)), None)
            if contest is None:
                continue
            choices = [c.id for c in contest.candidates if not c.withdrawn]
            rng.shuffle(choices)
            outcome = submit_ballot(user, election, contest_type, choices[:rng.randint(1, len(choices))],
                                    str(uuid.uuid4()))
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
    click.echo(f"Ballots: {outcomes}")


def _state_of(user):
    from app.models.enrollment_models import Enrolment

    enrolment = Enrolment.query.filter_by(user_id=user.id).first()
    return enrolment.state if enrolment else None
