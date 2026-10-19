"""Counting with an integrity gate, approvals and recount exclusions (R15, R19)."""
import json

from app import db
from app.models.election_models import Candidate
from app.models.results_models import CountRun
from app.models.voting_models import Ballot
from app.security.audit_security import append_event, raise_alert
from app.security.counting import count_house, count_senate
from app.security.integrity import verify_contest
from app.security.signed_actions import record_signed_action
from app.security.shared_security import utcnow


def run_count(contest, actor):
    """R19: verify first. If anything is wrong, there is no result at all: the run is
    stored as integrity_failed, an alert is raised, and it can never be approved."""
    from app.security.voting_security import read_preferences

    problems = verify_contest(contest)
    run = CountRun(contest_id=contest.id, run_by=actor.id)
    if problems:
        run.status, run.problems = "integrity_failed", json.dumps(problems)
        db.session.add(run)
        db.session.flush()
        raise_alert("ballot_tampering", f"contest {contest.state} {contest.contest_type}: {problems[0]}")
        append_event("integrity_failed", "failure", actor, "contest", contest.id,
                     problems=len(problems))
        record_signed_action(actor, "count_run", "contest", contest.id,
                             {"run_id": run.id, "status": run.status}, "failure")
        return run

    ballots = [read_preferences(b) for b in
               Ballot.query.filter_by(contest_id=contest.id).order_by(Ballot.id)]
    candidates = [c.id for c in contest.candidates if not c.withdrawn]
    excluded = []  # KE26 adds recount exclusions here
    if contest.contest_type == "house":
        result = count_house(ballots, candidates, excluded, seed=contest.id)
    else:
        result = count_senate(ballots, candidates, contest.seats, excluded, seed=contest.id)
    result["ballots"], result["excluded"] = len(ballots), excluded
    run.status, run.result = "completed", json.dumps(result)
    db.session.add(run)
    db.session.flush()
    record_signed_action(actor, "count_run", "contest", contest.id,
                         {"run_id": run.id, "status": run.status, "elected": result["elected"],
                          "excluded": excluded}, "success")
    return run