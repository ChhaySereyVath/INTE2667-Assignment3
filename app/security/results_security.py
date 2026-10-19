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
    excluded = confirmed_exclusions(contest)  # KE26 adds recount exclusions here
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

def approve_result(run, actor):
    """R15: approving a result is signed, and needs a SECOND delegate.

    Returns "approved", or why it was refused (the refusal is signed too).
    """
    reason = None
    if run.status != "completed":
        reason = "integrity_failed"  # R19: a failed count is never released
    elif run.run_by == actor.id:
        reason = "own_count"  # separation of duties: you cannot approve your own count
    elif CountRun.query.filter(CountRun.contest_id == run.contest_id,
                               CountRun.approved_by.isnot(None)).first():
        reason = "already_approved"
    if reason:
        record_signed_action(actor, "result_approve", "count_run", run.id, {"reason": reason}, "denied")
        return reason
    run.approved_by, run.approved_at = actor.id, utcnow()
    record_signed_action(actor, "result_approve", "count_run", run.id,
                         {"elected": json.loads(run.result)["elected"]}, "success")
    return "approved"


def published_results(election):
    """Approved results only, and only once the election is published. Candidate ids
    are swapped for names: this is what the public sees."""
    names = {}
    contests = []
    for contest in election.contests:
        run = CountRun.query.filter(CountRun.contest_id == contest.id,
                                    CountRun.approved_by.isnot(None)).first()
        if run is None:
            continue
        names.update({c.id: c.name for c in contest.candidates})
        result = json.loads(run.result)
        contests.append({
            "contest_type": contest.contest_type,
            "state": contest.state,
            "elected": [names[c] for c in result["elected"]],
            "first_preferences": {names[c]: votes for c, votes in result["rounds"][0].items()},
            "ballots": result["ballots"],
        })
    return contests

def confirmed_exclusions(contest):
    """Only exclusions a SECOND delegate has confirmed affect a count."""
    from app.models.results_models import Exclusion

    return [row.candidate_id for row in
            Exclusion.query.filter(Exclusion.contest_id == contest.id,
                                   Exclusion.confirmed_by.isnot(None))]


def propose_exclusion(contest, candidate, actor):
    from app.models.results_models import Exclusion

    row = Exclusion(contest_id=contest.id, candidate_id=candidate.id, proposed_by=actor.id)
    db.session.add(row)
    db.session.flush()
    record_signed_action(actor, "exclusion_propose", "candidate", candidate.id,
                         {"exclusion_id": row.id, "contest_id": contest.id}, "success")
    return row


def confirm_exclusion(row, actor):
    """Two-person rule: the proposer cannot confirm their own proposal."""
    if row.proposed_by == actor.id or row.confirmed_by is not None:
        record_signed_action(actor, "exclusion_confirm", "candidate", row.candidate_id,
                             {"exclusion_id": row.id}, "denied")
        return False
    row.confirmed_by = actor.id
    record_signed_action(actor, "exclusion_confirm", "candidate", row.candidate_id,
                         {"exclusion_id": row.id}, "success")
    return True


def candidate_or_none(candidate_id):
    return db.session.get(Candidate, str(candidate_id))