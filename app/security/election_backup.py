"""R07 (Yufei): the restore test also proves the ELECTION data came back whole.

Austin's verify_backup checks that a backup decrypts and that SQLite finds it intact.
This adds the checks that matter for an election:
- every contest has exactly as many ballots as voters marked as voted (no
  acknowledged vote lost, none counted twice), and
- Keane's audit trail still verifies, link by link.
"""
from datetime import datetime
from types import SimpleNamespace

import click
from flask import current_app
from flask.cli import with_appcontext


def _rows(connection, sql):
    cursor = connection.execute(sql)
    names = [column[0] for column in cursor.description]
    return [SimpleNamespace(**dict(zip(names, row))) for row in cursor.fetchall()]


def _tables(connection):
    return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def ballot_problems(connection):
    """Per contest: ballots stored == entitlements used."""
    if "contests" not in _tables(connection):
        return []
    problems = []
    for contest in _rows(connection, """
            SELECT c.state, c.contest_type,
                   (SELECT COUNT(*) FROM ballots b WHERE b.contest_id = c.id) AS ballots,
                   (SELECT COUNT(*) FROM vote_entitlements v
                     WHERE v.contest_id = c.id AND v.status = 'used') AS used
              FROM contests c ORDER BY c.state, c.contest_type"""):
        if contest.ballots != contest.used:
            problems.append(f"{contest.state} {contest.contest_type}: {contest.ballots} ballots "
                            f"but {contest.used} voters marked as voted")
    return problems


def audit_problems(connection):
    """Run Keane's chain check over the restored copy's audit trail."""
    from app.security.audit_security import chain_problems

    if "audit_events" not in _tables(connection):
        return []
    events = _rows(connection, "SELECT * FROM audit_events ORDER BY seq")
    for event in events:
        event.occurred_at = datetime.fromisoformat(event.occurred_at)
    heads = _rows(connection, "SELECT seq, record_hash FROM audit_head WHERE id = 1")
    return chain_problems(events, heads[0] if heads else None)


def election_problems(connection):
    return ballot_problems(connection) + audit_problems(connection)
