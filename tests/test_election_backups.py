"""R07 for election data: backups, restore tests and a simulated failure (Yufei)."""
import uuid
from datetime import datetime

from app import create_app, db
from app.models.voting_models import Ballot, VoteEntitlement
from app.security.backup import RestoreCheckFailed, create_backup, restore_backup, verify_backup
from app.security.shared_security import clock
from tests.conftest import make_test_config
from tests.test_voting import polling_election, vote


def voted_app(app, tmp_path):
    """Two voters; alice votes in both contests, bob in the House only."""
    election_id, (alice, bob) = polling_election(app, "alice", "bob")
    try:
        vote(alice, app, election_id, "house")
        vote(alice, app, election_id, "senate")
        vote(bob, app, election_id, "house")
    finally:
        clock.unfreeze()
    return election_id


# --- Y22 ---

def test_the_restore_test_checks_ballots_against_voters(app, tmp_path):
    voted_app(app, tmp_path)
    with app.app_context():
        backup = create_backup(tmp_path / "backups")
        report = verify_backup(backup, tmp_path / "reports")
    text = report.read_text()
    assert "Ballots match voters marked as voted, audit trail verifies: yes" in text
    assert "**PASS**" in text
    assert "| ballots | 3 |" in text


def test_a_backup_with_a_missing_ballot_fails_its_restore_test(app, tmp_path):
    """A backup that lost an acknowledged vote must not pass as good."""
    import pytest

    voted_app(app, tmp_path)
    with app.app_context():
        with db.engine.begin() as connection:  # simulate the loss, as someone with the sqlite3 tool could
            connection.exec_driver_sql("DROP TRIGGER IF EXISTS ballots_no_delete")  # Keane's guard
            connection.exec_driver_sql("DELETE FROM ballots WHERE id = (SELECT MIN(id) FROM ballots)")
        backup = create_backup(tmp_path / "backups")
        with pytest.raises(RestoreCheckFailed) as failure:
            verify_backup(backup, tmp_path / "reports")
    text = failure.value.report.read_text()
    assert "**FAIL**" in text and "voters marked as voted" in text


# --- Y23 ---

def test_the_restore_test_rechecks_the_audit_trail(app, tmp_path):
    import pytest

    voted_app(app, tmp_path)
    with app.app_context():
        with db.engine.begin() as connection:
            connection.exec_driver_sql("DROP TRIGGER audit_events_no_update")
            connection.exec_driver_sql("UPDATE audit_events SET result = 'failure' WHERE seq = 2")
        backup = create_backup(tmp_path / "backups")
        with pytest.raises(RestoreCheckFailed) as failure:
            verify_backup(backup, tmp_path / "reports")
    assert "event 2 has been altered" in failure.value.report.read_text()
