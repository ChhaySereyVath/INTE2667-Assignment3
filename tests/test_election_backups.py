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


# --- Y24 ---

def test_after_a_crash_the_restored_system_keeps_every_vote_and_counts_none_twice(tmp_path):
    """R07/R20 drill: votes are cast, a backup is taken, the database is lost, the
    backup is restored, and the service starts again on the restored copy."""
    live = tmp_path / "live.db"
    app = create_app(make_test_config(SQLALCHEMY_DATABASE_URI=f"sqlite:///{live}"))
    election_id, (alice, bob) = polling_election(app, "alice", "bob")
    key = str(uuid.uuid4())
    try:
        assert vote(alice, app, election_id, "house", key=key).status_code == 201
        assert vote(bob, app, election_id, "house").status_code == 201
    finally:
        clock.unfreeze()
    with app.app_context():
        backup = create_backup(tmp_path / "backups")
        db.engine.dispose()
    live.unlink()  # the "server failure": the live database is gone

    with app.app_context():  # the restore needs BACKUP_KEY from the config
        restored = restore_backup(backup, tmp_path / "restored.db")
    config = make_test_config(SQLALCHEMY_DATABASE_URI=f"sqlite:///{restored}")
    # Reuse the actual external keys configured by this app, including BACKUP_KEY.
    for name in ("DATA_ENC_KEY", "BLIND_INDEX_KEY", "BACKUP_KEY", "BALLOT_KEY",
                 "SECRET_KEY", "JWT_SECRET_KEY"):
        config[name] = app.config[name]  # the same keys, kept OUTSIDE the backup (R01)
    again = create_app(config)
    with again.app_context():
        assert Ballot.query.count() == 2
        assert VoteEntitlement.query.filter_by(status="used", contest_type="house").count() == 2
        from app.security.audit_security import verify_chain

        assert verify_chain() == []
    # Alice's terminal never saw the answer and retries: no second vote is created.
    from tests.test_auth_login import login

    client = again.test_client()
    login(client, "alice", "Correct-Horse-42")
    clock.freeze(datetime(2026, 5, 2, 12, 0, 0))
    try:
        retry = vote(client, again, election_id, "house", key=key)
    finally:
        clock.unfreeze()
    assert retry.get_json()["status"] == "already_accepted"
    with again.app_context():
        assert Ballot.query.count() == 2
        db.engine.dispose()


# --- Y25 ---

def test_restore_status_flags_an_overdue_restore_test(app, tmp_path):
    app.config["RESTORE_REPORT_DIR"] = str(tmp_path / "reports")
    runner = app.test_cli_runner()
    result = runner.invoke(args=["restore-status"])
    assert result.exit_code == 1 and "no restore test has ever been run" in result.output

    with app.app_context():
        clock.freeze(datetime(2026, 3, 1, 9, 0, 0))
        try:
            verify_backup(create_backup(tmp_path / "backups"), tmp_path / "reports")
            clock.freeze(datetime(2026, 3, 20, 9, 0, 0))
            assert runner.invoke(args=["restore-status"]).exit_code == 0  # 19 days: fine
            clock.freeze(datetime(2026, 4, 10, 9, 0, 0))
            late = runner.invoke(args=["restore-status"])
            assert late.exit_code == 1 and "OVERDUE" in late.output  # 40 days: overdue
        finally:
            clock.unfreeze()
