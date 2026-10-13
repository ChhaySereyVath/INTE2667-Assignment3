"""R01/R07: encrypted backups, restores and documented restore tests.

flask backup                  take an encrypted backup now (and prune old ones)
flask verify-backup [FILE]    restore the newest (or FILE) into memory, check it,
                              and write a dated report to docs/restore-reports/
flask restore FILE TARGET     restore a backup into a NEW database file

Run `flask backup` every 24 hours with Windows Task Scheduler or cron (see the sheet).
"""
import os
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import click
from flask import current_app
from flask.cli import with_appcontext

from app import db
from app.security.crypto import decrypt_bytes, encrypt_bytes
from app.security.shared_security import utcnow

BACKUP_NAME = re.compile(r"evp-(\d{8}-\d{6})-\d{6}\.db\.enc")


def create_backup(directory):
    """Copy the live database, encrypt it, and write it owner-readable only."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    name = f"evp-{utcnow():%Y%m%d-%H%M%S-%f}.db.enc"
    raw = db.engine.raw_connection()
    try:
        snapshot = sqlite3.connect(":memory:")
        # SQLite's backup API gives a consistent copy even while the app is running
        raw.driver_connection.backup(snapshot)
        data = snapshot.serialize()
        snapshot.close()
    finally:
        raw.close()
    path = directory / name
    # the file name is the associated data: a backup renamed to look like another
    # day's backup will not decrypt
    path.write_bytes(encrypt_bytes(data, aad=name))
    os.chmod(path, 0o600)  # R07: access-controlled
    return path


def read_backup(path):
    """Decrypt a backup into an in-memory database and check it is whole."""
    path = Path(path)
    data = decrypt_bytes(path.read_bytes(), aad=path.name)
    restored = sqlite3.connect(":memory:")
    restored.deserialize(data)
    if restored.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("Backup failed its integrity check")
    return restored


def table_counts(connection):
    """Rows per table, for the restore report."""
    names = [row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    # the names come from the backup's own catalogue, not from a user
    return {name: connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]  # nosec B608
            for name in names}


def restore_backup(path, target):
    """Restore into a NEW file. It never overwrites, so a mistake cannot destroy data."""
    target = Path(target)
    if target.exists():
        raise FileExistsError(f"{target} already exists; choose a new file name")
    restored = read_backup(path)
    out = sqlite3.connect(target)
    restored.backup(out)
    out.close()
    restored.close()
    return target


def prune_backups(directory, keep_days):
    """R07: delete backups older than the retention period (at least 90 days)."""
    cutoff = utcnow() - timedelta(days=keep_days)
    removed = []
    for path in sorted(Path(directory).glob("evp-*.db.enc")):
        match = BACKUP_NAME.fullmatch(path.name)
        if match and datetime.strptime(match.group(1), "%Y%m%d-%H%M%S") < cutoff:
            path.unlink()
            removed.append(path.name)
    return removed


def newest_backup(directory):
    backups = sorted(Path(directory).glob("evp-*.db.enc"))
    return backups[-1] if backups else None


def verify_backup(path, report_dir):
    """R07: a restore test with a written result. Returns the report's path."""
    restored = read_backup(path)
    counts = table_counts(restored)
    restored.close()
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    tested = utcnow()
    report = report_dir / f"restore-{tested:%Y%m%d-%H%M%S}.md"
    lines = [f"# Restore test {tested:%Y-%m-%d %H:%M} UTC", "",
             f"- Backup: `{Path(path).name}`",
             "- Decrypted with BACKUP_KEY: yes",
             "- SQLite integrity check: ok",
             "- Result: **PASS**", "", "| Table | Rows |", "|---|---|"]
    lines += [f"| {name} | {count} |" for name, count in counts.items()]
    report.write_text("\n".join(lines) + "\n")
    return report


@click.command("backup")
@with_appcontext
def backup_command():
    """Take an encrypted backup now, then remove backups past the retention period."""
    path = create_backup(current_app.config["BACKUP_DIR"])
    removed = prune_backups(current_app.config["BACKUP_DIR"], current_app.config["BACKUP_RETENTION_DAYS"])
    click.echo(f"Wrote {path}. Removed {len(removed)} backups older than "
               f"{current_app.config['BACKUP_RETENTION_DAYS']} days.")


@click.command("verify-backup")
@click.argument("backup_file", required=False)
@with_appcontext
def verify_backup_command(backup_file):
    """Restore-test a backup (the newest if none is given) and write a report."""
    path = Path(backup_file) if backup_file else newest_backup(current_app.config["BACKUP_DIR"])
    if path is None:
        raise click.ClickException("No backups found. Run `flask backup` first.")
    try:
        report = verify_backup(path, current_app.config["RESTORE_REPORT_DIR"])
    except ValueError:
        raise click.ClickException("Restore test FAILED: the backup could not be decrypted or is damaged.")
    click.echo(f"Restore test passed. Report: {report}")


@click.command("restore")
@click.argument("backup_file")
@click.argument("target_file")
@with_appcontext
def restore_command(backup_file, target_file):
    """Restore BACKUP_FILE into TARGET_FILE (a new file; it never overwrites)."""
    try:
        target = restore_backup(backup_file, target_file)
    except (ValueError, FileExistsError) as error:
        raise click.ClickException(str(error))
    click.echo(f"Restored into {target}. Stop the app, then point DATABASE_URL at it.")