# R07 restore drill: losing the database during an election

**Requirements:** R07 "A restoration test is performed ... Restoration results are
documented", and (from R20) "Recovery preserves acknowledged records" and "does not
allow the same record to be counted twice".

## The automated drill (runs with every `pytest`)

`test_after_a_crash_the_restored_system_keeps_every_vote_and_counts_none_twice`:

1. Two voters cast House ballots (one with a known Idempotency-Key).
2. An encrypted backup is taken (`create_backup`).
3. The live database file is **deleted** (the simulated failure).
4. The backup is restored into a new file (`restore_backup` never overwrites).
5. A fresh app starts on the restored file, with the same keys (kept outside the backup).
6. Checks: both ballots are there, both entitlements are still "used", the audit trail
   verifies, and the voter's retry with the same Idempotency-Key gets
   `already_accepted`, with the ballot count unchanged.

## The manual drill (do once, take screenshots)

| Step | Command | What you saw |
|---|---|---|
| 1 | `flask backup` | |
| 2 | stop the app, rename `instance\evp.db` to `evp.db.lost` | |
| 3 | `flask restore backups\evp-....db.enc instance\evp.db` | |
| 4 | `python run.py`, sign in, open the audit page, **Verify integrity** | |
| 5 | `flask verify-backup` → report in `docs/restore-reports/` | |

Result: PASS / FAIL, date, who ran it.
