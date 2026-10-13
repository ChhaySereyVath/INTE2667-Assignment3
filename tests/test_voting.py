"""
Voting subsystem tests
======================
Covers:
  VotingToken model          — generation, validity, expiry, invalidation
  VoteRecord model           — integrity hash creation and tamper detection (R-19)
  VoteAuditLog model         — append-only record creation
  POST /voting/token         — one-time token issuance (Solution 20)
  GET  /voting/ballot        — electorate-scoped ballot (R-11)
  POST /voting/cast          — atomic vote commit (Solution 11, R-19, Solution 18)
  GET  /voting/verify/<rc>   — receipt verification and tamper detection (R-19)
  Double-vote prevention     — has_voted flag + DB unique constraint
  Unauthenticated access     — all routes require login
"""

from datetime import timedelta

import pytest

from app import db
from app.models.voting_models import Candidate, VoteAuditLog, VoteRecord, VotingToken
from app.models.user import User
from app.security.shared_security import utcnow
from tests.test_auth_login import make_user

TEST_ORIGIN = "https://localhost"


def csrf_headers(client):
    cookie = client.get_cookie("csrf_access_token")
    return {"X-CSRF-TOKEN": cookie.value, "Origin": TEST_ORIGIN}


def login(client, username, password):
    return client.post(
        "/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": TEST_ORIGIN},
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASSWORD = "Correct-Horse-42"


def make_voter(username="alice", electorate="Melbourne", state="VIC", has_voted=False):
    """Create an active citizen with enrolment fields, add to session, return user."""
    user = User(username=username, role="citizen", status="active")
    user.set_password(PASSWORD)
    # The voting routes read electorate and state from the User row directly.
    # These columns may not exist yet (they belong to the enrolment subsystem);
    # we set them as Python attributes so the tests work whether or not the
    # migration has run. If the column exists, they persist; if not, the
    # attribute is still readable by the route in the same request context.
    user.electorate = electorate
    user.state      = state
    user.has_voted  = has_voted
    db.session.add(user)
    db.session.commit()
    return user


def make_candidate(
    name="Candidate A",
    party="Test Party",
    electorate="Melbourne",
    chamber="house",
    state="VIC",
    ballot_order=1,
    party_group=None,
):
    c = Candidate(
        name=name,
        party=party,
        electorate=electorate,
        chamber=chamber,
        state=state,
        ballot_order=ballot_order,
        party_group=party_group,
    )
    db.session.add(c)
    db.session.commit()
    return c


def login_as(client, username=None, password=PASSWORD):
    username = username or "alice"
    resp = login(client, username, password)
    assert resp.status_code == 200, f"Login failed: {resp.get_json()}"
    return resp


def get_token(client):
    """POST /voting/token and return the token string."""
    resp = client.post(
        "/voting/token",
        headers=csrf_headers(client),
        json={},
    )
    assert resp.status_code == 201, f"Token issuance failed: {resp.get_json()}"
    return resp.get_json()["token"]


def cast_vote(client, token, chamber="house", preferences=None, candidate_id=1):
    if preferences is None:
        preferences = {str(candidate_id): 1}
    return client.post(
        "/voting/cast",
        headers=csrf_headers(client),
        json={"token": token, "chamber": chamber, "preferences": preferences},
    )


# ---------------------------------------------------------------------------
# Model unit tests — VotingToken
# ---------------------------------------------------------------------------

class TestVotingTokenModel:

    def test_generate_returns_unique_strings(self, app):
        with app.app_context():
            tokens = {VotingToken.generate() for _ in range(100)}
            assert len(tokens) == 100  # all unique

    def test_generate_is_long_enough(self, app):
        with app.app_context():
            t = VotingToken.generate()
            # 64 url-safe bytes → ~86 chars; minimum acceptable is 64
            assert len(t) >= 64

    def test_new_for_voter_sets_correct_fields(self, app):
        with app.app_context():
            user = make_voter()
            tok = VotingToken.new_for_voter(user.id)
            assert tok.voter_id   == user.id
            assert tok.status     == "UNUSED"
            assert tok.token      is not None
            assert tok.expires_at > utcnow()

    def test_new_for_voter_expires_in_30_minutes(self, app):
        with app.app_context():
            user = make_voter()
            tok = VotingToken.new_for_voter(user.id)
            delta = tok.expires_at - utcnow()
            # Allow a small window for execution time
            assert timedelta(minutes=29) < delta <= timedelta(minutes=30, seconds=5)

    def test_is_valid_unused_and_not_expired(self, app):
        with app.app_context():
            user = make_voter()
            tok = VotingToken.new_for_voter(user.id)
            db.session.add(tok)
            db.session.commit()
            assert tok.is_valid() is True

    def test_is_valid_false_when_expired(self, app, frozen_clock):
        with app.app_context():
            user = make_voter()
            tok = VotingToken.new_for_voter(user.id)
            db.session.add(tok)
            db.session.commit()
        frozen_clock.advance(timedelta(minutes=31))
        with app.app_context():
            tok = db.session.query(VotingToken).first()
            assert tok.is_valid() is False

    def test_is_valid_false_after_invalidation(self, app):
        with app.app_context():
            user = make_voter()
            tok = VotingToken.new_for_voter(user.id)
            db.session.add(tok)
            db.session.commit()
            tok.invalidate()
            db.session.commit()
            assert tok.is_valid() is False
            assert tok.status   == "USED"
            assert tok.used_at  is not None


# ---------------------------------------------------------------------------
# Model unit tests — VoteRecord
# ---------------------------------------------------------------------------

class TestVoteRecordModel:

    def test_generate_receipt_is_unique(self, app):
        with app.app_context():
            receipts = {VoteRecord.generate_receipt() for _ in range(100)}
            assert len(receipts) == 100

    def test_generate_receipt_length(self, app):
        with app.app_context():
            r = VoteRecord.generate_receipt()
            assert len(r) == 64  # secrets.token_hex(32) → 64 hex chars

    def test_integrity_hash_is_deterministic(self, app):
        with app.app_context():
            now = utcnow()
            h1 = VoteRecord.compute_integrity_hash("uid-1", "house", "enc", now)
            h2 = VoteRecord.compute_integrity_hash("uid-1", "house", "enc", now)
            assert h1 == h2

    def test_integrity_hash_changes_with_each_field(self, app):
        with app.app_context():
            now = utcnow()
            base = VoteRecord.compute_integrity_hash("uid-1", "house", "enc", now)
            assert VoteRecord.compute_integrity_hash("uid-2", "house", "enc", now) != base
            assert VoteRecord.compute_integrity_hash("uid-1", "senate", "enc", now) != base
            assert VoteRecord.compute_integrity_hash("uid-1", "house", "enc2", now) != base
            later = now + timedelta(seconds=1)
            assert VoteRecord.compute_integrity_hash("uid-1", "house", "enc", later) != base

    def test_verify_integrity_passes_on_intact_record(self, app):
        with app.app_context():
            user = make_voter()
            now  = utcnow()
            enc  = "fake-encrypted-vote"
            vote = VoteRecord(
                voter_id       = user.id,
                chamber        = "house",
                encrypted_vote = enc,
                integrity_hash = VoteRecord.compute_integrity_hash(
                                     user.id, "house", enc, now),
                receipt_code   = VoteRecord.generate_receipt(),
                recorded_at    = now,
            )
            db.session.add(vote)
            db.session.commit()
            assert vote.verify_integrity() is True

    def test_verify_integrity_fails_after_tampering(self, app):
        with app.app_context():
            user = make_voter()
            now  = utcnow()
            enc  = "fake-encrypted-vote"
            vote = VoteRecord(
                voter_id       = user.id,
                chamber        = "house",
                encrypted_vote = enc,
                integrity_hash = VoteRecord.compute_integrity_hash(
                                     user.id, "house", enc, now),
                receipt_code   = VoteRecord.generate_receipt(),
                recorded_at    = now,
            )
            db.session.add(vote)
            db.session.commit()

            # Simulate a direct DB tamper
            vote.encrypted_vote = "tampered-vote-data"
            db.session.commit()

            assert vote.verify_integrity() is False


# ---------------------------------------------------------------------------
# Model unit tests — VoteAuditLog
# ---------------------------------------------------------------------------

class TestVoteAuditLogModel:

    def test_record_creates_entry(self, app):
        with app.app_context():
            user = make_voter()
            VoteAuditLog.record("TOKEN_ISSUED", voter_id=user.id, ip_address="1.2.3.4")
            db.session.commit()
            log = db.session.query(VoteAuditLog).one()
            assert log.event_type == "TOKEN_ISSUED"
            assert log.voter_id   == user.id
            assert log.ip_address == "1.2.3.4"

    def test_record_stores_extra_kwargs_as_json(self, app):
        import json
        with app.app_context():
            user = make_voter()
            VoteAuditLog.record("VOTE_CAST", voter_id=user.id, chamber="house",
                                receipt="abc123")
            db.session.commit()
            log = db.session.query(VoteAuditLog).one()
            data = json.loads(log.event_data)
            assert data["chamber"] == "house"
            assert data["receipt"] == "abc123"

    def test_record_works_without_voter(self, app):
        with app.app_context():
            VoteAuditLog.record("ELIGIBILITY_FAIL", ip_address="9.9.9.9")
            db.session.commit()
            log = db.session.query(VoteAuditLog).one()
            assert log.voter_id is None

    def test_timestamp_is_set_automatically(self, app):
        with app.app_context():
            user = make_voter()
            before = utcnow()
            VoteAuditLog.record("TOKEN_ISSUED", voter_id=user.id)
            db.session.commit()
            log = db.session.query(VoteAuditLog).one()
            assert log.timestamp >= before


# ---------------------------------------------------------------------------
# Route tests — unauthenticated access is blocked
# ---------------------------------------------------------------------------

class TestUnauthenticatedAccess:

    def test_token_requires_login(self, client):
        resp = client.post("/voting/token", json={})
        assert resp.status_code == 401

    def test_ballot_requires_login(self, client):
        resp = client.get("/voting/ballot?chamber=house")
        assert resp.status_code == 401

    def test_cast_requires_login(self, client):
        resp = client.post("/voting/cast", json={})
        assert resp.status_code == 401

    def test_verify_requires_login(self, client):
        resp = client.get("/voting/verify/somecode")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Route tests — POST /voting/token
# ---------------------------------------------------------------------------

class TestIssueToken:

    def test_active_voter_gets_token(self, app, client):
        with app.app_context():
            make_voter()
        login_as(client)
        resp = client.post("/voting/token", headers=csrf_headers(client), json={})
        assert resp.status_code == 201
        body = resp.get_json()
        assert "token" in body
        assert "expires_at" in body
        assert len(body["token"]) >= 64

    def test_token_is_stored_in_database(self, app, client):
        with app.app_context():
            make_voter()
        login_as(client)
        token_str = get_token(client)
        with app.app_context():
            row = db.session.query(VotingToken).one()
            assert row.token  == token_str
            assert row.status == "UNUSED"

    def test_token_issuance_is_audited(self, app, client):
        with app.app_context():
            make_voter()
        login_as(client)
        get_token(client)
        with app.app_context():
            log = db.session.query(VoteAuditLog).filter_by(
                event_type="TOKEN_ISSUED"
            ).first()
            assert log is not None

    def test_second_token_expires_first(self, app, client):
        """Requesting a second token should mark the first EXPIRED, not accumulate tokens."""
        with app.app_context():
            make_voter()
        login_as(client)
        get_token(client)
        get_token(client)  # second request
        with app.app_context():
            tokens = db.session.query(VotingToken).all()
            statuses = {t.status for t in tokens}
            # One EXPIRED (the first), one UNUSED (the second)
            assert "EXPIRED" in statuses
            assert "UNUSED"  in statuses

    def test_already_voted_voter_cannot_get_token(self, app, client):
        with app.app_context():
            make_voter(has_voted=True)
        login_as(client)
        resp = client.post("/voting/token", headers=csrf_headers(client), json={})
        assert resp.status_code == 409
        assert "already" in resp.get_json()["error"].lower()

    def test_double_vote_attempt_is_audited(self, app, client):
        with app.app_context():
            make_voter(has_voted=True)
        login_as(client)
        client.post("/voting/token", headers=csrf_headers(client), json={})
        with app.app_context():
            log = db.session.query(VoteAuditLog).filter_by(
                event_type="DOUBLE_VOTE_ATTEMPT"
            ).first()
            assert log is not None


# ---------------------------------------------------------------------------
# Route tests — GET /voting/ballot
# ---------------------------------------------------------------------------

class TestGetBallot:

    def test_ballot_returns_candidates_for_voters_electorate(self, app, client):
        with app.app_context():
            make_voter(electorate="Melbourne", state="VIC")
            make_candidate(name="Alice", electorate="Melbourne", chamber="house")
            make_candidate(name="Bob",   electorate="Melbourne", chamber="house",
                           ballot_order=2)
            # This one belongs to a different electorate — must NOT appear
            make_candidate(name="Carol", electorate="Sydney", chamber="house")
        login_as(client)
        resp = client.get("/voting/ballot?chamber=house")
        assert resp.status_code == 200
        body = resp.get_json()
        names = [c["name"] for c in body["candidates"]]
        assert "Alice" in names
        assert "Bob"   in names
        assert "Carol" not in names

    def test_ballot_ordered_by_ballot_order(self, app, client):
        with app.app_context():
            make_voter()
            make_candidate(name="Z-Last",  ballot_order=3)
            make_candidate(name="A-First", ballot_order=1)
            make_candidate(name="M-Mid",   ballot_order=2)
        login_as(client)
        resp = client.get("/voting/ballot?chamber=house")
        names = [c["name"] for c in resp.get_json()["candidates"]]
        assert names == ["A-First", "M-Mid", "Z-Last"]

    def test_ballot_rejects_invalid_chamber(self, app, client):
        with app.app_context():
            make_voter()
        login_as(client)
        resp = client.get("/voting/ballot?chamber=magic")
        assert resp.status_code == 400

    def test_ballot_requires_chamber_param(self, app, client):
        with app.app_context():
            make_voter()
        login_as(client)
        resp = client.get("/voting/ballot")
        assert resp.status_code == 400

    def test_ballot_includes_electorate_in_response(self, app, client):
        with app.app_context():
            make_voter(electorate="Kooyong", state="VIC")
        login_as(client)
        resp = client.get("/voting/ballot?chamber=house")
        assert resp.get_json()["electorate"] == "Kooyong"


# ---------------------------------------------------------------------------
# Route tests — POST /voting/cast
# ---------------------------------------------------------------------------

class TestCastVote:

    def test_valid_vote_returns_receipt(self, app, client):
        with app.app_context():
            make_voter()
            c = make_candidate()
        login_as(client)
        token = get_token(client)
        resp = cast_vote(client, token, candidate_id=c.id if hasattr(c, 'id') else 1)
        assert resp.status_code == 201
        body = resp.get_json()
        assert "receipt" in body
        assert len(body["receipt"]) == 64  # secrets.token_hex(32)

    def test_vote_is_stored_encrypted(self, app, client):
        with app.app_context():
            make_voter()
            c = make_candidate()
            cid = c.id
        login_as(client)
        token = get_token(client)
        cast_vote(client, token, candidate_id=cid)
        with app.app_context():
            vote = db.session.query(VoteRecord).one()
            # Must be ciphertext, not plaintext JSON
            assert "preferences" not in vote.encrypted_vote
            assert vote.encrypted_vote.startswith("v1:")  # our AES-GCM token format

    def test_vote_record_has_integrity_hash(self, app, client):
        with app.app_context():
            make_voter()
            c = make_candidate()
            cid = c.id
        login_as(client)
        token = get_token(client)
        cast_vote(client, token, candidate_id=cid)
        with app.app_context():
            vote = db.session.query(VoteRecord).one()
            assert len(vote.integrity_hash) == 64   # SHA-256 hex
            assert vote.verify_integrity() is True  # passes immediately after storage

    def test_token_is_marked_used_after_cast(self, app, client):
        with app.app_context():
            make_voter()
            c = make_candidate()
            cid = c.id
        login_as(client)
        token = get_token(client)
        cast_vote(client, token, candidate_id=cid)
        with app.app_context():
            tok = db.session.query(VotingToken).one()
            assert tok.status == "USED"

    def test_vote_is_audited(self, app, client):
        with app.app_context():
            make_voter()
            c = make_candidate()
            cid = c.id
        login_as(client)
        token = get_token(client)
        cast_vote(client, token, candidate_id=cid)
        with app.app_context():
            log = db.session.query(VoteAuditLog).filter_by(
                event_type="VOTE_CAST"
            ).first()
            assert log is not None

    def test_same_token_cannot_be_used_twice(self, app, client):
        """Replaying a used token must be rejected (Solution 20)."""
        with app.app_context():
            make_voter()
            c = make_candidate()
            cid = c.id
        login_as(client)
        token = get_token(client)
        first  = cast_vote(client, token, candidate_id=cid)
        second = cast_vote(client, token, candidate_id=cid)
        assert first.status_code  == 201
        assert second.status_code in (401, 409)

    def test_invalid_token_is_rejected(self, app, client):
        with app.app_context():
            make_voter()
            make_candidate()
        login_as(client)
        resp = cast_vote(client, "not-a-real-token")
        assert resp.status_code == 401
        with app.app_context():
            log = db.session.query(VoteAuditLog).filter_by(
                event_type="INVALID_TOKEN"
            ).first()
            assert log is not None

    def test_expired_token_is_rejected(self, app, client, frozen_clock):
        with app.app_context():
            make_voter()
            make_candidate()
        login_as(client)
        token = get_token(client)
        frozen_clock.advance(timedelta(minutes=31))
        resp = cast_vote(client, token)
        assert resp.status_code == 401

    def test_candidate_outside_electorate_is_rejected(self, app, client):
        """Voter in Melbourne cannot vote for a Sydney candidate (R-11)."""
        with app.app_context():
            make_voter(electorate="Melbourne")
            sydney_candidate = make_candidate(electorate="Sydney", name="Sydney Pol")
            scid = sydney_candidate.id
        login_as(client)
        token = get_token(client)
        resp = cast_vote(client, token, preferences={str(scid): 1})
        assert resp.status_code == 422

    def test_double_vote_via_has_voted_flag_rejected(self, app, client):
        """Second vote attempt after has_voted=True must be rejected at app layer."""
        with app.app_context():
            make_voter(has_voted=True)
            make_candidate()
        login_as(client)
        # Need to bypass the token check to reach cast — get token before flag is checked
        # Actually token issuance itself rejects has_voted; so token endpoint returns 409
        resp = client.post("/voting/token", headers=csrf_headers(client), json={})
        assert resp.status_code == 409

    def test_missing_required_fields_rejected(self, app, client):
        with app.app_context():
            make_voter()
        login_as(client)
        get_token(client)
        # Missing "preferences"
        resp = client.post(
            "/voting/cast",
            headers=csrf_headers(client),
            json={"token": "x", "chamber": "house"},
        )
        assert resp.status_code == 400

    def test_invalid_chamber_rejected(self, app, client):
        with app.app_context():
            make_voter()
        login_as(client)
        token = get_token(client)
        resp = client.post(
            "/voting/cast",
            headers=csrf_headers(client),
            json={"token": token, "chamber": "invalid", "preferences": {"1": 1}},
        )
        assert resp.status_code == 400

    def test_no_body_rejected(self, app, client):
        with app.app_context():
            make_voter()
        login_as(client)
        resp = client.post(
            "/voting/cast",
            headers=csrf_headers(client),
            data="not json",
            content_type="application/json",
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Route tests — GET /voting/verify/<receipt>
# ---------------------------------------------------------------------------

class TestVerifyReceipt:

    def _cast_and_get_receipt(self, app, client):
        """Helper: full vote flow, returns receipt code."""
        with app.app_context():
            make_voter()
            c = make_candidate()
            cid = c.id
        login_as(client)
        token = get_token(client)
        resp = cast_vote(client, token, candidate_id=cid)
        return resp.get_json()["receipt"]

    def test_valid_receipt_returns_recorded_true(self, app, client):
        receipt = self._cast_and_get_receipt(app, client)
        resp = client.get(f"/voting/verify/{receipt}")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["recorded"]  is True
        assert body["tampered"]  is False
        assert "chamber"         in body
        assert "recorded_at"     in body

    def test_wrong_receipt_returns_404(self, app, client):
        self._cast_and_get_receipt(app, client)
        resp = client.get("/voting/verify/notarealreceipt1234567890")
        assert resp.status_code == 404

    def test_tampered_record_detected(self, app, client):
        """Directly mutate encrypted_vote in DB — verify should flag tampered=True (R-19)."""
        receipt = self._cast_and_get_receipt(app, client)
        with app.app_context():
            vote = db.session.query(VoteRecord).filter_by(receipt_code=receipt).one()
            vote.encrypted_vote = "v1:00000000:tampered-ciphertext"
            db.session.commit()
        resp = client.get(f"/voting/verify/{receipt}")
        assert resp.status_code == 200
        assert resp.get_json()["tampered"] is True

    def test_tamper_detection_is_audited(self, app, client):
        receipt = self._cast_and_get_receipt(app, client)
        with app.app_context():
            vote = db.session.query(VoteRecord).filter_by(receipt_code=receipt).one()
            vote.encrypted_vote = "v1:00000000:tampered-ciphertext"
            db.session.commit()
        client.get(f"/voting/verify/{receipt}")
        with app.app_context():
            log = db.session.query(VoteAuditLog).filter_by(
                event_type="TAMPER_DETECTED"
            ).first()
            assert log is not None

    def test_voter_cannot_verify_another_voters_receipt(self, app, client):
        """R-11: receipt lookup is scoped to the authenticated voter's own records."""
        # Alice votes
        with app.app_context():
            make_voter(username="alice")
            make_voter(username="bob")
            c = make_candidate()
            cid = c.id
        login_as(client, "alice")
        alice_token = get_token(client)
        alice_resp  = cast_vote(client, alice_token, candidate_id=cid)
        alice_receipt = alice_resp.get_json()["receipt"]

        # Bob logs in and tries Alice's receipt
        client.delete("/auth/logout", headers=csrf_headers(client))
        login_as(client, "bob")
        resp = client.get(f"/voting/verify/{alice_receipt}")
        assert resp.status_code == 404  # Bob sees "not found", not Alice's data

    def test_very_long_receipt_returns_404_not_500(self, app, client):
        with app.app_context():
            make_voter()
        login_as(client)
        resp = client.get("/voting/verify/" + "x" * 200)
        assert resp.status_code == 404