"""R15: privileged actions bound to a verified person and signed by the server.

Each record says who (account, role and the MFA-verified session they used), did
what, to which target, with what details, when, and whether it succeeded. The server
signs all of that with ACTION_SIGNING_KEY (Ed25519). Anyone with the PUBLIC key can
later check every record, so an edited record, or one inserted by someone without
the key, is exposed.
"""
import uuid
from datetime import timedelta
from functools import wraps

import click
from flask import current_app, g, jsonify
from flask.cli import with_appcontext

from app import db
from app.models.audit_models import SignedAction
from app.security.audit_security import append_event
from app.security.shared_security import utcnow
from app.security.signing import canonical_json, public_key_hex, sign, verify

# signed action -> the audit event that goes with it (R13)
SIGNED_ACTIONS = {
    "candidate_create": "candidate_change",
    "candidate_update": "candidate_change",
    "candidate_withdraw": "candidate_change",
    "count_run": "count_run",
    "exclusion_propose": "exclusion_proposed",
    "exclusion_confirm": "exclusion_confirmed",
    "result_approve": "result_approved",
}
OUTCOMES = ("success", "denied", "failure")

def record_signed_action(actor, action, target_type, target_id, payload, outcome):
    """Sign and store one action, plus its audit event. The caller commits, so the
    action and its record are saved together or not at all."""
    if action not in SIGNED_ACTIONS or outcome not in OUTCOMES:
        raise ValueError("unknown signed action or outcome")
    row = SignedAction(
        id=str(uuid.uuid4()),
        actor_id=actor.id,
        actor_role=actor.role,
        session_id=g.current_session.id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        payload=canonical_json(payload),
        outcome=outcome,
        signed_at=utcnow(),
    )
    row.signature = sign(row.signed_fields(), "ACTION_SIGNING_KEY")
    db.session.add(row)
    append_event(SIGNED_ACTIONS[action], "success" if outcome == "success" else outcome,
                 actor, target_type, target_id)
    return row


def verify_actions():
    """Check every signed record with the public key. Returns the problems found."""
    public = public_key_hex("ACTION_SIGNING_KEY")
    return [f"signed action {row.id} fails verification"
            for row in SignedAction.query.order_by(SignedAction.signed_at).all()
            if not verify(row.signed_fields(), row.signature, public)]