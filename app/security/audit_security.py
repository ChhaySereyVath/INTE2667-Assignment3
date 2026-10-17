"""R13/R14: the tamper-evident audit trail.

Every event stores the hash of the event before it, so changing, deleting or
reordering any event breaks the chain from that point on. Signed "anchors" written to
a separate file catch the one thing a chain alone cannot: someone rebuilding the
whole chain from scratch, or cutting events off the end.
"""
import hashlib
import json
import logging
from pathlib import Path

import click
from flask import current_app
from flask.cli import with_appcontext
from sqlalchemy import select, update

from app import db
from app.models.audit_models import AUDIT_ACTIONS, GENESIS_HASH, RESULTS, AuditEvent, AuditHead
from app.security.shared_security import utcnow
from app.security.signing import canonical_json


def _hashable_fields(event):
    """Everything about an event except its own hash."""
    return {
        "seq": event.seq,
        "occurred_at": event.occurred_at.isoformat(),
        "actor_id": event.actor_id,
        "actor_role": event.actor_role,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "result": event.result,
        "details": event.details,
    }


def compute_hash(prev_hash, event):
    """R14: record_hash = SHA-256(previous hash + this event as canonical JSON)."""
    data = prev_hash + canonical_json(_hashable_fields(event))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def append_event(action, result, actor=None, target_type=None, target_id=None, **details):
    """R13: add one event to the trail. The caller commits, so the event is saved in
    the same transaction as the change it describes (both happen, or neither)."""
    if action not in AUDIT_ACTIONS or result not in RESULTS:
        raise ValueError("unknown audit action or result")
    # R14: write to the head row FIRST. The database lets one request at a time past
    # this line, so each event gets its own seq and the true previous hash.
    db.session.execute(update(AuditHead).where(AuditHead.id == 1).values(seq=AuditHead.seq + 1))
    seq, prev_hash = db.session.execute(
        select(AuditHead.seq, AuditHead.record_hash).where(AuditHead.id == 1)).one()
    event = AuditEvent(
        seq=seq,
        occurred_at=utcnow(),
        actor_id=actor.id if actor is not None else None,
        actor_role=actor.role if actor is not None else None,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        result=result,
        details=canonical_json(details),
        prev_hash=prev_hash,
    )
    event.record_hash = compute_hash(event.prev_hash, event)
    db.session.execute(update(AuditHead).where(AuditHead.id == 1).values(record_hash=event.record_hash))
    db.session.add(event)
    db.session.flush()  # the next append in this request sees this one
    return event
