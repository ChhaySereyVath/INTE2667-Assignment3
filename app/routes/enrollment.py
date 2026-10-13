"""Enrolment endpoints: /enrollment/... (R03, R04, R05, R11).

Routes do three things only: validate the body, call an enrolment function, return
JSON. Every access decision lives in app/security/enrollment_security.py.
"""
from datetime import date

from flask import Blueprint, jsonify, request

from app import db
from app.models.enrollment_models import Enrolment
from app.security.enrollment_security import get_scoped_or_404, identity_key, record_change
from app.security.shared_security import permission_required, utcnow
from app.security.validators import ADDRESS_RE, NAME_RE, POSTCODE_RE, STATES, validate

enrollment_bp = Blueprint("enrollment", __name__)

# R16 (Yufei's requirement) only accepts an enrolment from an adult; the date rule
# here is the input check, not the eligibility decision.
EARLIEST_DOB = date(1900, 1, 1)

ENROL_SCHEMA = {
    "given_name": {"type": str, "required": True, "pattern": NAME_RE},
    "family_name": {"type": str, "required": True, "pattern": NAME_RE},
    "date_of_birth": {"type": "date", "required": True, "min": EARLIEST_DOB},
    "address_line": {"type": str, "required": True, "pattern": ADDRESS_RE},
    "suburb": {"type": str, "required": True, "pattern": NAME_RE},
    "postcode": {"type": str, "required": True, "pattern": POSTCODE_RE},
    "state": {"type": str, "required": True, "enum": STATES},
}

ADDRESS_SCHEMA = {
    "address_line": {"type": str, "required": True, "pattern": ADDRESS_RE},
    "suburb": {"type": str, "required": True, "pattern": NAME_RE},
    "postcode": {"type": str, "required": True, "pattern": POSTCODE_RE},
    "state": {"type": str, "required": True, "enum": STATES},
}

def _write_enrolment(enrolment, cleaned):
    """Encrypt each field onto the row. The row must already have its id."""
    for field in ("given_name", "family_name", "address_line", "suburb", "postcode"):
        enrolment.set_field(field, cleaned[field])
    enrolment.set_field("date_of_birth", cleaned["date_of_birth"].isoformat())
    enrolment.state = cleaned["state"]


def _create_enrolment(owner_id, cleaned, actor, registered_by=None):
    """Shared by self-enrolment and staff registration. Returns (enrolment, error)."""
    if Enrolment.query.filter_by(user_id=owner_id).first() is not None:
        return None, "already enrolled"
    key = identity_key(cleaned["given_name"], cleaned["family_name"],
                       cleaned["date_of_birth"].isoformat())
    if Enrolment.query.filter_by(identity_bidx=key).first() is not None:
        return None, "already enrolled"

    enrolment = Enrolment(user_id=owner_id, identity_bidx=key, status="pending",
                          registered_by=registered_by, state=cleaned["state"],
                          given_name_enc="", family_name_enc="", date_of_birth_enc="",
                          address_line_enc="", suburb_enc="", postcode_enc="")
    db.session.add(enrolment)
    db.session.flush()  # R01: the id is part of what each field is encrypted against
    _write_enrolment(enrolment, cleaned)
    record_change(enrolment, actor, "created", "enrolment", None, "pending")
    db.session.commit()
    return enrolment, None


@enrollment_bp.route("/me", methods=["GET"])
@permission_required("enrolment:self:read")
def read_own_enrolment(current_user):
    """R03: a citizen checks their own enrolment."""
    enrolment = Enrolment.query.filter_by(user_id=current_user.id).first()
    if enrolment is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"enrolment": enrolment.to_dict()}), 200


@enrollment_bp.route("/me", methods=["POST"])
@permission_required("enrolment:self:enrol")
def self_enrol(current_user):
    """R03: a citizen enrols themselves. The record starts as pending."""
    ok, cleaned, errors = validate(request.get_json(silent=True), ENROL_SCHEMA)
    if not ok:
        # R04: a failed validation must not write anything at all
        return jsonify({"error": "Invalid request", "fields": errors}), 400

    enrolment, problem = _create_enrolment(current_user.id, cleaned, current_user)
    if problem is not None:
        return jsonify({"error": "Already enrolled"}), 409
    return jsonify({"enrolment": enrolment.to_dict()}), 201

@enrollment_bp.route("/me/address", methods=["PATCH"])
@permission_required("enrolment:self:update_address")
def update_own_address(current_user):
    """R03/R05: a citizen updates their own address; every field change is recorded."""
    ok, cleaned, errors = validate(request.get_json(silent=True), ADDRESS_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400

    enrolment = Enrolment.query.filter_by(user_id=current_user.id).first()
    if enrolment is None:
        return jsonify({"error": "Not found"}), 404

    for field in ("address_line", "suburb", "postcode"):
        old = enrolment.get_field(field)
        if old != cleaned[field]:
            record_change(enrolment, current_user, "address_update", field, old, cleaned[field])
            enrolment.set_field(field, cleaned[field])
    if enrolment.state != cleaned["state"]:
        record_change(enrolment, current_user, "address_update", "state",
                      enrolment.state, cleaned["state"])
        enrolment.state = cleaned["state"]
    enrolment.updated_at = utcnow()
    db.session.commit()
    return jsonify({"enrolment": enrolment.to_dict()}), 200

@enrollment_bp.route("/<record_id>", methods=["GET"])
@permission_required("enrolment:staff:read")
def staff_read_enrolment(current_user, record_id):
    """R11: a staff member reads a record, but only in a state they are assigned to."""
    enrolment = get_scoped_or_404(record_id, current_user, "read")
    return jsonify({"enrolment": enrolment.to_dict()}), 200