"""R08: phishing-resistant MFA with WebAuthn (FIDO2 security keys and passkeys).
We need WebAuthn for phishing resistance because a password alone is not enough for privileged actions (R08).
The browser and the key sign with a private key that never leave device and the server checks with the public key we stored. 
The signature includes the real website address, so a fake site cannot get a valid signature.

"""
import secrets
from datetime import timedelta

from flask import current_app
from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
                                      PublicKeyCredentialDescriptor,
                                      UserVerificationRequirement)

from app import db
from app.models.auth_models import MfaChallenge, WebAuthnCredential
from app.security.shared_security import utcnow


def has_security_key(user):
    return WebAuthnCredential.query.filter_by(user_id=user.id).first() is not None


def _new_challenge(user, session_row, purpose):
    """A fresh 32-byte random challenge, stored so the answer can be checked once."""
    raw = secrets.token_bytes(32)
    seconds = current_app.config["MFA_CHALLENGE_SECONDS"]
    db.session.add(MfaChallenge(
        user_id=user.id,
        session_id=session_row.id,
        purpose=purpose,
        challenge=bytes_to_base64url(raw),
        expires_at=utcnow() + timedelta(seconds=seconds),
    ))
    db.session.commit()
    return raw


def _take_challenge(user, session_row, purpose):
    """R08: the newest unused challenge for THIS session, if still in date.

    It is marked used before anything else happens, so whatever the outcome it can
    never be answered a second time.
    """
    row = (MfaChallenge.query
           .filter_by(user_id=user.id, session_id=session_row.id, purpose=purpose, used_at=None)
           .order_by(MfaChallenge.created_at.desc())
           .first())
    if row is None:
        return None
    row.used_at = utcnow()
    db.session.commit()
    if row.expires_at <= row.used_at:
        return None  # expired
    return base64url_to_bytes(row.challenge)


def _options_dict(options):
    import json

    return json.loads(options_to_json(options))


def registration_options(user, session_row):
    """Step 1 of adding a key: what the browser passes to navigator.credentials.create()."""
    existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(row.credential_id))
                for row in WebAuthnCredential.query.filter_by(user_id=user.id).all()]
    options = generate_registration_options(
        rp_id=current_app.config["WEBAUTHN_RP_ID"],
        rp_name=current_app.config["WEBAUTHN_RP_NAME"],
        user_id=user.id.encode("ascii"),
        user_name=user.username,
        challenge=_new_challenge(user, session_row, "register"),
        timeout=current_app.config["MFA_CHALLENGE_SECONDS"] * 1000,
        exclude_credentials=existing,  # the same key cannot be registered twice
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED),
    )
    return _options_dict(options)


def finish_registration(user, session_row, credential):
    """Step 2: check the new key's answer and store its public key. True if accepted."""
    challenge = _take_challenge(user, session_row, "register")
    if challenge is None:
        return False
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=current_app.config["WEBAUTHN_RP_ID"],
            expected_origin=current_app.config["WEBAUTHN_ORIGIN"],
        )
    except Exception:  # noqa: BLE001 - fail closed: ANY problem means no key is added
        return False
    db.session.add(WebAuthnCredential(
        user_id=user.id,
        credential_id=bytes_to_base64url(verified.credential_id),
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
    ))
    db.session.commit()
    return True


def authentication_options(user, session_row):
    """Step 1 of signing in with a key: what the browser passes to navigator.credentials.get()."""
    allowed = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(row.credential_id))
               for row in WebAuthnCredential.query.filter_by(user_id=user.id).all()]
    options = generate_authentication_options(
        rp_id=current_app.config["WEBAUTHN_RP_ID"],
        challenge=_new_challenge(user, session_row, "authenticate"),
        timeout=current_app.config["MFA_CHALLENGE_SECONDS"] * 1000,
        allow_credentials=allowed,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return _options_dict(options)


def finish_authentication(user, session_row, credential):
    """Step 2: check the signature against the stored public key. True if accepted.

    The library also checks the origin (phishing), the RP ID, the challenge, and
    that the key's signature counter went up (a cloned key repeats old counts).
    """
    challenge = _take_challenge(user, session_row, "authenticate")
    if challenge is None:
        return False
    credential_id = credential.get("id") if isinstance(credential, dict) else None
    stored = WebAuthnCredential.query.filter_by(user_id=user.id, credential_id=credential_id).first()
    if stored is None:
        return False  # not one of THIS user's keys
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=current_app.config["WEBAUTHN_RP_ID"],
            expected_origin=current_app.config["WEBAUTHN_ORIGIN"],
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
        )
    except Exception:  # noqa: BLE001 - fail closed: ANY problem means MFA failed
        return False
    stored.sign_count = verified.new_sign_count
    stored.last_used_at = utcnow()
    db.session.commit()
    return True