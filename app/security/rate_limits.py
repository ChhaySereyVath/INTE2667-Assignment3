"""R06: rate limiting, so one person or one computer cannot flood the service.

Signed-in requests are counted per ACCOUNT (an attacker cannot dodge the limit by
changing IP address, and voters behind one shared polling-place connection do not
use up each other's allowance). Anonymous requests are counted per IP address.
"""
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

DEFAULT_LIMIT = "300 per minute"


def rate_key():
    """The identity a request is counted against: the account, else the IP."""
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
    except Exception:  # an expired or revoked token is just an anonymous request here
        user_id = None
    return f"user:{user_id}" if user_id else f"ip:{get_remote_address()}"


limiter = Limiter(key_func=rate_key, default_limits=[DEFAULT_LIMIT],
                  storage_uri="memory://", headers_enabled=True)

# Tighter limits for the endpoints attackers aim at. Login, registration and
# recovery are counted per IP (there is no account yet); voting per account.
ROUTE_LIMITS = {
    "auth.login": ("10 per minute", get_remote_address),
    "auth.register": ("5 per minute", get_remote_address),
    "auth.activate": ("10 per minute", get_remote_address),
    "recovery.request_recovery": ("3 per minute", get_remote_address),
    "recovery.confirm_recovery": ("5 per minute", get_remote_address),
    "voting.eligibility": ("20 per minute", rate_key),
    "voting.cast_ballot": ("5 per minute", rate_key),
}


def install_rate_limits(app):
    """Attach the limiter after every blueprint is registered, then apply the
    per-route limits from the one table above (so no route file needs editing)."""
    for endpoint, (rule, key) in ROUTE_LIMITS.items():
        if endpoint in app.view_functions:
            app.view_functions[endpoint] = limiter.limit(rule, key_func=key)(app.view_functions[endpoint])
    limiter.init_app(app)
    # static files (CSS, JS) are not worth counting
    limiter.exempt(app.view_functions["static"])
