"""
R02 - Redact PII in logs and error messages
Covers : Name , DOB, Address, Email, VoterID, Phone
"""

import re
import logging

# Setting which fields is considered PII and should be redacted in logs and error messages
PII_FIELDS = ['full_name','first_name', 'last_name', 'email', 'address', 'dob', 'phone', 'voter_id', 'password', 'token', 'medicare', 'passport', 'voting_token' ]

_PII_PATTERN = re.compile(
    r'("(?:' + "|".join(PII_FIELDS) + r')")\s*:\s*("(?:[^"\\]|\\.)*"|\S+)',
    re.IGNORECASE
)
#----------------------------------------------------
# ReplacePII Field Values in a string with [REDACTED]
#----------------------------------------------------
class PIIRedactionFilter(logging.Filter):
    def redact_pii(text):
        return _PII_PATTERN.sub(r'\1: "[REDACTED]"', text)

    # ADDING A LOGGING FILTER

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_pii(str(record.msg))

        # Redacting any string arguments passed to the logger
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_pii(v) for k, v in record.args.items()}

        elif isinstance(record.args, tuple):
            record.args = tuple(redact_pii(str(arg)) for arg in record.args)
        return True

# Attaching filter to Flask's logger

# This is API is called in create_app() after the app is creaeted.
# It attaches the PII redaction filter to every log handler. 
def init_pii_filter(app):

    pii_filter = PIIRedactionFilter()

    # Applying to Flask's own logger
    app.logger.addFilter(pii_filter)

    # Apply to the root logger so Werkzeug and SQLAlchemy logs are also filtered
    root_logger = logging.getLogger()
    root_logger.addFilter(pii_filter)

    # Also apply to the Werkzeug request logger specifically
    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.addFilter(pii_filter)


