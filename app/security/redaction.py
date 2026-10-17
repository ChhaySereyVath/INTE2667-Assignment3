"""R02: keep personal and secret values out of every log line.

A filter on the app's loggers rewrites each message before it is written. It is a
safety net: code should log ids only, but if a value slips through (an exception
message, a library's debug line), it is masked here.
"""
import logging
import re
import uuid

from flask import g, has_request_context

MASK = "[redacted]"

# key=value, key: value or "key": "value" for any key that names something sensitive
SENSITIVE_KEYS = (r"password|passwd|token|secret|authorization|cookie|csrf|api_key|"
                  r"date_of_birth|dob|address_line|address|suburb|postcode|given_name|"
                  r"family_name|email|preferences|signature")
KEY_VALUE = re.compile(
    r"""(?P<key>["']?(?:\w*?)(?:""" + SENSITIVE_KEYS + r""")\w*["']?\s*[=:]\s*)"""
    r"""(?P<value>"[^"]*"|'[^']*'|[^\s,;&}]+)""",
    re.IGNORECASE,
)
PATTERNS = (
    re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"),                      # JSON Web Tokens
    re.compile(r"(?i)bearer\s+[\w.-]+"),                            # Authorization headers
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # email addresses
)


def redact(text):
    """Return `text` with sensitive values replaced by [redacted]."""
    for pattern in PATTERNS:  # first, so "Authorization: Bearer x" loses the whole token
        text = pattern.sub(MASK, text)
    return KEY_VALUE.sub(lambda m: m.group("key") + MASK, text)


class RedactingFilter(logging.Filter):
    """Attached to a logger: formats the message once, redacts it, and passes it on."""

    def filter(self, record):
        record.msg = redact(record.getMessage())
        record.args = ()
        if record.exc_info:
            # the traceback text can quote the exception message: redact that too
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        if has_request_context() and "request_id" in g:
            record.msg = f"request_id={g.request_id} {record.msg}"
        return True


REDACTED_LOGGERS = ("evp.security", "werkzeug", "sqlalchemy")


def install_redaction(app):
    """Put the filter on the app's logger and on the other loggers we write to."""
    redacting = RedactingFilter()
    for logger in [app.logger] + [logging.getLogger(name) for name in REDACTED_LOGGERS]:
        if not any(isinstance(f, RedactingFilter) for f in logger.filters):
            logger.addFilter(redacting)


def new_request_id():
    """R02: a random id that links an error message to its log line, without the
    message having to contain anything else."""
    return uuid.uuid4().hex
