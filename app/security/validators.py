"""R04: server-side allowlist validation for every JSON request body (Part 2 solution S01).

Usage:
    SCHEMA = {
        "postcode": {"type": str, "required": True, "pattern": POSTCODE_RE},
        "state":    {"type": str, "required": True, "enum": STATES},
    }
    ok, cleaned, errors = validate(request.get_json(silent=True), SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400
"""
import re
import uuid
from datetime import date


def validate(data, schema):
    """Check a JSON body against a schema. Returns (ok, cleaned, errors).

    - The body must be a JSON object; any field not in the schema is rejected.
    - Error messages describe the rule, never the submitted value (R02).
    - cleaned holds the converted values (e.g. a date object) only when ok is True.
    """
    if not isinstance(data, dict):
        return False, {}, {"_body": "must be a JSON object"}

    errors = {}
    cleaned = {}
    for field in data:
        if field not in schema:
            errors[field] = "unknown field"  # stops clients sending e.g. "role" or "status"

    for field, rule in schema.items():
        value = data.get(field)
        if value is None or value == "":
            if rule.get("required"):
                errors[field] = "required"
            continue
        ok, result = _check(value, rule)
        if ok:
            cleaned[field] = result
        else:
            errors[field] = result

    if errors:
        return False, {}, errors
    return True, cleaned, {}


def _check(value, rule):
    """Check one value. Returns (True, converted value) or (False, error message)."""
    kind = rule.get("type", str)

    if kind is str:
        if not isinstance(value, str):
            return False, "must be text"

        value = value.strip()

        if "min" in rule and len(value) < rule["min"]:
            return False, f"must be at least {rule['min']} characters"

        if "max" in rule and len(value) > rule["max"]:
            return False, f"must be at most {rule['max']} characters"

        if "pattern" in rule and not rule["pattern"].fullmatch(value):
            return False, "has an invalid format"

        if "enum" in rule and value not in rule["enum"]:
            return False, "is not an allowed value"
        
        return True, value

    if kind is int:
        # bool is a subclass of int in Python, so True/False must be rejected explicitly
        if isinstance(value, bool) or not isinstance(value, int):
            return False, "must be a whole number"

        if "min" in rule and value < rule["min"]:
            return False, f"must be at least {rule['min']}"

        if "max" in rule and value > rule["max"]:
            return False, f"must be at most {rule['max']}"

        if "enum" in rule and value not in rule["enum"]:
            return False, "is not an allowed value"

        return True, value

    if kind is bool:
        if not isinstance(value, bool):
            return False, "must be true or false"

        return True, value

    if kind is list:
        if not isinstance(value, list):
            return False, "must be a list"

        if "max" in rule and len(value) > rule["max"]:
            return False, f"must have at most {rule['max']} items"

        return True, value

    if kind == "uuid":
        if not isinstance(value, str):
            return False, "must be an id"
        try:
            return True, uuid.UUID(value)
        except ValueError:
            return False, "must be an id"

    if kind == "date":
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return False, "must be a date (YYYY-MM-DD)"
        try:
            parsed = date.fromisoformat(value)
        except ValueError:
            return False, "must be a real date"
        if "min" in rule and parsed < rule["min"]:
            return False, "is too early"
        if "max" in rule and parsed > rule["max"]:
            return False, "is too late"
        return True, parsed

    return False, "has an unsupported type"