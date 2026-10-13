"""R04: invalid types, lengths, formats and values are rejected on the server."""
import uuid
from datetime import date
from app.security.validators import (
    ADDRESS_RE,
    EMAIL_RE,
    NAME_RE,
    POSTCODE_RE,
    STATES,
    USERNAME_RE,
    validate,
)

SIMPLE_SCHEMA = {
    "name": {"type": str, "required": True, "max": 20},
    "suburb": {"type": str},
}


def test_valid_body_passes_and_is_cleaned():
    ok, cleaned, errors = validate({"name": "  Alex  ", "suburb": "Carlton"}, SIMPLE_SCHEMA)
    assert ok and errors == {}
    assert cleaned == {"name": "Alex", "suburb": "Carlton"}


def test_body_must_be_an_object():
    for body in (None, [], "text", 5):
        ok, _, errors = validate(body, SIMPLE_SCHEMA)
        assert not ok and "_body" in errors


def test_unknown_fields_are_rejected():
    ok, _, errors = validate({"name": "Alex", "role": "administrator"}, SIMPLE_SCHEMA)
    assert not ok and errors == {"role": "unknown field"}


def test_missing_required_field():
    ok, _, errors = validate({"suburb": "Carlton"}, SIMPLE_SCHEMA)
    assert not ok and errors == {"name": "required"}


def test_errors_never_repeat_the_submitted_value():
    sneaky = "<script>steal(document.cookie)</script>"
    ok, _, errors = validate({"name": sneaky}, SIMPLE_SCHEMA)
    assert not ok
    assert sneaky not in str(errors)

def test_types_lengths_ranges_and_enums():
    schema = {"age": {"type": int, "min": 18, "max": 120}, "name": {"type": str, "max": 5},
              "agree": {"type": bool}, "tags": {"type": list, "max": 2},
              "state": {"type": str, "enum": ("NSW", "VIC")}}
    assert validate({"age": 30, "name": "Al", "agree": True, "tags": ["a"], "state": "NSW"}, schema)[0]
    assert validate({"age": True}, schema)[2] == {"age": "must be a whole number"}  # bool is not int
    assert validate({"age": "30"}, schema)[2] == {"age": "must be a whole number"}
    assert validate({"age": 17}, schema)[2] == {"age": "must be at least 18"}
    assert validate({"name": "toolong"}, schema)[2] == {"name": "must be at most 5 characters"}
    assert validate({"name": ["list"]}, schema)[2] == {"name": "must be text"}
    assert validate({"agree": "yes"}, schema)[2] == {"agree": "must be true or false"}
    assert validate({"tags": ["a", "b", "c"]}, schema)[2] == {"tags": "must have at most 2 items"}
    assert validate({"state": "XYZ"}, schema)[2] == {"state": "is not an allowed value"}

def test_uuid_and_date_rules():
    schema = {"id": {"type": "uuid"}, "dob": {"type": "date", "max": date(2026, 1, 1)}}
    new_id = str(uuid.uuid4())
    ok, cleaned, _ = validate({"id": new_id, "dob": "1990-04-12"}, schema)
    assert ok and cleaned["dob"] == date(1990, 4, 12) and str(cleaned["id"]) == new_id
    assert not validate({"id": "12345"}, schema)[0]
    assert not validate({"dob": "12/04/1990"}, schema)[0]
    assert not validate({"dob": "1990-02-30"}, schema)[0]  # not a real date
    assert not validate({"dob": "2030-01-01"}, schema)[0]  # after the max date

ADDRESS_SCHEMA = {
    "address_line": {"type": str, "required": True, "pattern": ADDRESS_RE},
    "postcode": {"type": str, "required": True, "pattern": POSTCODE_RE},
    "state": {"type": str, "required": True, "enum": STATES},
}

SQL_INJECTION = [
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "1 UNION SELECT password_hash FROM users",
]

XSS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)"
]

def test_address_schema_accepts_a_real_address():
    body = {"address_line": "Unit 4/12 Example Rd", "postcode": "3053", "state": "VIC"}
    assert validate(body, ADDRESS_SCHEMA)[0]


def test_injection_and_script_payloads_are_rejected_by_patterns():
    for payload in SQL_INJECTION + XSS:
        for pattern in (NAME_RE, USERNAME_RE, POSTCODE_RE, EMAIL_RE):
            assert not pattern.fullmatch(payload), (pattern.pattern, payload)
        ok, _, errors = validate({"address_line": payload, "postcode": "3000", "state": "VIC"}, ADDRESS_SCHEMA)
        assert not ok and "address_line" in errors


def test_overlong_and_control_characters_are_rejected():
    assert not NAME_RE.fullmatch("A" * 101)
    assert not NAME_RE.fullmatch("Alex\x00Testperson")
    assert not ADDRESS_RE.fullmatch("42 Example St\nDROP")


def test_good_values_match_the_patterns():
    assert NAME_RE.fullmatch("Zoë O'Brien-Nguyen")
    assert USERNAME_RE.fullmatch("alex_t.2026")
    assert EMAIL_RE.fullmatch("alex.testperson@example.com")
    assert ADDRESS_RE.fullmatch("Unit 4/12 Example Rd, Carlton")
    assert POSTCODE_RE.fullmatch("0800")