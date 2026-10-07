"""R04: invalid types, lengths, formats and values are rejected on the server."""
from app.security.validators import validate

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