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