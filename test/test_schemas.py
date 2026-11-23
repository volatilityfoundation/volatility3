"""schemas.validate() reports an invalid ISF by returning False."""

import pytest

from volatility3 import schemas

pytest.importorskip("jsonschema")


@pytest.fixture(autouse=True)
def isolated_validation_cache(monkeypatch):
    """Keep the tests away from the user's cache of validated ISFs."""
    monkeypatch.setattr(schemas, "cached_validations", set())
    monkeypatch.setattr(schemas, "record_cached_validations", lambda validations: None)


def test_validate_returns_false_for_invalid_isf():
    """A document that does not match its schema is not an exception."""
    assert schemas.validate({"metadata": {"format": "6.2.0"}}, use_cache=False) is False


def test_validate_returns_true_for_valid_isf():
    isf = {
        "metadata": {"format": "6.2.0"},
        "base_types": {},
        "symbols": {},
        "enums": {},
        "user_types": {},
    }
    assert schemas.validate(isf, use_cache=False) is True
