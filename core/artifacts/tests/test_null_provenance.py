"""A present null stamp is malformed, rather than an unstamped artifact."""
import pytest

from core.artifacts import provenance


@pytest.mark.parametrize("wrapped", [False, True], ids=["object", "array"])
def test_null_stamp_is_invalid(wrapped):
    artifact = {provenance.PROVENANCE_KEY: None}
    data = [artifact] if wrapped else artifact
    status, messages = provenance.check_provenance(data)
    assert status == provenance.STATUS_INVALID
    assert len(messages) == 1
    assert "provenance" in messages[0] and "must be an object" in messages[0]


@pytest.mark.parametrize("wrapped", [False, True], ids=["object", "array"])
def test_absent_stamp_stays_legacy(wrapped):
    data = [{}] if wrapped else {}
    assert provenance.check_provenance(data) == (provenance.STATUS_LEGACY, [])


def test_null_stamp_in_mixed_array_is_not_legacy_tolerance():
    valid = {}
    provenance.stamp_provenance(valid, "owned-test", untrusted=True)
    status, messages = provenance.check_provenance([valid, {"provenance": None}])
    assert status == provenance.STATUS_INVALID
    assert messages == ["[1].provenance: must be an object, got NoneType"]


def test_legacy_element_tolerance_stays_available():
    valid = {}
    provenance.stamp_provenance(valid, "owned-test", untrusted=True)
    status, messages = provenance.check_provenance([valid, {}])
    assert status == provenance.STATUS_OK
    assert messages == ["1 element(s) without a provenance stamp (treated as untrusted)"]


def test_null_consumer_view_remains_untrusted():
    view = provenance.provenance_of({"provenance": None})
    assert view["untrusted"] is True
    assert view["legacy"] is True
    assert view["schema_validated"] is False
