"""Unstamped scalar elements cannot inherit a neighbour's trusted view."""
import copy

import pytest

from core.artifacts import provenance


def trusted(generator="mechanical"):
    return provenance.stamp_provenance({}, generator, untrusted=False, schema_validated=True)


@pytest.mark.parametrize("unstamped", [None, "unstamped text", 7, False])
def test_unstamped_scalar_prevents_trusted_aggregate(unstamped):
    data = [trusted(), unstamped]
    before = copy.deepcopy(data)
    view = provenance.provenance_of(data)
    assert view["untrusted"] is True
    assert view["schema_validated"] is False
    assert view["legacy"] is False
    assert view["generator"] == "mixed"
    assert data == before


def test_dictionary_only_trust_view_is_unchanged():
    assert provenance.provenance_of([trusted(), trusted()]) == {
        "generator": "mechanical", "untrusted": False,
        "schema_validated": True, "legacy": False,
    }


def test_scalar_only_list_stays_unknown_untrusted():
    assert provenance.provenance_of([None, "text", 7]) == {
        "generator": "unknown", "untrusted": True,
        "schema_validated": False, "legacy": True,
    }


def test_empty_list_stays_unknown_untrusted():
    assert provenance.provenance_of([]) == {
        "generator": "unknown", "untrusted": True,
        "schema_validated": False, "legacy": True,
    }
