"""A truncated input census cannot prove preservation of all mutations."""

import pytest

from core.audit import protocol_state as protocol

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.fixture(autouse=True)
def native_grammar():
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")


def query(body):
    sources = {"unit.c": "void Read(struct S *State){\n" + body + "\n}"}
    index = protocol.build_state_field_index(sources)
    return index, protocol.check_invariant_multi_site("Count <= Limit", index, sources)


@pytest.mark.parametrize("cap", ["writes", "fields"])
def test_collector_truncation_cannot_hide_a_later_violation(monkeypatch, cap):
    if cap == "writes":
        monkeypatch.setattr(protocol, "MAX_SITES_PER_FIELD", 1)
        body = "State->Count=State->Limit;\nState->Count++;"
    else:
        monkeypatch.setattr(protocol, "MAX_CENSUS_FIELDS", 1)
        body = "State->Count=State->Limit;\nState->Limit--;"
    index, result = query(body)
    assert index["skipped"] is True
    assert result["outcome"] == "inconclusive", result
    assert result["sites"][0]["verdict"] == "preserved"
    assert "partial census" in result["reason"]
    assert "source index incomplete" in result["reason"]


def test_complete_collector_retains_a_preservation_proof():
    index, result = query("State->Count=State->Limit;")
    assert index["skipped"] is False
    assert result["outcome"] == "preserved", result


def test_checked_counterexample_survives_incomplete_collection(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_SITES_PER_FIELD", 1)
    index, result = query("State->Count++;\nState->Count=State->Limit;")
    assert index["skipped"] is True
    assert result["outcome"] == "violable", result
    assert result["sites"][0]["model"]["Count'"] > result["sites"][0]["model"]["Limit"]


def test_incomplete_empty_census_is_not_reported_as_preserved(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_CENSUS_FIELDS", 0)
    index, result = query("State->Count++;")
    assert index["skipped"] is True and index["fields"] == {}
    assert result["outcome"] == "inconclusive", result
    assert result["sites"] == []
    assert "partial census" in result["reason"]


def test_upstream_incompleteness_cannot_refute_through_adjudication(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_SITES_PER_FIELD", 1)
    sources = {"unit.c": "void Read(struct S *State){\nState->Count=State->Limit;\nState->Count++;\n}"}
    index = protocol.build_state_field_index(sources)
    result = protocol._adjudicate_invariant("Count <= Limit", index, sources, {}, {})
    assert result.outcome == "inconclusive", result.to_dict()


def test_zero_analysis_cap_is_not_an_empty_complete_census():
    sources = {"unit.c": "void Read(struct S *State){\nState->Count++;\n}"}
    index = protocol.build_state_field_index(sources)
    result = protocol.check_invariant_multi_site("Count <= Limit", index, sources, max_sites=0)
    assert result["outcome"] == "inconclusive", result
    assert result["sites"] == []
    assert "partial census" in result["reason"]


@pytest.mark.parametrize("marker", [None, 0, "false", []])
def test_unknown_completeness_markers_cannot_license_preservation(marker):
    sources = {"unit.c": "void Read(struct S *State){\nState->Count=State->Limit;\n}"}
    index = protocol.build_state_field_index(sources)
    index["skipped"] = marker
    result = protocol.check_invariant_multi_site("Count <= Limit", index, sources)
    assert result["outcome"] == "inconclusive", result
    assert "source index incomplete" in result["reason"]
