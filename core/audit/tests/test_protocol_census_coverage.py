"""Source field mutations omitted by the lexical census cannot prove safety."""

import pytest

from core.audit import protocol_state as protocol

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.fixture(autouse=True)
def native_grammar():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


@pytest.mark.parametrize("mutation", [
    "State->Count\n++;", "++\nState->Count;", "State\n->Count++;",
    "State->\nCount++;", "(State->Count\n)++;", "State->Count /* update */ ++;",
    "State/* receiver */->Count++;", "State->Count\n+= 1;",
    "State->Limit\n--;",
], ids=["postfix", "prefix", "receiver", "member", "parentheses", "tail-comment", "receiver-comment", "compound", "other-field"])
def test_omitted_source_write_prevents_false_preservation(mutation):
    sources = {"unit.c": "void Read(struct S *State){\nState->Count=State->Limit;\n" + mutation + "\n}"}
    index = protocol.build_state_field_index(sources)
    result = protocol.check_invariant_multi_site("Count <= Limit", index, sources)
    assert result["outcome"] == "inconclusive", result
    assert "source field write absent from census" in result["reason"]
    evidence = protocol._adjudicate_invariant("Count <= Limit", index, sources, {}, {})
    assert evidence.outcome == "inconclusive", evidence.to_dict()


def test_empty_census_with_a_multiline_write_is_incomplete():
    sources = {"unit.c": "void Read(struct S *State){\nState->Count\n++;\n}"}
    result = protocol.check_invariant_multi_site("Count <= Limit", protocol.build_state_field_index(sources), sources)
    assert result["outcome"] == "inconclusive", result
    assert result["sites"] == []


def test_checked_counterexample_survives_an_omitted_source_write(monkeypatch):
    from core.audit import protocol_invariant_bindings as bindings

    monkeypatch.setattr(bindings, "census_coverage_refusal", lambda *a, **k: pytest.fail("existential witness required universal coverage"))
    sources = {"unit.c": "void Read(struct S *State){\nState->Count++;\nState->Count\n=0;\n}"}
    result = protocol.check_invariant_multi_site("Count <= Limit", protocol.build_state_field_index(sources), sources)
    assert result["outcome"] == "violable", result


@pytest.mark.parametrize("extra", [
    "consume(State\n->Count);", "sizeof(State->Count++);",
    "/* State->Count\n++; */", '"State->Count\\n++;";',
], ids=["multiline-read", "unevaluated-update", "comment", "string"])
def test_coverage_probe_does_not_invent_evaluated_writes(extra):
    from core.audit.protocol_invariant_bindings import census_coverage_refusal

    source = "void Read(struct S *State){\nState->Count=State->Limit;\n" + extra + "\n}"
    sources = {"unit.c": source}
    fields = protocol.build_state_field_index(sources)["fields"]
    assert census_coverage_refusal(sources.items(), {"Count", "Limit"}, fields, deadline=1, clock=lambda: 0) == ""


@pytest.mark.parametrize("limit", ["input", "nodes", "deadline", "syntax"])
def test_unavailable_source_coverage_cannot_report_preservation(monkeypatch, limit):
    from core.audit import invariant_source, protocol_invariant_bindings as bindings

    source = "void Read(struct S *State){\nState->Count=State->Limit;\n}"
    if limit == "input":
        monkeypatch.setattr(bindings, "_MAX_SOURCE", len(source) - 1)
    elif limit == "nodes":
        monkeypatch.setattr(invariant_source, "_MAX_NODES", 1)
    elif limit == "syntax":
        source += "\nvoid Broken("
    sources = {"unit.c": source}
    result = protocol.check_invariant_multi_site(
        "Count <= Limit", protocol.build_state_field_index(sources), sources,
        budget_s=0 if limit == "deadline" else 2,
    )
    assert result["outcome"] == "inconclusive", result
    refusal = bindings.census_coverage_refusal(
        sources.items(), {"Count", "Limit"}, protocol.build_state_field_index(sources)["fields"],
        deadline=0 if limit == "deadline" else 1, clock=lambda: 0,
    )
    assert "source census coverage" in refusal


def test_missing_write_in_another_function_is_not_hidden_by_scoped_proofs():
    sources = {"unit.c": "void Safe(struct S *State){\nState->Count=State->Limit;\n}\n"
               "void Update(struct S *State){\nState->Count\n++;\n}"}
    result = protocol.check_invariant_multi_site("Count <= Limit", protocol.build_state_field_index(sources), sources)
    assert result["outcome"] == "inconclusive", result
    assert result["sites"][0]["verdict"] == "preserved"
