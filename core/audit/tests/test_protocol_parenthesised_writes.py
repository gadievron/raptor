"""Parenthesised field lvalues must reach the invariant solver census."""

import pytest

from core.audit import protocol_state as protocol

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.mark.parametrize("mutation", [
    "(State->Count)++;", "((State->Count))++;",
    "++(State->Count);", "++ (( State->Count ));",
    "(State->Count) += 1;", "(State->Limit)--;",
    "--(State->Limit);", "(State->Limit) -= 1;",
], ids=["postfix", "nested-postfix", "prefix", "nested-prefix", "add", "limit-postfix", "limit-prefix", "subtract"])
def test_parenthesised_write_cannot_hide_behind_a_safe_assignment(mutation):
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")
    source = "void Read(struct S *State){\nState->Count=State->Limit;\n" + mutation + "\n}"
    sources = {"unit.c": source}
    index = protocol.build_state_field_index(sources)
    result = protocol.check_invariant_multi_site("Count <= Limit", index, sources)
    assert result["outcome"] == "violable", result
    assert len(result["sites"]) == 2
    assert result["sites"][1]["verdict"] == "violable"
    evidence = protocol._adjudicate_invariant("Count <= Limit", index, sources, {}, {})
    assert evidence.outcome != "refuted", evidence.to_dict()


@pytest.mark.parametrize("operator", ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="])
def test_parenthesised_assignment_retains_rhs_and_write_classification(operator):
    index = protocol.build_state_field_index({"unit.c": f"((State->Count)) {operator} 7;"})
    bucket = index["fields"]["Count"]
    assert len(bucket["writes"]) == 1
    assert bucket["writes"][0]["rhs"] == "7"
    assert len(bucket["reads"]) == (operator != "=")


@pytest.mark.parametrize("expression", ["(State->Count) == 7;", "read(State->Count);", "((State->Count));"], ids=["comparison", "call", "grouped-read"])
def test_parenthesised_reads_remain_reads(expression):
    bucket = protocol.build_state_field_index({"unit.c": expression})["fields"]["Count"]
    assert bucket["writes"] == []
    assert len(bucket["reads"]) == 1


@pytest.mark.parametrize("operator", ["*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="])
def test_unsupported_parenthesised_updates_prevent_preservation(operator):
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")
    sources = {"unit.c": "void Read(struct S *State){\nState->Count=State->Limit;\n"
               + f"(State->Count) {operator} 2;\n}}"}
    index = protocol.build_state_field_index(sources)
    result = protocol.check_invariant_multi_site("Count <= Limit", index, sources)
    assert result["outcome"] == "inconclusive", result
    assert result["sites"][1]["verdict"] == "out_of_scope"
