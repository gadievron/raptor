"""Ambiguous short-name candidates retain an unresolved call annotation."""

import pytest

from core.dataflow import Step
from core.dataflow import path_annotator
from core.dataflow.sanitizer_evidence import CandidateValidator, PROVENANCE_LLM


def _candidate(qualified):
    return CandidateValidator(
        name="sanitize", qualified_name=qualified, semantics_tag="sql_escape",
        semantics_text="owned fixture", confidence=0.9,
        source_file="fixture.py", source_line=1,
        extraction_provenance=PROVENANCE_LLM,
    )


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("chain", [("sanitize",), ("other", "sanitize")])
def test_ambiguous_short_match_stays_unresolved(monkeypatch, reverse, chain):
    candidates = [_candidate("auth.sanitize"), _candidate("db.sanitize")]
    if reverse:
        candidates.reverse()
    monkeypatch.setattr(path_annotator, "_extract_call_chains",
                        lambda snippet, language: (chain,))
    result = path_annotator._annotate_step(
        Step("caller.py", 1, 0, "owned call"), 0, candidates,
    )
    assert result.on_path_validators == ()
    assert result.inlined_helpers == (".".join(chain),)


def test_unique_short_match_is_retained(monkeypatch):
    monkeypatch.setattr(path_annotator, "_extract_call_chains",
                        lambda snippet, language: (("sanitize",),))
    result = path_annotator._annotate_step(
        Step("caller.py", 1, 0, "sanitize(value)"), 0,
        [_candidate("db.sanitize")],
    )
    assert result.on_path_validators == ("db.sanitize",)
    assert result.inlined_helpers == ()
