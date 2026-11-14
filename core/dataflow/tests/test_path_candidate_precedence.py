"""Qualified candidate matches precede unrelated short-name matches."""

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
def test_qualified_candidate_wins_over_earlier_bare_match(monkeypatch, reverse):
    candidates = [_candidate("auth.sanitize"), _candidate("db.sanitize")]
    if reverse:
        candidates.reverse()
    monkeypatch.setattr(path_annotator, "_extract_call_chains",
                        lambda snippet, language: (("db", "sanitize"),))
    result = path_annotator._annotate_step(
        Step("caller.py", 1, 0, "db.sanitize(value)"), 0, candidates,
    )
    assert result.on_path_validators == ("db.sanitize",)
    assert result.inlined_helpers == ()


def test_longest_qualified_suffix_wins(monkeypatch):
    monkeypatch.setattr(path_annotator, "_extract_call_chains",
                        lambda snippet, language: (("app", "db", "sanitize"),))
    result = path_annotator._annotate_step(
        Step("caller.py", 1, 0, "app.db.sanitize(value)"), 0,
        [_candidate("sanitize"), _candidate("db.sanitize"),
         _candidate("app.db.sanitize")],
    )
    assert result.on_path_validators == ("app.db.sanitize",)
