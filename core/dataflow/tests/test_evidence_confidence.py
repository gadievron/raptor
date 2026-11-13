"""Malformed evidence confidence is not a numeric observation."""

import pytest

from core.dataflow.sanitizer_evidence import CandidateValidator, PROVENANCE_LLM, SEMANTICS_OTHER


def test_evidence_confidence_validation():
    base = dict(name="fixture", qualified_name="fixture", semantics_tag=SEMANTICS_OTHER,
                semantics_text="Unverified fixture", source_file="fixture.py", source_line=1,
                extraction_provenance=PROVENANCE_LLM)
    for value in (0, 0.5, 1, "0.5"):
        assert CandidateValidator.from_dict({**base, "confidence": value}).confidence == float(value)
    assert CandidateValidator.from_dict(base).confidence == 0
    for value in (True, False, None, "invalid", 10**400):
        with pytest.raises(ValueError, match="confidence"):
            CandidateValidator.from_dict({**base, "confidence": value})
    for value in (True, False):
        with pytest.raises(ValueError, match="confidence"):
            CandidateValidator(**base, confidence=value)
