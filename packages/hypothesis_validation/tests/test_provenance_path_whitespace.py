"""Distinct filesystem path spellings cannot share hypothesis provenance."""
from dataclasses import replace

import pytest

from packages.hypothesis_validation.hypothesis import FlowStep, Hypothesis, Location
from packages.hypothesis_validation.provenance import ProvenanceMismatch, hash_hypothesis
from packages.hypothesis_validation.result import Evidence, ValidationResult


def test_path_whitespace_distinguishes_actual_files_and_evidence_roots(tmp_path):
    subject = tmp_path / "subject.c"
    subject.write_text("int owned;\n", encoding="utf-8")
    for left, right in (("a b.c", "a  b.c"), ("lead.c", " lead.c"),
                        ("trail.c", "trail.c "), ("a b.c", "a\tb.c")):
        paths = [tmp_path / name for name in (left, right)]
        for path in paths:
            path.write_text("int owned;\n", encoding="utf-8")
        assert paths[0].stat().st_ino != paths[1].stat().st_ino
        for field in ("target", "source", "sink", "flow_steps"):
            hypotheses = []
            for path in paths:
                h = Hypothesis(claim="owned claim", target=subject)
                value = path if field == "target" else (
                    [FlowStep(file=str(path), line=1)] if field == "flow_steps"
                    else Location(file=str(path), line=1)
                )
                hypotheses.append(replace(h, **{field: value}))
            refs = [hash_hypothesis(h) for h in hypotheses]
            assert refs[0] != refs[1], (field, left, right)
            with pytest.raises(ProvenanceMismatch):
                ValidationResult(verdict="inconclusive", evidence=[
                    Evidence(tool="owned", rule="owned", summary="owned", refers_to=ref)
                    for ref in refs
                ])
    a = Hypothesis(claim="owned claim", target=subject)
    assert hash_hypothesis(a) == hash_hypothesis(replace(a, claim="  owned\n claim "))
    assert hash_hypothesis(a) == hash_hypothesis(replace(a, target=tmp_path / "folder" / ".." / "subject.c"))
    assert hash_hypothesis(Hypothesis(claim="foo bar", target=type(subject)("/x"), cwe="CWE-129")) == (
        "066b6bcb035ac80f53209d417bb66bcf155d5a869305c50b3c92eb1f236a3e93"
    )
