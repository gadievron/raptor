"""Corpus identity errors are refused before publishing any pair."""

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.label import GroundTruth
from core.dataflow.owasp_corpus_generator import write_corpus


def test_writer_preflights_all_pair_identities(tmp_path):
    def pair(fid, label_id=None):
        step = Step(file_path="fixture.java", line=1, column=0, snippet="x", label="source")
        return (Finding(finding_id=fid, producer="codeql", rule_id="java/x", message="m", source=step, sink=step),
                GroundTruth(finding_id=label_id or fid, verdict="true_positive", rationale="fixture", labeler="fixture", labeled_at="2026-11-13"))
    for name, pairs, message in (
        ("mismatch", [pair("first"), pair("second", "different")], "mismatch"),
        ("duplicate", [pair("first"), pair("first")], "duplicate"),
    ):
        out = tmp_path / name
        with pytest.raises(ValueError, match=message):
            write_corpus(pairs, out)
        assert not out.exists()
    out = tmp_path / "valid"
    assert write_corpus([pair("first"), pair("second")], out) == 2
    assert sorted(p.name for p in out.iterdir()) == ["first.json", "first.label.json", "second.json", "second.label.json"]
