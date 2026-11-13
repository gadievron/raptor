"""Corpus writer IDs must remain single portable filename components."""

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.label import GroundTruth
from core.dataflow.owasp_corpus_generator import write_corpus


def test_writer_refuses_path_bearing_ids_before_output(tmp_path):
    def pair(fid):
        step = Step(file_path="fixture.java", line=1, column=0, snippet="x", label="source")
        return (Finding(finding_id=fid, producer="codeql", rule_id="java/x", message="m", source=step, sink=step),
                GroundTruth(finding_id=fid, verdict="true_positive", rationale="fixture", labeler="fixture", labeled_at="2026-11-13"))
    for index, fid in enumerate(("../escape", "nested/file", "..\\escape", "C:escape", str(tmp_path / "absolute"), "nul\x00id")):
        out = tmp_path / f"refusal-{index}"
        with pytest.raises(ValueError, match="filename"):
            write_corpus([pair("valid"), pair(fid)], out)
        assert not out.exists()
    assert not (tmp_path / "escape.json").exists()
    out = tmp_path / "valid"
    assert write_corpus([pair("codeql_rule-1_abc"), pair("case.name")], out) == 2
    assert len(list(out.iterdir())) == 4
