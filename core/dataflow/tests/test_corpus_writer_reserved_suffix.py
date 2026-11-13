"""Finding files cannot occupy the corpus label-file namespace."""

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.label import GroundTruth
from core.dataflow.owasp_corpus_generator import write_corpus
from core.dataflow.run_corpus import iter_corpus


def test_writer_reserves_label_suffix_and_preserves_roundtrip(tmp_path):
    def pair(fid):
        step = Step(file_path="fixture.java", line=1, column=0, snippet="x", label="source")
        return (Finding(finding_id=fid, producer="codeql", rule_id="java/x", message="m", source=step, sink=step),
                GroundTruth(finding_id=fid, verdict="true_positive", rationale="fixture", labeler="fixture", labeled_at="2026-11-13"))
    for index, ids in enumerate((("a.label",), ("a", "a.label"), ("a.label", "a"))):
        out = tmp_path / f"refusal-{index}"
        with pytest.raises(ValueError, match="reserved"):
            write_corpus([pair(fid) for fid in ids], out)
        assert not out.exists()
    out = tmp_path / "valid"
    assert write_corpus([pair("a"), pair("a.labelled")], out) == 2
    assert [f.finding_id for f, _ in iter_corpus(out)] == ["a", "a.labelled"]
