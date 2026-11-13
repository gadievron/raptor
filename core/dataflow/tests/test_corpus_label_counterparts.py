"""A corpus label needs an admitted finding file, not another label."""

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.label import GroundTruth
from core.dataflow.run_corpus import iter_corpus


def test_label_counterpart_must_be_a_finding_filename(tmp_path):
    step = Step(file_path="fixture.java", line=1, column=0, snippet="x", label="source")
    finding = Finding(finding_id="a", producer="codeql", rule_id="java/x", message="m", source=step, sink=step)
    label = GroundTruth(finding_id="a", verdict="true_positive", rationale="fixture", labeler="fixture", labeled_at="2026-11-13")
    (tmp_path / "a.json").write_text(finding.to_json(), encoding="utf-8")
    (tmp_path / "a.label.json").write_text(label.to_json(), encoding="utf-8")
    extra = tmp_path / "a.label.label.json"
    extra.write_text(label.to_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="orphan.*label"):
        next(iter(iter_corpus(tmp_path)))
    extra.unlink()
    assert [f.finding_id for f, _ in iter_corpus(tmp_path)] == ["a"]
