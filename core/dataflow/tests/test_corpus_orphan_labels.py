"""Orphan labels cannot silently disappear from corpus intake."""

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.label import GroundTruth
from core.dataflow.run_corpus import iter_corpus


def test_orphan_label_is_refused_before_any_finding_is_yielded(tmp_path):
    label = GroundTruth(finding_id="orphan", verdict="true_positive", rationale="fixture", labeler="fixture", labeled_at="2026-11-13")
    (tmp_path / "z-orphan.label.json").write_text(label.to_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="orphan.*label"):
        list(iter_corpus(tmp_path))
    step = Step(file_path="fixture.java", line=1, column=0, snippet="x", label="source")
    finding = Finding(finding_id="valid", producer="codeql", rule_id="java/x", message="m", source=step, sink=step)
    valid_label = GroundTruth(finding_id="valid", verdict="true_positive", rationale="fixture", labeler="fixture", labeled_at="2026-11-13")
    (tmp_path / "a-valid.json").write_text(finding.to_json(), encoding="utf-8")
    (tmp_path / "a-valid.label.json").write_text(valid_label.to_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="orphan.*label"):
        next(iter(iter_corpus(tmp_path)))
    (tmp_path / "z-orphan.label.json").unlink()
    assert [f.finding_id for f, _ in iter_corpus(tmp_path)] == ["valid"]
    empty = tmp_path / "empty"
    empty.mkdir()
    assert list(iter_corpus(empty)) == []
