"""Corpus labels must identify the finding they grade."""

import json

import pytest

from core.dataflow import Finding, GroundTruth, Step, VERDICT_TRUE_POSITIVE
from core.dataflow.run_corpus import iter_corpus, run
from core.dataflow.validator import ValidatorVerdict


def test_corpus_refuses_mismatched_label_before_validation(tmp_path):
    step = Step("fixture.py", 1, 0, "value")
    finding = Finding("finding-a", "fixture", "fixture", "fixture", step, step)
    label = GroundTruth("finding-a", VERDICT_TRUE_POSITIVE, "fixture", "fixture", "2026-11-13")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "arbitrary-name.json").write_text(finding.to_json())
    label_path = corpus / "arbitrary-name.label.json"
    label_path.write_text(label.to_json())
    assert list(iter_corpus(corpus)) == [(finding, label)]

    calls = []

    class RecordingValidator:
        def validate(self, value):
            calls.append(value.finding_id)
            return ValidatorVerdict.EXPLOITABLE

    assert run(corpus, RecordingValidator(), tmp_path / "valid.csv") == 1
    assert calls == ["finding-a"]
    calls.clear()
    label_path.write_text(json.dumps({**label.to_dict(), "finding_id": "finding-b"}))
    with pytest.raises(ValueError, match="finding.*label|label.*finding"):
        run(corpus, RecordingValidator(), tmp_path / "invalid.csv")
    assert calls == []
