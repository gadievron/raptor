"""Duplicated corpus identities must not receive multiple votes."""

import pytest

from core.dataflow import Finding, GroundTruth, Step, VERDICT_TRUE_POSITIVE
from core.dataflow.run_corpus import run
from core.dataflow.validator import ValidatorVerdict


def _write_pair(corpus, basename, finding_id):
    step = Step("fixture.py", 1, 0, "value")
    finding = Finding(finding_id, "fixture", "fixture", "fixture", step, step)
    label = GroundTruth(finding_id, VERDICT_TRUE_POSITIVE, "fixture", "fixture", "2026-11-13")
    (corpus / f"{basename}.json").write_text(finding.to_json())
    (corpus / f"{basename}.label.json").write_text(label.to_json())


def test_duplicate_corpus_id_refuses_second_validation(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    _write_pair(corpus, "a", "finding-a")
    _write_pair(corpus, "b", "finding-b")
    calls = []

    class RecordingValidator:
        def validate(self, finding):
            calls.append(finding.finding_id)
            return ValidatorVerdict.EXPLOITABLE

    assert run(corpus, RecordingValidator(), tmp_path / "valid.csv") == 2
    assert calls == ["finding-a", "finding-b"]
    calls.clear()
    _write_pair(corpus, "b", "finding-a")
    with pytest.raises(ValueError, match="duplicate.*finding"):
        run(corpus, RecordingValidator(), tmp_path / "invalid.csv")
    assert calls == ["finding-a"]
