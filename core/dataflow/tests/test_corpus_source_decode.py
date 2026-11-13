"""Measurement records must not silently replace malformed UTF-8."""

import json

import pytest

from core.dataflow import Finding, GroundTruth, Step, VERDICT_TRUE_POSITIVE
from core.dataflow.run_corpus import iter_corpus


def test_corpus_rejects_malformed_utf8_preserving_valid_unicode(tmp_path):
    step = Step("fixture.py", 1, 0, "value")
    finding = Finding("fixture�é", "fixture", "fixture", "fixture", step, step)
    label = GroundTruth(finding.finding_id, VERDICT_TRUE_POSITIVE, "fixture", "fixture", "2026-11-13")
    records = {
        tmp_path / "fixture.json": json.dumps(finding.to_dict(), ensure_ascii=False).encode("utf-8"),
        tmp_path / "fixture.label.json": json.dumps(label.to_dict(), ensure_ascii=False).encode("utf-8"),
    }
    for path, raw in records.items():
        path.write_bytes(raw)
    assert list(iter_corpus(tmp_path)) == [(finding, label)]
    for malformed in records:
        for path, raw in records.items():
            path.write_bytes(raw)
        malformed.write_bytes(records[malformed].replace("�".encode("utf-8"), b"\xff"))
        with pytest.raises(UnicodeDecodeError):
            list(iter_corpus(tmp_path))
