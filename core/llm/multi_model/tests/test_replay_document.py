"""Frozen replay presentation preserves estimator results and native JSON."""
from copy import deepcopy
import importlib
import json

from core.llm.multi_model.replay import render_json, render_markdown, replay
from core.llm.multi_model.replay_document import build_document
from core.llm.multi_model.tests.test_replay_render_scrub import _report
from core.reporting.document import ReportDocument
from core.reporting.renderers import render_document


def test_document_does_not_reload_or_reestimate_and_retains_abstention_scope(tmp_path, monkeypatch):
    path = tmp_path / "recorded.json"
    path.write_text(json.dumps({"results": [
        {"finding_id": "F1", "rule_id": "rule", "is_exploitable": True,
         "multi_model_analyses": [{"model": "m1", "is_exploitable": True}, {"model": "m2", "is_exploitable": False}]},
        {"finding_id": "F2", "rule_id": "rule",
         "multi_model_analyses": [{"model": "m1", "is_exploitable": True}, {"model": "m2", "is_exploitable": True}]}]}))
    source = path.read_bytes()
    report = replay([path])
    native = render_json(report)
    def refuse(*args, **kwargs):
        raise AssertionError("presentation must not reload or re-estimate")
    module = importlib.import_module("core.llm.multi_model.replay")
    monkeypatch.setattr(module, "load_from_paths", refuse)
    monkeypatch.setattr(module, "estimate_partitioned", refuse)

    document = build_document(report)
    restored = ReportDocument.from_dict(document.to_dict())
    assert restored.to_dict() == document.to_dict()
    assert render_markdown(report) == render_document(document, "markdown").content.decode()
    for format in ("markdown", "json", "xml"):
        text = render_document(restored, format).content
        assert b"no recorded verdict" in text and b"excluded from flip rates" in text
        assert b"Inferred per-model reliability" in text
    assert report.n_no_recorded_verdict == 1
    assert render_json(report) == native and path.read_bytes() == source
    assert not any(block.kind == "legacy_markdown" for block in document.blocks)


def test_raw_label_capture_is_bounded_and_native_records_are_unchanged():
    report = _report("class" * 40, "model" * 40)
    before = deepcopy(report)
    document = build_document(report)
    assert set(document.extensions["raptor.truncated_fields"]) == {"Model", "Decision class"}
    assert any("64 characters" in note for note in document.diagnostics)
    assert report == before
