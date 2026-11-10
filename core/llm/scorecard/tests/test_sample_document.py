"""Reasoning samples are inert typed content, with retained-read provenance."""
from copy import deepcopy

from core.llm.scorecard.cli import _render_samples
from core.llm.scorecard.sample_document import build_sample_document
from core.llm.scorecard.tests.test_render_scrub import _stat
from core.reporting.document import ReportDocument
from core.reporting.renderers import render_document


def test_samples_preserve_recorded_fields_and_defang_foreign_markdown():
    stat = _stat("owned class", "owned model")
    stat.trusted = False
    stat.disagreement_samples = [{"ts": "2026-11-10", "event_type": "recorded event", "this_reasoning": "cheap thought FP",
                                  "other_reasoning": "full found real bug", "note": '<img src="https://foreign.example/tracker">',
                                  "producer_field": "recorded supplemental explanation\x1b[2J\n# injected heading"}]
    before = deepcopy(stat)
    document = build_sample_document(stat)
    assert document.metadata["Recorded read integrity"] == "unverified"
    assert any("do not grant" in note for note in document.diagnostics)
    assert ReportDocument.from_dict(document.to_dict()).to_dict() == document.to_dict()
    markdown = _render_samples(stat)
    assert "foreign.example" not in markdown and "\x1b" not in markdown
    assert "\n# injected heading" not in markdown
    for format in ("markdown", "json", "xml"):
        text = render_document(document, format).content
        assert b"cheap thought FP" in text and b"full found real bug" in text
        assert b"producer_field" in text and b"recorded supplemental explanation" in text
    assert stat == before
    assert not any(block.kind == "legacy_markdown" for block in document.blocks)


def test_sample_and_field_caps_disclose_loss_without_mutating_recorded_data():
    stat = _stat("owned class" * 20, "owned model")
    sample = {"note": "long reasoning " * 1000, **{f"extra_{index}": "recorded detail" for index in range(25)}}
    stat.disagreement_samples = [dict(sample) for _ in range(101)]
    before = deepcopy(stat)
    document = build_sample_document(stat)
    assert document.summary == {"Recorded samples": 101, "Samples omitted": 1, "Additional fields omitted": 500}
    assert set(document.extensions["raptor.truncated_fields"]) >= {"Decision class", "Operator note"}
    assert any("Portable capture is limited" in note for note in document.diagnostics)
    assert any("not a complete model-call history" in note for note in document.diagnostics)
    assert stat == before
