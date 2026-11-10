"""Pin the shared rendering boundaries used by newly audited producers."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from core.analysis import gadget_reporting
from core.dataflow import corpus_report_completion, parity_report_completion
from core.dataflow.sanitizer_cut_parity import aggregate_parity
from core.dataflow.trust_corpus_report import CorpusReport
from core.reporting.options import ReportOptions
from core.reporting.renderers import render_document
from packages.llm_analysis import reporting as analysis_reporting


_HOSTILE = "owned-boundary |\n<script>owned</script> ![fetch](https://example.invalid/asset) `\x1b[2J"


@pytest.mark.parametrize("field", ["line", "file", "file_path", "finding_id", "id", "status"])
def test_typed_foreign_fields_are_data_until_shared_rendering(field):
    if field == "line":
        captured = {"target_path": "owned", "tier": "hint", "census": {"complete": True},
                    "chains": [{"sink": {"line": _HOSTILE}}]}
        original = deepcopy(captured)
        document = gadget_reporting.build_document(captured)
        value = document.blocks[-1].rows[0][-1]
    else:
        captured = {"mode": "prep_only", "results": [{field: _HOSTILE, "analysis": {"is_exploitable": False}}]}
        original = deepcopy(captured)
        document = analysis_reporting.build_document(captured)
        column = {"file": 2, "file_path": 2, "finding_id": 1, "id": 1, "status": 3}[field]
        value = document.blocks[0].rows[0][column]
    assert value == _HOSTILE  # Sanitising structured data early would corrupt recorded identifiers.
    for format in ("markdown", "json", "xml"):
        output = render_document(document, format).content.decode()
        assert "\x1b" not in output
        assert "owned-boundary" in output
        if format != "json":
            assert "<script>" not in output
        if format == "markdown":
            assert "![fetch](" not in output
            matching_rows = [line for line in output.splitlines() if line.startswith("| ") and "owned-boundary" in line]
            assert len(matching_rows) == 1
            assert matching_rows[0].count("|") == len(document.blocks[-1 if field == "line" else 0].columns) + 1
    assert captured == original


@pytest.mark.parametrize("producer", ["gadget", "corpus", "parity", "analysis"])
def test_disabled_producer_quick_views_use_terminal_sanitisation_without_files(tmp_path, capsys, producer):
    disabled = ReportOptions(enabled=False)
    if producer == "gadget":
        report = {"target_path": _HOSTILE, "tier": "hint", "census": {"complete": False}, "chains": []}
        gadget_reporting.emit(report, tmp_path / "target", None, disabled)
    elif producer == "corpus":
        report = CorpusReport(read_state="failed", read_reason=_HOSTILE)
        corpus_report_completion.emit(report, tmp_path / "source.db", disabled)
    elif producer == "parity":
        # Proposal-kind labels do not flow into this aggregate quick view.
        # The same renderer protects every terminal field that is displayed.
        report = replace(aggregate_parity([]), by_kind={_HOSTILE: {
            "both_suppress": 0, "lexical_only": 0, "value_bound_only": 0, "neither": 0}})
        parity_report_completion.emit(report, disabled)
    else:
        report = {"mode": "prep_only", "results": []}
        analysis_reporting.emit(report, tmp_path / "run", [], tmp_path / Path(_HOSTILE), disabled)
    shown = capsys.readouterr()
    assert "Structured command result captured" in shown.err
    assert "\x1b" not in shown.err
    assert "unavailable (" not in shown.err  # Proves the real summary path was reached.
    if producer == "parity":
        assert "fixture-measurement" in shown.err
    else:
        assert "owned-boundary" in shown.err
    assert list(tmp_path.iterdir()) == []
