"""Captured rates distinguish missing comparison data from measured zero."""
from copy import deepcopy
import importlib

import pytest

from core.llm.multi_model.replay import ClassSummary, FindingComparison, ReplayReport, render_json
from core.llm.multi_model.replay_completion import complete
from core.llm.multi_model.replay_document import build_document
from core.reporting.options import ReportOptions
from core.reporting.renderers import render_document


@pytest.mark.parametrize("population,missing", [(0, 0), (1, 1), (1, 0)], ids=["empty", "abstained", "comparable-zero"])
def test_captured_rate_availability_preserves_native_numbers(tmp_path, monkeypatch, capsys, population, missing):
    def forbidden(*args, **kwargs):
        raise AssertionError("captured presentation must not load or estimate")

    module = importlib.import_module("core.llm.multi_model.replay")
    monkeypatch.setattr(module, "load_from_paths", forbidden)
    monkeypatch.setattr(module, "estimate_partitioned", forbidden)
    findings = [FindingComparison("owned", "owned-class", None if missing else False,
                                  0.25, 0.1, 0.4, 2, "no_recorded_verdict" if missing else "no_flip")]
    classes = [ClassSummary("owned-class", 1, 0, 0, True, 1, [
        {"model": model, "alpha": 0.75, "beta": 0.75} for model in ("owned-a", "owned-b")
    ])]
    report = ReplayReport([], population * 2, population, ["owned-a", "owned-b"] if population else [],
                          ["owned-class"] if population else [], findings if population else [], classes if population else [],
                          0.0, 0.0, 0.0, {"0.2–0.3": 1.0} if population else {}, n_no_recorded_verdict=missing)
    before = deepcopy(report)
    native = render_json(report)
    document = build_document(report)
    text = render_document(document).content.decode()
    complete(report, ReportOptions(enabled=False), tmp_path / "native.md")
    quick = capsys.readouterr().err
    if population == missing:
        assert "unavailable (no comparable recorded verdicts)" in text
        assert "Flip rate: unavailable" in quick
        assert "0.0%" not in text
    else:
        assert "0.0%" in text and "Flip rate: 0.0" in quick
        assert "unavailable (no comparable recorded verdicts)" not in text
    assert report == before and render_json(report) == native
    assert f"No recorded verdict (excluded from flip rates): {missing}" in quick
    assert not list(tmp_path.iterdir())
