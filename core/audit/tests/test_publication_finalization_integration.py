"""Actual mandatory journal refusal remains visible after finalisation."""
import json

import pytest

from core.audit import orchestrator as orch
from core.audit.tests.test_initial_publication_failure import (
    test_replacement_requires_ack_without_losing_prior_or_spend as _replacement,
)
from core.audit.tests.test_processing_finalization_integration import _finalize
from core.audit.journal import load_entries

LABEL = "new review assessments (journal acknowledgement unavailable)"


@pytest.mark.parametrize("failure", ["journal", "mismatched_ack"])
def test_unacknowledged_replacement_reaches_final_completeness(tmp_path, monkeypatch, capsys, failure):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    captured = []
    retain = orch._retain_initial_publication_failure
    def capture(result, config, outcome, gap):
        captured.append((result, config.out_dir))
        return retain(result, config, outcome, gap)
    monkeypatch.setattr(orch, "_retain_initial_publication_failure", capture)
    # This invokes real review_one_function, Collector and signed prior journal;
    # only the model/optional tools and the failing mandatory append are scripted.
    _replacement(tmp_path, monkeypatch, True, failure)
    assert len(captured) == 1
    result, out = captured[0]
    before = [(e.verdict, e.body) for e in load_entries(out)]
    assert before == [("suspicious", "Prior assessment")]
    _finalize(out, result, monkeypatch)
    report = json.loads((out / "audit-report.json").read_text())
    assert report["completeness"]["partial"] is True
    assert LABEL in report["completeness"]["missing"]
    assert report["completeness"]["resumable"] is False
    assert report["stats"]["suspicious"] == 1 and report["stats"]["clean"] == 0
    assert [(e.verdict, e.body) for e in load_entries(out)] == before
    assert result.total_cost_usd == .325
    console = capsys.readouterr().out
    assert "Processing incomplete:" in console and LABEL in console
    assert "Fresh unverified proposal" not in console + json.dumps(report)


def test_optional_telemetry_failure_does_not_imply_publication_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    captured = []
    review = orch.review_one_function
    def capture(*args, **kwargs):
        outcome = review(*args, **kwargs)
        captured.append((args[4], args[2].out_dir))
        return outcome
    monkeypatch.setattr(orch, "review_one_function", capture)
    _replacement(tmp_path, monkeypatch, True, "telemetry")
    result, out = captured[0]
    assert result.publication_failures == []
    _finalize(out, result, monkeypatch)
    report = json.loads((out / "audit-report.json").read_text())
    assert LABEL not in report["completeness"]["missing"]
    assert report["stats"]["clean"] == 1
    assert LABEL not in capsys.readouterr().out
