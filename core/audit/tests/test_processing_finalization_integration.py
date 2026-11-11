"""Known producer retention failures survive real CLI finalisation.

Execution adapters and lifecycle transport are inert; report persistence is real.
"""
import errno
import json
from types import SimpleNamespace

import pytest

from core.audit.tests.test_finalize_interrupt_lifecycle import _load_cli
from core.audit.tests.test_processing_limitations import (
    MESSAGES, _reject_write, _setup, _snapshot,
)
from core.audit.tests.test_report_completeness import TestCompleteRunReport as _CompleteRun


@pytest.mark.parametrize("kind", ["dark", "differential"])
def test_producer_retention_failure_reaches_final_report(kind, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    out = _CompleteRun()._complete_run(tmp_path)
    prior = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    op = _setup(kind, tmp_path, monkeypatch, confirms=False)
    op.config.out_dir = out
    before = _snapshot(op.result)
    failure = OSError(errno.EIO, "private-retention-sentinel")
    _reject_write(monkeypatch, failure)
    with pytest.raises(OSError) as caught:
        op.run()
    assert caught.value is failure
    assert _snapshot(op.result) == before
    _finalize(out, op.result, monkeypatch)
    report = json.loads((out / "audit-report.json").read_text())
    assert report["completeness"]["partial"] is True
    assert report["completeness"]["missing"] == [MESSAGES[kind]]
    assert report["completeness"]["run_status"] == "completed"
    assert report["completeness"]["resumable"] is False
    assert report["stats"]["clean"] == 1 and report["stats"]["error"] == 0
    console = capsys.readouterr().out
    assert "Processing incomplete:" in console and MESSAGES[kind] in console
    assert "private-retention-sentinel" not in console + json.dumps(report)
    assert MESSAGES[kind] in (out / "audit-report.md").read_text()
    assert _snapshot(op.result) == before
    for name, content in prior.items():
        assert (out / name).read_bytes() == content


def _finalize(out, result, monkeypatch):
    import subprocess
    import core.audit.forecast as forecast
    calls = []
    def lifecycle(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(subprocess, "run", lifecycle)
    monkeypatch.setattr(forecast, "record_run_calibration", lambda out: None)
    result.terminated_by = "completed"
    _load_cli()._finalize_run(out, result, "scripted-model")
    assert calls and all("complete" in cmd for cmd in calls)


def test_ordinary_pass_error_does_not_invent_retention_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    out = _CompleteRun()._complete_run(tmp_path)
    op = _setup("dark", tmp_path, monkeypatch, confirms=False)
    op.result.errors = 1
    assert op.result.processing_limitations == []
    _finalize(out, op.result, monkeypatch)
    report = json.loads((out / "audit-report.json").read_text())
    assert not set(MESSAGES.values()).intersection(report["completeness"]["missing"])
    assert "Processing incomplete:" not in capsys.readouterr().out
