"""Portable capture metadata must not trigger instrumentation or copy payloads."""
import json

import pytest

from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from packages.frida import cli, runner


_PAYLOAD_KEYS = {"native exit status", "target", "script origin", "requested duration seconds", "requested module",
                 "effective spawn", "unsafe attach requested", "follow children", "device selection", "capture result"}


def _run_args(tmp_path):
    hook = tmp_path / "hook.json"
    hook.write_text("send('owned-hook-secret');")
    return ["--target", "1234", "--out", str(tmp_path / "native"), "--script", str(hook)]


def _postprocessors(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_maybe_harvest_seeds", lambda path: calls.append("seeds"))
    monkeypatch.setattr(cli, "_maybe_correlate_io", lambda path: calls.append("io"))
    return calls


@pytest.mark.parametrize("events", [0, 7])
@isolated_cli_logging()
def test_portable_receipt_keeps_capture_metadata_without_raw_payloads(tmp_path, monkeypatch, capsys, events):
    calls = []
    posts = _postprocessors(monkeypatch)

    def completed(cfg):
        calls.append(cfg)
        cfg.out_dir.mkdir()
        (cfg.out_dir / "events.jsonl").write_text("owned-event-secret")
        (cfg.out_dir / "metadata.json").write_text("not JSON; reporter must not reread it")
        (cfg.out_dir / "script.js").write_text(cfg.script_source)
        (cfg.out_dir / "frida-report.md").write_text("native legacy report")
        return runner.RunResult(ok=True, events_captured=events, duration_actual_sec=1.25, resolved_pid=1234)

    monkeypatch.setattr(cli, "run", completed)
    assert cli.main(_run_args(tmp_path) + ["--report-format", "json"]) == 0
    assert len(calls) == 1 and posts == ["seeds", "io"]
    streams = capsys.readouterr()
    assert f"{events} events captured" in streams.out and "Summary" in streams.err
    root = tmp_path / "native"
    assert (root / "frida-report.md").read_text() == "native legacy report"
    text = (root / "frida-capture-report.json").read_text()
    assert "owned-hook-secret" not in text and "owned-event-secret" not in text
    context, _, _ = load_committed_report(root)
    payload = context.extensions["raptor.result"]
    assert set(payload) == _PAYLOAD_KEYS  # frozen persisted receipt schema, not learned vocabulary
    assert payload["capture result"]["events_captured"] == events
    assert context.extensions["raptor.findings_available"] is False
    assert any("Zero captured events" in note for note in context.diagnostics)


@isolated_cli_logging()
def test_failed_capture_retains_native_status_and_redacts_diagnostic(tmp_path, monkeypatch):
    posts = _postprocessors(monkeypatch)
    monkeypatch.setattr(cli, "run", lambda cfg: runner.RunResult(ok=False, error="https://user:owned-secret@[invalid"))
    assert cli.main(_run_args(tmp_path) + ["--report-format", "json"]) == 1
    assert posts == []
    context, _, _ = load_committed_report(tmp_path / "native")
    assert context.state == "failed" and context.extensions["raptor.result"]["native exit status"] == 1
    assert "owned-secret" not in context.extensions["raptor.result"]["capture result"]["error"]


@isolated_cli_logging()
def test_missing_frida_report_does_not_adopt_stale_metadata(tmp_path, monkeypatch):
    args = _run_args(tmp_path)
    root = tmp_path / "native"
    root.mkdir()
    (root / "metadata.json").write_text(json.dumps({"ok": True, "events_captured": 999}))

    def unavailable(cfg):
        raise runner.FridaUnavailable("missing")

    monkeypatch.setattr(cli, "run", unavailable)
    assert cli.main(args + ["--report-format", "json"]) == 3
    context, _, _ = load_committed_report(root)
    assert context.extensions["raptor.result"]["capture result"] is None
    assert context.extensions["raptor.metrics"]["Events captured"] is None and context.state == "failed"


@isolated_cli_logging()
def test_frida_report_cannot_replace_operator_hook(tmp_path, monkeypatch, capsys):
    args = _run_args(tmp_path)
    hook = tmp_path / "hook.json"
    before = hook.read_bytes()
    monkeypatch.setattr(cli, "run", lambda cfg: runner.RunResult(ok=True))
    _postprocessors(monkeypatch)
    assert cli.main(args + ["--report-format", "json", "--report-output", str(hook)]) == 0
    assert hook.read_bytes() == before and "Report persistence failed" in capsys.readouterr().err


@isolated_cli_logging()
def test_no_report_keeps_native_completion_without_portable_files(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run", lambda cfg: runner.RunResult(ok=True))
    _postprocessors(monkeypatch)
    assert cli.main(_run_args(tmp_path) + ["--no-report"]) == 0
    assert not (tmp_path / "native" / "reporting-manifest.json").exists()


@isolated_cli_logging()
def test_report_preflight_precedes_script_loading(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "load_script_source", lambda *args: pytest.fail("must preflight"))
    with pytest.raises(SystemExit) as error:
        cli.main(_run_args(tmp_path) + ["--report-format", "json", "--report-output", str(tmp_path / "bad.xml")])
    assert error.value.code == 2
