"""An implicit native-only invocation must identify retained older receipts."""
import json

import pytest

from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from packages.frida import cli, runner
from packages.frida.tests.test_reporting import _postprocessors, _run_args


@pytest.mark.parametrize("ok,status", [(False, 1), (True, 0)])
@isolated_cli_logging()
def test_implicit_native_only_run_warns_without_replacing_prior_receipt(
    tmp_path, monkeypatch, capsys, ok, status,
):
    args = _run_args(tmp_path)
    _postprocessors(monkeypatch)
    records = [runner.RunResult(ok=True, events_captured=7),
               runner.RunResult(ok=ok, error=None if ok else "captured failure", events_captured=0)]
    calls = []

    def captured(cfg):
        calls.append(cfg)
        result = records[len(calls) - 1]
        cfg.out_dir.mkdir(exist_ok=True)
        (cfg.out_dir / "metadata.json").write_text(json.dumps({"ok": result.ok, "events": result.events_captured}))
        return result

    monkeypatch.setattr(cli, "run", captured)
    assert cli.main(args + ["--report-format", "json"]) == 0
    root = tmp_path / "native"
    previous, _, _ = load_committed_report(root)
    assert previous.extensions["raptor.metrics"]["Events captured"] == 7
    portable = {p.relative_to(root): p.read_bytes() for p in root.rglob("*")
                if p.is_file() and p.name != "metadata.json"}
    capsys.readouterr()
    assert cli.main(args) == status
    streams = capsys.readouterr()
    (tmp_path / "captured-stderr.txt").write_text(streams.err, encoding="utf-8")
    assert streams.err.count("prior report artifacts were not refreshed") == 1
    assert "Summary" not in streams.err
    assert len(calls) == 2
    assert json.loads((root / "metadata.json").read_text())["events"] == 0
    for name, contents in portable.items():
        assert (root / name).read_bytes() == contents


@isolated_cli_logging()
def test_fresh_implicit_native_only_run_does_not_warn_or_export(tmp_path, monkeypatch, capsys):
    _postprocessors(monkeypatch)
    monkeypatch.setattr(cli, "run", lambda cfg: runner.RunResult(ok=True, events_captured=0))
    assert cli.main(_run_args(tmp_path)) == 0
    assert "not refreshed" not in capsys.readouterr().err
    assert not (tmp_path / "native" / "reporting-manifest.json").exists()
