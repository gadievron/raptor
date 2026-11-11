"""Native-only map completion discloses retained portable snapshots once."""
import hashlib

import pytest

from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from packages.binary_analysis import cli
from packages.binary_analysis.manifest import BinaryManifest
from packages.binary_analysis.pipeline import BinaryAnalysisResult


def _captured(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target = tmp_path / "captured-input"
    data = b"owned captured input, never executed"
    target.write_bytes(data)
    out = tmp_path / "out"
    manifest = BinaryManifest(schema_version=1, binary_path=str(target),
                              binary_sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data),
                              executable=False, target_kind="unknown", arch="unknown", bits=0,
                              binary_format="unknown")
    result = BinaryAnalysisResult(manifest, {"entry_points": []}, [], [], out / "graph.sqlite")
    monkeypatch.setattr(cli, "start_run", lambda *args, **kwargs: out)
    monkeypatch.setattr(cli, "complete_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "fail_run", lambda *args, **kwargs: None)
    return ["map", str(target), "--out", str(out)], out, result


@pytest.mark.parametrize("fails,status", [(False, 0), (True, 1)])
@isolated_cli_logging()
def test_implicit_map_retains_prior_receipt_and_warns_once(tmp_path, monkeypatch, capsys, fails, status):
    args, out, result = _captured(tmp_path, monkeypatch)
    attempts = []
    completions = []
    finish = cli._complete_map_report

    def captured(*args, **kwargs):
        attempts.append("captured analyser result")
        if fails and len(attempts) == 2:
            raise RuntimeError("captured map failure")
        return result

    def completed(*args, **kwargs):
        completions.append("completion")
        return finish(*args, **kwargs)

    monkeypatch.setattr(cli, "analyse_blackbox_binary", captured)
    monkeypatch.setattr(cli, "_complete_map_report", completed)
    assert cli.main(args + ["--report-format", "json"]) == 0
    previous, _, _ = load_committed_report(out)
    assert previous.kind == "binary-map"
    portable = {p.relative_to(out): p.read_bytes() for p in out.rglob("*")
                if p.is_file() and p.name != "map-result.json"}
    completions.clear()
    capsys.readouterr()
    assert cli.main(args) == status
    streams = capsys.readouterr()
    (tmp_path / "captured-stderr.txt").write_text(streams.err, encoding="utf-8")
    assert streams.err.count("prior report artifacts were not refreshed") == 1
    assert completions == ["completion"] and len(attempts) == 2
    assert "Summary" not in streams.err
    for name, contents in portable.items():
        assert (out / name).read_bytes() == contents


@isolated_cli_logging()
def test_fresh_implicit_map_does_not_export_or_warn(tmp_path, monkeypatch, capsys):
    args, out, result = _captured(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "analyse_blackbox_binary", lambda *args, **kwargs: result)
    assert cli.main(args) == 0
    assert "not refreshed" not in capsys.readouterr().err
    assert not (out / "reporting-manifest.json").exists()
