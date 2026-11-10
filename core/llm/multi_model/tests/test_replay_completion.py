"""Replay CLI exports reuse one recorded result and preserve native lanes."""
from dataclasses import replace
import importlib
import json

import pytest

from core.llm.multi_model.replay import main
from core.llm.multi_model.tests.test_replay_render_scrub import _report
from core.reporting.writer import load_committed_report, regenerate


def _capture(tmp_path, monkeypatch):
    source = tmp_path / "recorded.json"
    source.write_text("owned source bytes")
    report = replace(_report("recorded class", "recorded model"), sources=[str(source)])
    calls = []
    def run(paths, **kwargs):
        assert paths == [source]
        calls.append(True)
        return report
    monkeypatch.setattr(importlib.import_module("core.llm.multi_model.replay"), "replay", run)
    return source, calls


@pytest.mark.parametrize("flags,exported", [([], False), (["--no-report"], False),
                                         (["--report-format", "json", "--report-format", "xml"], True)])
def test_json_stdout_native_files_and_independent_summary(tmp_path, monkeypatch, capsys, flags, exported):
    source, calls = _capture(tmp_path, monkeypatch)
    output = tmp_path / "native.json"
    assert main([str(source), "--json", "--out", str(output), *flags]) == 0
    displayed = capsys.readouterr()
    native = json.loads(displayed.out)
    assert native == json.loads(output.read_text()) == json.loads((tmp_path / "native.json.json").read_text())
    assert "Panel records: 1" in displayed.err and "Offline estimator comparison" in displayed.err
    assert calls == [True] and source.read_text() == "owned source bytes"
    root = tmp_path / ".native-portable"
    if exported:
        context, document, _ = load_committed_report(root)
        assert document.snapshot_id == context.snapshot_id
        assert context.extensions["raptor.findings_available"] is False
        assert context.run_id == "unknown"
        xml = (root / "panel-replay-summary.xml").read_bytes()
        source.unlink()
        regenerate(root, tmp_path / "offline.xml", format="xml")
        assert (tmp_path / "offline.xml").read_bytes() == xml
    else:
        assert not root.exists()


@pytest.mark.parametrize("destination", ["source-native", "source-portable", "native-portable"])
def test_output_collisions_refused_before_replay(tmp_path, monkeypatch, destination):
    source, calls = _capture(tmp_path, monkeypatch)
    native = tmp_path / "native.json"
    if destination == "source-native":
        flags = ["--out", str(source)]
    else:
        flags = ["--out", str(native), "--report-format", "json", "--report-output",
                 str(source if destination == "source-portable" else native)]
    with pytest.raises(SystemExit) as error:
        main([str(source), *flags])
    assert error.value.code == 2 and not calls
    assert source.read_text() == "owned source bytes" and not native.exists()


def test_invalid_options_precede_replay(tmp_path, monkeypatch):
    source, calls = _capture(tmp_path, monkeypatch)
    with pytest.raises(SystemExit) as error:
        main([str(source), "--no-report", "--report-format", "json"])
    assert error.value.code == 2 and not calls


def test_optional_publisher_failure_preserves_completed_replay(tmp_path, monkeypatch, capsys):
    source, calls = _capture(tmp_path, monkeypatch)
    from core.llm.multi_model import replay_completion
    reached = []
    def fail(*args, **kwargs):
        reached.append(True)
        raise OSError("private fault")
    monkeypatch.setattr(replay_completion, "complete_reporting", fail)
    assert main([str(source), "--json", "--report-format", "json", "--report-output", str(tmp_path / "portable")]) == 0
    displayed = capsys.readouterr()
    assert json.loads(displayed.out)["total_panels"] == 1
    assert "native replay retained" in displayed.err and "private fault" not in displayed.err
    assert reached == [True] and calls == [True]


def test_native_writes_replace_symlinks_without_touching_targets(tmp_path, monkeypatch, capsys):
    source, calls = _capture(tmp_path, monkeypatch)
    retained = tmp_path / "retained.txt"
    retained.write_text("operator data")
    output = tmp_path / "native.json"
    sibling = tmp_path / "native.json.json"
    output.symlink_to(retained)
    sibling.symlink_to(retained)
    assert main([str(source), "--json", "--out", str(output)]) == 0
    assert retained.read_text() == "operator data"
    assert not output.is_symlink() and not sibling.is_symlink()
    assert json.loads(output.read_text()) == json.loads(capsys.readouterr().out)
    assert calls == [True]


def test_export_without_native_or_portable_destination_precedes_replay(tmp_path, monkeypatch):
    source, calls = _capture(tmp_path, monkeypatch)
    with pytest.raises(SystemExit) as error:
        main([str(source), "--report-format", "json"])
    assert error.value.code == 2 and not calls
    assert source.read_text() == "owned source bytes"
