"""Tests for libexec/raptor-run-status (read-only run introspection)."""

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_cli():
    cli_path = str(REPO_ROOT / "libexec" / "raptor-run-status")
    loader = SourceFileLoader("raptor_run_status_cli", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_run_status_cli", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _make_run(base: Path, name: str, status="completed",
              ts="2026-01-01T00:00:00+00:00") -> Path:
    run = base / name
    run.mkdir(parents=True)
    (run / ".raptor-run.json").write_text(json.dumps({
        "command": "agentic", "status": status, "timestamp": ts,
    }), encoding="utf-8")
    return run


class TestSingleRun:
    def test_renders_status(self, tmp_path, monkeypatch, capsys):
        mod = _load_cli()
        run = _make_run(tmp_path, "run_a")
        monkeypatch.setattr("sys.argv",
                            ["raptor-run-status", str(run)])
        mod.main()
        out = capsys.readouterr().out
        assert "Status:    Completed" in out
        assert "agentic" in out

    def test_raw_is_parseable_ascii_json(self, tmp_path, monkeypatch,
                                         capsys):
        mod = _load_cli()
        run = _make_run(tmp_path, "run_a")
        monkeypatch.setattr("sys.argv",
                            ["raptor-run-status", str(run), "--raw"])
        mod.main()
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "completed"

    def test_non_run_dir_exits_2(self, tmp_path, monkeypatch, capsys):
        mod = _load_cli()
        monkeypatch.setattr("sys.argv",
                            ["raptor-run-status", str(tmp_path)])
        with pytest.raises(SystemExit) as exc:
            mod.main()
        assert exc.value.code == 2
        assert "not a run directory" in capsys.readouterr().err

    def test_run_dir_and_project_conflict(self, tmp_path, monkeypatch,
                                          capsys):
        mod = _load_cli()
        run = _make_run(tmp_path, "run_a")
        monkeypatch.setattr("sys.argv", [
            "raptor-run-status", str(run), "--project", "x"])
        with pytest.raises(SystemExit) as exc:
            mod.main()
        assert exc.value.code == 2


class TestProjectView:
    def test_lists_runs_and_details_running(self, tmp_path,
                                            monkeypatch, capsys):
        mod = _load_cli()
        _make_run(tmp_path, "run_old", status="completed",
                  ts="2026-01-01T00:00:00+00:00")
        _make_run(tmp_path, "run_live", status="running",
                  ts="2026-01-02T00:00:00+00:00")
        monkeypatch.setattr(mod, "_resolve_project_dir",
                            lambda name: tmp_path)
        monkeypatch.setattr("sys.argv", ["raptor-run-status"])
        mod.main()
        out = capsys.readouterr().out
        assert "2 run(s)" in out
        assert "run_old" in out and "run_live" in out
        # The running run gets the detail block (heartbeat line).
        assert "heartbeat" in out

    def test_no_active_project_exits_1(self, tmp_path, monkeypatch,
                                       capsys):
        mod = _load_cli()
        monkeypatch.setattr(mod, "_resolve_project_dir",
                            lambda name: None)
        monkeypatch.setattr("sys.argv", ["raptor-run-status"])
        with pytest.raises(SystemExit) as exc:
            mod.main()
        assert exc.value.code == 1
        assert "no active project" in capsys.readouterr().err

    def test_hostile_run_name_escaped(self, tmp_path, monkeypatch,
                                      capsys):
        mod = _load_cli()
        _make_run(tmp_path, "run_\x1b[31mred")
        monkeypatch.setattr(mod, "_resolve_project_dir",
                            lambda name: tmp_path)
        monkeypatch.setattr("sys.argv", ["raptor-run-status"])
        mod.main()
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "\\x1b" in out
