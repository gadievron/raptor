"""Tests for the raptor-review digest subcommand."""

import argparse
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_review_module():
    cli_path = str(REPO_ROOT / "libexec" / "raptor-review")
    loader = SourceFileLoader("raptor_review_cli_digest", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_review_cli_digest", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _make_run(tmp_path) -> Path:
    run = tmp_path / "run_001"
    run.mkdir()
    (run / ".raptor-run.json").write_text(json.dumps({
        "command": "agentic", "status": "completed",
        "timestamp": "2026-01-01T00:00:00+00:00",
    }), encoding="utf-8")
    (run / "findings.json").write_text(json.dumps([
        {"id": "f1", "file": "a.c", "line": 3, "vuln_type": "overflow",
         "is_exploitable": True},
    ]), encoding="utf-8")
    return run


def _args(run_dir=None, raw=False):
    return argparse.Namespace(run_dir=run_dir, raw=raw, out=None,
                              project=None)


class TestDigestSubcommand:
    def test_renders_ranked_summary(self, tmp_path, capsys):
        mod = _load_review_module()
        run = _make_run(tmp_path)
        mod.cmd_digest(_args(run_dir=str(run)))
        out = capsys.readouterr().out
        assert "What matters" in out
        assert "Exploitable, unverified (1)" in out
        assert "/validate" in out

    def test_raw_json(self, tmp_path, capsys):
        mod = _load_review_module()
        run = _make_run(tmp_path)
        mod.cmd_digest(_args(run_dir=str(run), raw=True))
        payload = json.loads(capsys.readouterr().out)
        assert payload["command"] == "agentic"
        assert payload["exploitable_unverified"][0]["finding_id"] == "f1"

    def test_non_run_dir_exits_2(self, tmp_path, capsys):
        mod = _load_review_module()
        with pytest.raises(SystemExit) as exc:
            mod.cmd_digest(_args(run_dir=str(tmp_path)))
        assert exc.value.code == 2

    def test_falls_back_to_latest_run(self, tmp_path, monkeypatch,
                                      capsys):
        mod = _load_review_module()
        run = _make_run(tmp_path)
        monkeypatch.setattr(mod, "_resolve_out_dir", lambda a: run)
        mod.cmd_digest(_args())
        assert "What matters" in capsys.readouterr().out

    def test_no_run_exits_1(self, tmp_path, monkeypatch, capsys):
        mod = _load_review_module()
        monkeypatch.setattr(mod, "_resolve_out_dir", lambda a: None)
        with pytest.raises(SystemExit) as exc:
            mod.cmd_digest(_args())
        assert exc.value.code == 1
