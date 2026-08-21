"""Tests for `--threat-model` support on the standard CodeQL suite pass.

`QueryRunner.active_threat_models` gates on the config kill-switch and
the CLI version (flag first shipped in 2.15.3); `run_suite` appends one
`--threat-model=<name>` per configured model. The codeql binary is
mocked throughout — no test invokes a real CLI.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


def _bare_runner(version="2.26.3"):
    from packages.codeql.query_runner import QueryRunner
    runner = QueryRunner.__new__(QueryRunner)  # bypass __init__
    runner.codeql_cli = "codeql"
    if version is not None:
        runner._version_probe = version
    return runner


class TestActiveThreatModels:
    def test_default_is_local(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS", ("local",))
        assert _bare_runner().active_threat_models() == ("local",)

    def test_kill_switch_disables(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", False)
        assert _bare_runner().active_threat_models() == ()

    def test_empty_model_set_disables(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS", ())
        assert _bare_runner().active_threat_models() == ()

    def test_old_cli_skips_flag(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS", ("local",))
        assert _bare_runner(version="2.14.6").active_threat_models() == ()

    def test_minimum_version_boundary(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS", ("local",))
        assert _bare_runner(version="2.15.3").active_threat_models() == (
            "local",)
        assert _bare_runner(version="2.15.2").active_threat_models() == ()

    def test_unknown_version_skips_flag(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS", ("local",))
        runner = _bare_runner(version=None)
        runner._version_probe = ""  # failed probe, cached
        assert runner.active_threat_models() == ()

    def test_unparseable_version_skips_flag(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS", ("local",))
        assert _bare_runner(version="nightly").active_threat_models() == ()

    def test_config_reads_are_fresh_after_gate_cached(self, monkeypatch):
        # Per-run CLI overrides flip the config AFTER a runner may
        # already exist; only the version gate is cached.
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS", ("local",))
        runner = _bare_runner()
        assert runner.active_threat_models() == ("local",)
        monkeypatch.setattr(
            RaptorConfig, "CODEQL_THREAT_MODELS", ("local", "environment"))
        assert runner.active_threat_models() == ("local", "environment")
        monkeypatch.setattr(
            RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", False)
        assert runner.active_threat_models() == ()

    def test_flag_construction(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", True)
        monkeypatch.setattr(
            RaptorConfig, "CODEQL_THREAT_MODELS", ("local", "!environment"))
        assert _bare_runner()._threat_model_args() == [
            "--threat-model=local", "--threat-model=!environment",
        ]


class TestVersionProbe:
    def test_probe_parses_dotted_version(self, monkeypatch):
        runner = _bare_runner(version=None)
        proc = MagicMock(returncode=0,
                         stdout="CodeQL command-line toolchain release 2.20.1.")
        with patch("packages.codeql.query_runner.subprocess.run",
                   return_value=proc):
            assert runner._codeql_version() == "2.20.1"

    def test_probe_failure_cached_as_none(self, monkeypatch):
        runner = _bare_runner(version=None)
        with patch("packages.codeql.query_runner.subprocess.run",
                   side_effect=OSError("no codeql")) as mock_run:
            assert runner._codeql_version() is None
            assert runner._codeql_version() is None
            assert mock_run.call_count == 1  # cached, not re-probed


class TestRunSuiteCommand:
    def test_analyze_cmd_carries_threat_model_flags(
            self, monkeypatch, tmp_path):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_THREAT_MODELS", ("local",))
        monkeypatch.delenv("CODEQL_QUERIES", raising=False)
        runner = _bare_runner()
        captured = {}

        def fake_sandbox_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return MagicMock(returncode=1, stdout="", stderr="boom")

        with patch("core.sandbox.run", side_effect=fake_sandbox_run):
            runner.run_suite(tmp_path / "db", "python", tmp_path / "out")
        assert "--threat-model=local" in captured["cmd"]

    def test_analyze_cmd_clean_when_disabled(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "CODEQL_THREAT_MODELS_ENABLED", False)
        monkeypatch.delenv("CODEQL_QUERIES", raising=False)
        runner = _bare_runner()
        captured = {}

        def fake_sandbox_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return MagicMock(returncode=1, stdout="", stderr="boom")

        with patch("core.sandbox.run", side_effect=fake_sandbox_run):
            runner.run_suite(tmp_path / "db", "python", tmp_path / "out")
        assert not [a for a in captured["cmd"]
                    if str(a).startswith("--threat-model")]


def _write_sarif(path: Path, rule_cwes: dict):
    """Minimal SARIF with one result per (rule_id, cwe) entry."""
    rules = [
        {"id": rid,
         "properties": {"tags": [f"external/cwe/cwe-{cwe}"]}}
        for rid, cwe in rule_cwes.items()
    ]
    results = [
        {"ruleId": rid,
         "message": {"text": "m"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "a.py"},
             "region": {"startLine": 1}}}]}
        for rid in rule_cwes
    ]
    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": rules}},
        "results": results,
    }]}
    path.write_text(json.dumps(sarif), encoding="utf-8")


class TestIrisOverlapSummary:
    def test_counts_per_language_and_cwe(self, tmp_path):
        from packages.codeql.query_runner import iris_overlap_summary
        _write_sarif(tmp_path / "codeql_python.sarif",
                     {"py/cmd": "078", "py/sqli": "089"})
        _write_sarif(tmp_path / "codeql_python_iris.sarif",
                     {"raptor/cmd": "078"})
        summary = iris_overlap_summary(tmp_path, ["python"])
        assert "python" in summary
        std = summary["python"]["standard"]
        iris = summary["python"]["iris"]
        assert sum(std.values()) == 2
        assert sum(iris.values()) == 1

    def test_language_without_both_sarifs_omitted(self, tmp_path):
        from packages.codeql.query_runner import iris_overlap_summary
        _write_sarif(tmp_path / "codeql_go.sarif", {"go/x": "078"})
        # no codeql_go_iris.sarif
        assert iris_overlap_summary(tmp_path, ["go"]) == {}


class TestCliFlags:
    def test_agent_parser_accepts_flags(self):
        import subprocess
        r = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1]
                                 / "agent.py"), "--help"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert r.returncode == 0, r.stderr
        assert "--threat-models" in r.stdout
        assert "--no-threat-models" in r.stdout

    def test_raptor_codeql_parser_accepts_flags(self):
        import subprocess
        repo_root = Path(__file__).resolve().parents[3]
        r = subprocess.run(
            [sys.executable, str(repo_root / "raptor_codeql.py"), "--help"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert r.returncode == 0, r.stderr
        assert "--threat-models" in r.stdout
        assert "--no-threat-models" in r.stdout


class TestModelPackArgs:
    """Learned model packs must be APPLIED, not merely resolvable —
    and cached results must not mask their rows (the vacuous
    zero-delta bug, verified live on the corpus)."""

    def _runner(self):
        from packages.codeql.query_runner import QueryRunner
        qr = QueryRunner.__new__(QueryRunner)
        qr.additional_model_packs = None
        return qr

    def test_no_packs_no_args(self):
        qr = self._runner()
        assert qr._model_pack_args("java") == []
        assert not qr._has_model_packs("java")

    def test_pack_args_pair_resolution_and_application(self):
        qr = self._runner()
        qr.additional_model_packs = {
            "java": [("/tmp/packs", "raptor/learned-models-java")],
        }
        args = qr._model_pack_args("java")
        assert args == [
            "--additional-packs", "/tmp/packs",
            "--model-packs", "raptor/learned-models-java",
        ]
        assert qr._has_model_packs("java")
        assert qr._model_pack_args("cpp") == []
