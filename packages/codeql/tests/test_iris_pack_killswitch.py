"""Tests for the IRIS Tier 1 master kill-switch in `/codeql`.

The standalone `/codeql` consumer routes through
`QueryRunner.analyze_iris_packs`; the kill-switch must early-out
before any pack work happens. Symmetric to the kill-switch test in
`test_dataflow_validation.py` for the other three consumers.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


class TestAnalyzeIrisPacksKillSwitch:
    def test_returns_empty_when_disabled(self, monkeypatch):
        from core.config import RaptorConfig
        from packages.codeql.query_runner import QueryRunner

        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", False)
        runner = QueryRunner.__new__(QueryRunner)  # bypass __init__

        result = runner.analyze_iris_packs(
            databases={"python": Path("./db")},
            out_dir=Path("./out"),
        )
        assert result == {}

    def test_runs_when_enabled_no_pack_root(self, monkeypatch, tmp_path):
        """Default-enabled with no pack root configured falls through to
        the empty-extras early-out — distinguishes from the kill-switch
        early-out (the disabled path skips even checking extras roots)."""
        from core.config import RaptorConfig
        from packages.codeql.query_runner import QueryRunner

        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])
        runner = QueryRunner.__new__(QueryRunner)
        result = runner.analyze_iris_packs(
            databases={"python": tmp_path / "db"},
            out_dir=tmp_path / "out",
        )
        assert result == {}


class TestCodeqlCliFlag:
    """`/codeql --no-iris-tier1` flips the master switch for this run.

    Exercises the REAL `/codeql` surface (`raptor_codeql.py`) — a
    previous version of this test simulated the argparse slice with a
    throwaway parser, which hid the fact that the dispatched script's
    own parser rejected the flag with "unrecognized arguments".
    """

    @staticmethod
    def _make_args(**overrides):
        from types import SimpleNamespace
        base = {
            "repo": "/tmp/some-repo",
            "out": None,
            "codeql_cli": None,
            "languages": None,
            "build_command": None,
            "force": False,
            "extended": False,
            "min_files": 1,
            "traced_build": False,
            "scan_only": False,
            "no_iris_tier1": False,
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def _run_workflow(self, args):
        """Run the workflow with a stub agent; return the switch value
        observed at scan time."""
        from unittest.mock import MagicMock, patch

        import raptor_codeql
        from core.config import RaptorConfig

        seen = {}

        def _scan(**_kwargs):
            seen["enabled"] = RaptorConfig.IRIS_TIER1_ENABLED
            return MagicMock(success=True, total_findings=0)

        agent = MagicMock()
        agent.run_autonomous_analysis.side_effect = _scan
        with patch.object(raptor_codeql, "CodeQLAgent", return_value=agent), \
             patch.object(raptor_codeql, "store_codeql_build_reliability"):
            raptor_codeql.run_autonomous_workflow(args)
        return seen["enabled"]

    def test_parser_accepts_flag(self):
        """The dispatched script's own argparse knows --no-iris-tier1."""
        import subprocess
        import sys as _sys
        r = subprocess.run(
            [_sys.executable, str(Path(__file__).resolve().parents[3]
                                  / "raptor_codeql.py"), "--help"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert r.returncode == 0, r.stderr
        assert "--no-iris-tier1" in r.stdout

    def test_flag_reaches_master_switch(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)
        enabled = self._run_workflow(self._make_args(no_iris_tier1=True))
        assert enabled is False

    def test_no_flag_leaves_switch_on(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)
        enabled = self._run_workflow(self._make_args())
        assert enabled is True
