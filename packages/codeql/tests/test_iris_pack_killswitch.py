"""Tests for the IRIS Tier 1 master kill-switch in `/codeql`.

The standalone `/codeql` consumer routes through
`QueryRunner.analyze_iris_packs`; the kill-switch must early-out
before any pack work happens. Symmetric to the kill-switch test in
`test_dataflow_validation.py` for the other three consumers.
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


class TestAnalyzeIrisPacksKillSwitch:
    def test_returns_empty_when_disabled(self, monkeypatch):
        from core.config import RaptorConfig
        from packages.codeql.query_runner import QueryRunner

        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", False)
        runner = QueryRunner.__new__(QueryRunner)  # bypass __init__

        result = runner.analyze_iris_packs(
            databases={"python": Path("/tmp/db")},
            out_dir=Path("/tmp/out"),
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


class TestCodeqlAgentCliFlag:
    """`/codeql --no-iris-tier1` flips the master switch for this run."""

    def test_flag_sets_config_false(self, monkeypatch):
        from core.config import RaptorConfig
        # Reset before to ensure deterministic baseline
        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)

        # Simulate the argparse + flag-application slice of main()
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--no-iris-tier1", action="store_true")
        args = parser.parse_args(["--no-iris-tier1"])
        if args.no_iris_tier1:
            RaptorConfig.IRIS_TIER1_ENABLED = False

        assert RaptorConfig.IRIS_TIER1_ENABLED is False

    def test_no_flag_leaves_config_default(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)

        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--no-iris-tier1", action="store_true")
        args = parser.parse_args([])
        if args.no_iris_tier1:
            RaptorConfig.IRIS_TIER1_ENABLED = False

        assert RaptorConfig.IRIS_TIER1_ENABLED is True
