"""Symbolic (angr) channel wiring into _run_tool_chain.

Verifies that a ``{"type": "symbolic", "config": {"binary": ...}}``
chain entry dispatches ``run_symbolic_sweep`` and classifies the
outcome into the confirmed / errored / inconclusive / skipped buckets.
Also tests ``_resolve_binary_path`` for the binary-sentinel reverse
lookup.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from core.audit.orchestrator import _resolve_binary_path, _run_tool_chain
from core.audit.sweep import SweepResult


class _Cfg:
    """Minimal OrchestratorConfig stand-in."""

    def __init__(self, target: Path, out_dir: Path):
        self.target_path = target
        self.out_dir = out_dir
        self.codeql_db_path = None
        self.project_sinks = None
        self.tool_chain_early_exit = False


def _chain(binary: str) -> list[dict]:
    return [{"type": "symbolic", "config": {"binary": binary}}]


def _run(cfg, chain, *, errored=None, skipped=None, inconclusive=None):
    return _run_tool_chain(
        chain,
        config=cfg,
        file_path="binary:app",
        function_name="vuln_func",
        source=None,
        hypothesis="heap overflow in vuln_func",
        cwe="CWE-122",
        errored_types=errored,
        skipped_types=skipped,
        inconclusive_types=inconclusive,
    )


class TestSymbolicDispatch:
    def test_confirmed_witness_enters_confirmed_list(self, tmp_path):
        cfg = _Cfg(tmp_path, tmp_path / "out")
        cfg.out_dir.mkdir()
        witness = SweepResult(
            tool="symbolic", file_path="binary:app",
            function_name="vuln_func", outcome="confirmed",
            rule_id="symbolic-pc-hijack",
            matches=[{"rule_id": "symbolic-pc-hijack", "message": "w"}],
            details={"mode": "pc_hijack"},
        )
        with patch("core.audit.sweep.run_symbolic_sweep",
                   return_value=witness):
            confirmed = _run(cfg, _chain(str(tmp_path / "app")))
        assert any("symbolic:symbolic-pc-hijack" in c for c in confirmed)

    def test_inconclusive_not_in_confirmed(self, tmp_path):
        cfg = _Cfg(tmp_path, tmp_path / "out")
        cfg.out_dir.mkdir()
        inc = SweepResult(
            tool="symbolic", file_path="binary:app",
            function_name="vuln_func", outcome="inconclusive",
            rule_id="symbolic-reach",
            details={"reason": "no witness within budget"},
        )
        inconclusive: set = set()
        with patch("core.audit.sweep.run_symbolic_sweep",
                   return_value=inc):
            confirmed = _run(
                cfg, _chain(str(tmp_path / "app")),
                inconclusive=inconclusive,
            )
        assert not confirmed
        assert "symbolic" in inconclusive

    def test_error_recorded_in_errored_set(self, tmp_path):
        cfg = _Cfg(tmp_path, tmp_path / "out")
        cfg.out_dir.mkdir()
        err = SweepResult(
            tool="symbolic", file_path="binary:app",
            function_name="vuln_func", outcome="error",
            errors=["angr not installed"],
        )
        errored: set = set()
        with patch("core.audit.sweep.run_symbolic_sweep",
                   return_value=err):
            confirmed = _run(
                cfg, _chain(str(tmp_path / "app")),
                errored=errored,
            )
        assert not confirmed
        assert "symbolic" in errored

    def test_missing_binary_config_is_skipped(self, tmp_path):
        cfg = _Cfg(tmp_path, tmp_path / "out")
        cfg.out_dir.mkdir()
        skipped: set = set()
        confirmed = _run(cfg, _chain(""), skipped=skipped)
        assert not confirmed
        assert "symbolic" in skipped

    def test_reach_crash_receipt_string(self, tmp_path):
        cfg = _Cfg(tmp_path, tmp_path / "out")
        cfg.out_dir.mkdir()
        crash = SweepResult(
            tool="symbolic", file_path="binary:app",
            function_name="vuln_func", outcome="confirmed",
            rule_id="symbolic-reach-crash",
            matches=[{"rule_id": "symbolic-reach-crash", "message": "c"}],
            details={"mode": "reach"},
        )
        with patch("core.audit.sweep.run_symbolic_sweep",
                   return_value=crash):
            confirmed = _run(cfg, _chain(str(tmp_path / "app")))
        assert "symbolic:symbolic-reach-crash" in confirmed


class TestResolveBinaryPath:
    def test_stem_match_returns_path(self, tmp_path):
        binary = tmp_path / "myapp"
        binary.write_bytes(b"\x7fELF")
        cfg = _Cfg(tmp_path, tmp_path / "out")
        cfg.inventory = {
            "binary_oracle": {
                "binaries": [{"path": str(binary), "build_id": "abc"}],
            },
        }
        assert _resolve_binary_path(cfg, "binary:myapp") == binary

    def test_no_match_returns_none(self, tmp_path):
        cfg = _Cfg(tmp_path, tmp_path / "out")
        cfg.inventory = {
            "binary_oracle": {
                "binaries": [{"path": "/nonexistent/x", "build_id": "a"}],
            },
        }
        assert _resolve_binary_path(cfg, "binary:other") is None

    def test_no_inventory_returns_none(self, tmp_path):
        cfg = _Cfg(tmp_path, tmp_path / "out")
        cfg.inventory = None
        assert _resolve_binary_path(cfg, "binary:app") is None


class TestAngrMissingDegradation:
    """When angr is absent the symbolic entry never enters the chain."""

    def test_no_symbolic_entry_when_angr_unavailable(self, tmp_path):
        from core.audit.orchestrator import _hypothesis_to_tool_chain
        from core.audit.sweep import symbolic_applicable

        with patch("core.symbolic._availability.angr_available",
                   return_value=False):
            assert not symbolic_applicable("CWE-122", "binary:app")

        chain = _hypothesis_to_tool_chain(
            "heap overflow in parse()", "binary:app",
            cwe="CWE-122",
        )
        types = {e["type"] for e in chain}
        assert "symbolic" not in types

    def test_run_symbolic_sweep_returns_error_without_angr(self, tmp_path):
        from core.audit.sweep import run_symbolic_sweep

        with patch("core.symbolic._availability.angr_available",
                   return_value=False):
            res = run_symbolic_sweep(
                target_path=tmp_path / "bin",
                file_path="binary:bin",
                function_name="f",
                out_dir=tmp_path,
                cwe="CWE-122",
            )
        assert res.outcome == "error"
        assert "angr" in res.errors[0]
