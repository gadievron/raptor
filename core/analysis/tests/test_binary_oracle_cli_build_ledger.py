"""Tests for the traced-build ledger consultation seam in
resolve_binary_paths: build-produced auto-detect candidates lose
absent-suppression authority (ride the no-suppress channel), operator
assertions keep full authority, and a corrupt ledger fail-closes
without erroring the run."""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.analysis.binary_build_ledger import record_build_delta
from core.analysis.binary_oracle_cli import resolve_binary_paths
from core.hash import sha256_file


@pytest.fixture(autouse=True)
def _xdg_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _args(**overrides):
    base = {
        "binary": None,
        "binary_auto": False,
        "binary_edges": False,
        "no_binary_oracle": False,
        "target_kind": "auto",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _bin(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF" + payload)
    path.chmod(0o755)
    return path


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    return repo


def _ledger_with(repo: Path, binary: Path) -> None:
    """Seed the repo's ledger with *binary*'s content hash."""
    record_build_delta(
        repo, {}, {str(binary): sha256_file(binary)})


@patch("core.analysis.binary_oracle_cli._project_binaries",
       return_value=([], None))
class TestLedgerConsultation:
    def test_build_produced_candidate_loses_suppression(
            self, _proj, tmp_path, caplog):
        repo = _repo(tmp_path)
        planted = _bin(repo / "build" / "planted", b"by-build")
        _ledger_with(repo, planted)
        no_suppress: list = []
        with patch("core.analysis.binary_oracle_cli._autodetect_binaries",
                   return_value=[planted]), \
                caplog.at_level(logging.WARNING):
            paths = resolve_binary_paths(
                _args(), repo, "auto", no_suppress_out=no_suppress)
        # Still resolved — verdicts enrich at hint tier.
        assert str(planted) in paths
        assert str(planted) in no_suppress
        msg = " ".join(r.getMessage() for r in caplog.records)
        assert "traced build" in msg
        assert "--binary" in msg and "/project binary add" in msg

    def test_unrelated_untracked_binary_unaffected(
            self, _proj, tmp_path):
        repo = _repo(tmp_path)
        planted = _bin(repo / "build" / "planted", b"by-build")
        mine = _bin(repo / "build" / "mine", b"operator-built")
        _ledger_with(repo, planted)
        no_suppress: list = []
        with patch("core.analysis.binary_oracle_cli._autodetect_binaries",
                   return_value=[mine]):
            paths = resolve_binary_paths(
                _args(), repo, "auto", no_suppress_out=no_suppress)
        assert str(mine) in paths
        assert no_suppress == []

    def test_absent_ledger_flags_nothing(self, _proj, tmp_path):
        repo = _repo(tmp_path)
        b = _bin(repo / "build" / "app", b"x")
        no_suppress: list = []
        with patch("core.analysis.binary_oracle_cli._autodetect_binaries",
                   return_value=[b]):
            resolve_binary_paths(
                _args(), repo, "auto", no_suppress_out=no_suppress)
        assert no_suppress == []

    def test_corrupt_ledger_fail_closes_without_error(
            self, _proj, tmp_path, caplog):
        from core.analysis.binary_build_ledger import ledger_path
        repo = _repo(tmp_path)
        b = _bin(repo / "build" / "app", b"x")
        path = ledger_path(repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("tampered garbage\n")
        no_suppress: list = []
        with patch("core.analysis.binary_oracle_cli._autodetect_binaries",
                   return_value=[b]), \
                caplog.at_level(logging.WARNING):
            paths = resolve_binary_paths(
                _args(), repo, "auto", no_suppress_out=no_suppress)
        assert str(b) in paths
        assert str(b) in no_suppress
        assert any("cannot be verified" in r.getMessage()
                   for r in caplog.records)

    def test_explicit_binary_keeps_authority(self, _proj, tmp_path):
        # --binary is an operator assertion: suppresses auto-detect,
        # and even with --binary-auto re-enabling it, the declared
        # path never reaches the ledger gate.
        repo = _repo(tmp_path)
        planted = _bin(repo / "build" / "planted", b"by-build").resolve()
        _ledger_with(repo, planted)
        no_suppress: list = []
        with patch("core.analysis.binary_oracle_cli._autodetect_binaries",
                   return_value=[planted]):
            paths = resolve_binary_paths(
                _args(binary=[str(planted)], binary_auto=True),
                repo, "auto", no_suppress_out=no_suppress)
        assert str(planted) in paths
        assert no_suppress == []

    def test_log_escapes_hostile_candidate_names(
            self, _proj, tmp_path, caplog):
        repo = _repo(tmp_path)
        planted = _bin(repo / "build" / "app\x1b]0;owned\x07", b"evil")
        _ledger_with(repo, planted)
        with patch("core.analysis.binary_oracle_cli._autodetect_binaries",
                   return_value=[planted]), \
                caplog.at_level(logging.WARNING):
            resolve_binary_paths(_args(), repo, "auto")
        msg = " ".join(r.getMessage() for r in caplog.records)
        assert "\x1b" not in msg
        assert "\\x1b" in msg


class TestProjectDeclaredExempt:
    def test_project_store_path_keeps_authority(self, tmp_path):
        repo = _repo(tmp_path)
        planted = _bin(repo / "build" / "planted", b"by-build")
        _ledger_with(repo, planted)
        no_suppress: list = []
        with patch("core.analysis.binary_oracle_cli._project_binaries",
                   return_value=([str(planted)], "proj")), \
                patch("core.analysis.binary_oracle_cli."
                      "_autodetect_binaries", return_value=[planted]):
            paths = resolve_binary_paths(
                _args(), repo, "auto", no_suppress_out=no_suppress)
        assert str(planted) in paths
        assert no_suppress == []
