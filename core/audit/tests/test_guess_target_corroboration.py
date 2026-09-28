"""Tests for libexec/raptor-audit ``_guess_target`` — the recovered
target must be corroborated against the ``target_path`` sealed into
``.raptor-run.json`` at run start."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType

_AUDIT_PATH = Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit"


import pytest

@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """User registries stay out of the real home: the root-conftest
    layer doing this is stripped from release extracts (conftest.py
    is export-ignore), so the pin must travel in-file."""
    from core.testing.state_isolation import pin_user_state_dirs
    pin_user_state_dirs(monkeypatch, tmp_path)


def _load_raptor_audit() -> ModuleType:
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = importlib.machinery.SourceFileLoader(
        "raptor_audit", str(_AUDIT_PATH),
    )
    spec = importlib.util.spec_from_file_location(
        "raptor_audit", str(_AUDIT_PATH), loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


audit_cli = _load_raptor_audit()


def _write_checklist(out_dir: Path, target_path: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "checklist.json").write_text(
        json.dumps({"target_path": target_path, "files": []}),
    )


class TestGuessTarget:
    def test_no_checklist_returns_none(self, tmp_path):
        assert audit_cli._guess_target(tmp_path) is None

    def test_recovers_target_without_metadata(self, tmp_path):
        """No .raptor-run.json (older runs) — unverifiable, accepted."""
        target = tmp_path / "repo"
        target.mkdir()
        out_dir = tmp_path / "out"
        _write_checklist(out_dir, str(target))
        assert audit_cli._guess_target(out_dir) == target

    def test_recovers_target_when_sealed_matches(self, tmp_path):
        from core.run.metadata import start_run
        target = tmp_path / "repo"
        target.mkdir()
        out_dir = tmp_path / "out"
        start_run(out_dir, "audit", target=target)
        _write_checklist(out_dir, str(target))
        assert audit_cli._guess_target(out_dir) == target

    def test_refuses_mismatched_target(self, tmp_path, capsys):
        """checklist.json redirected to a different tree than the run
        was started against — refuse and tell the operator to pass
        --target explicitly."""
        from core.run.metadata import start_run
        target = tmp_path / "repo"
        target.mkdir()
        attacker = tmp_path / "attacker-tree"
        attacker.mkdir()
        out_dir = tmp_path / "out"
        start_run(out_dir, "audit", target=target)
        _write_checklist(out_dir, str(attacker))

        assert audit_cli._guess_target(out_dir) is None
        err = capsys.readouterr().err
        assert "--target" in err
        assert "does not match" in err
