"""The SessionStart hook writes CLAUDE_ENV_FILE, which the session
shell *sources* — the checkout path must be written shell-safe.
Regression: an f-string interpolated the path bare inside double
quotes, so a checkout under a directory named ``$(cmd)``, a backtick
form, or one containing ``"`` executed shell in every session."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-session-init"


@pytest.fixture
def session_init(monkeypatch):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    loader = importlib.machinery.SourceFileLoader(
        "raptor_session_init_under_test", str(SCRIPT),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _source_and_read(env_file: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c",
         f'source {str(env_file)!r} && printf "%s" "$RAPTOR_DIR"'],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


@pytest.mark.parametrize("hostile_dir", [
    'evil$(touch {marker})',
    'evil`touch {marker}`',
    'evil"; touch {marker}; "',
])
def test_hostile_checkout_path_does_not_execute(
    session_init, tmp_path, monkeypatch, hostile_dir,
):
    marker = tmp_path / "pwned"
    root = tmp_path / hostile_dir.format(marker=marker)
    (root / "bin").mkdir(parents=True)
    env_file = tmp_path / "env"
    monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
    monkeypatch.setattr(session_init, "REPO_ROOT", root)

    session_init.write_env_file()

    proc = _source_and_read(env_file)
    assert proc.returncode == 0, proc.stderr
    assert not marker.exists(), "hostile path executed on source"
    # The variable round-trips byte-exact.
    assert proc.stdout == str(root)


def test_benign_path_roundtrips_and_extends_path(
    session_init, tmp_path, monkeypatch,
):
    root = tmp_path / "raptor"
    (root / "bin").mkdir(parents=True)
    env_file = tmp_path / "env"
    monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
    monkeypatch.setattr(session_init, "REPO_ROOT", root)

    session_init.write_env_file()

    proc = subprocess.run(
        ["bash", "-c",
         f'PATH=/usr/bin; source {str(env_file)!r} && printf "%s" "$PATH"'],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == f"/usr/bin:{root / 'bin'}"


def test_import_does_not_leak_test_module(session_init):
    # exec_module registers nothing in sys.modules by default; keep it so.
    assert "raptor_session_init_under_test" not in sys.modules
