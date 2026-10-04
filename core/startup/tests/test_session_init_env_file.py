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
    # write_env_file() mutates os.environ["RAPTOR_DIR"] directly (its
    # production job: pin the var for the session process). Register
    # the var with monkeypatch FIRST so that in-test mutation is rolled
    # back at teardown — otherwise the hostile-path parametrizations
    # leave RAPTOR_DIR pointing at the fake checkout for every later
    # test in the session (observed: tracer spawns and subprocess
    # probes importing from the poisoned tree under shuffled order).
    monkeypatch.setenv("RAPTOR_DIR", str(REPO_ROOT))
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




def test_raptor_env_file_takes_priority(
    session_init, tmp_path, monkeypatch,
):
    """RAPTOR_ENV_FILE (Codex) is checked before CLAUDE_ENV_FILE."""
    root = tmp_path / "raptor"
    (root / "bin").mkdir(parents=True)
    raptor_env = tmp_path / "raptor.env"
    claude_env = tmp_path / "claude.env"
    monkeypatch.setenv("RAPTOR_ENV_FILE", str(raptor_env))
    monkeypatch.setenv("CLAUDE_ENV_FILE", str(claude_env))
    monkeypatch.setattr(session_init, "REPO_ROOT", root)

    session_init.write_env_file()

    assert raptor_env.exists()
    assert not claude_env.exists()


def test_claude_env_file_fallback(
    session_init, tmp_path, monkeypatch,
):
    """CLAUDE_ENV_FILE is used when RAPTOR_ENV_FILE is not set."""
    root = tmp_path / "raptor"
    (root / "bin").mkdir(parents=True)
    claude_env = tmp_path / "claude.env"
    monkeypatch.delenv("RAPTOR_ENV_FILE", raising=False)
    monkeypatch.setenv("CLAUDE_ENV_FILE", str(claude_env))
    monkeypatch.setattr(session_init, "REPO_ROOT", root)

    session_init.write_env_file()

    assert claude_env.exists()


def test_codex_session_seeds_credentials_in_env_file(
    session_init, tmp_path, monkeypatch,
):
    """CODEX=1 triggers session seeding; credentials land in the env file."""
    from unittest.mock import patch as mock_patch

    root = tmp_path / "raptor"
    (root / "bin").mkdir(parents=True)
    env_file = tmp_path / "raptor.env"
    registry = tmp_path / "registry"
    monkeypatch.setenv("RAPTOR_ENV_FILE", str(env_file))
    monkeypatch.delenv("CLAUDE_ENV_FILE", raising=False)
    monkeypatch.setenv("CODEX", "1")
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(registry))
    monkeypatch.setattr(session_init, "REPO_ROOT", root)

    fake_pid = 99999
    with mock_patch(
        "core.run.metadata._find_claude_ancestor", return_value=fake_pid,
    ):
        session_init.write_env_file()

    content = env_file.read_text(encoding="utf-8")
    assert "RAPTOR_SESSION_PID=" in content
    assert "RAPTOR_SESSION_TOKEN=" in content
    assert str(fake_pid) in content
    sessions_dir = registry / "sessions.d"
    entry = sessions_dir / str(fake_pid)
    assert entry.exists()
    entry_text = entry.read_text(encoding="utf-8")
    assert "seeded_by=codex-hook" in entry_text


def test_claude_session_does_not_seed(
    session_init, tmp_path, monkeypatch,
):
    """Without CODEX=1, no session credentials in the env file."""
    root = tmp_path / "raptor"
    (root / "bin").mkdir(parents=True)
    env_file = tmp_path / "claude.env"
    monkeypatch.delenv("CODEX", raising=False)
    monkeypatch.delenv("RAPTOR_ENV_FILE", raising=False)
    monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
    monkeypatch.setattr(session_init, "REPO_ROOT", root)

    session_init.write_env_file()

    content = env_file.read_text(encoding="utf-8")
    assert "RAPTOR_SESSION_PID" not in content
    assert "RAPTOR_SESSION_TOKEN" not in content


def test_import_does_not_leak_test_module(session_init):
    # exec_module registers nothing in sys.modules by default; keep it so.
    assert "raptor_session_init_under_test" not in sys.modules
