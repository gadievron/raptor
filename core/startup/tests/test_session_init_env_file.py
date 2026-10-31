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
    monkeypatch.delenv("CODEX", raising=False)
    monkeypatch.delenv("RAPTOR_ENV_FILE", raising=False)
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


def _codex_session_fixtures(monkeypatch, tmp_path):
    """Shared setup for Codex session tests: registry, identity mocks."""
    from unittest.mock import patch as mock_patch

    registry = tmp_path / "registry"
    sessions_dir = registry / "sessions.d"
    monkeypatch.setenv("CODEX", "1")
    monkeypatch.setenv("RAPTOR_CODEX_HOOK", "1")
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(registry))
    monkeypatch.delenv("RAPTOR_SESSION_PID", raising=False)
    monkeypatch.delenv("RAPTOR_SESSION_TOKEN", raising=False)

    from core.project import sessions as _sessions
    monkeypatch.setattr(_sessions, "SESSIONS_DIR", sessions_dir)

    fake_identity = {
        "starttime": "12345", "boot_id": "test-boot-id",
        "pidns": "4026531836",
    }
    return registry, sessions_dir, fake_identity, mock_patch


def test_codex_session_seeds_registry_without_shared_shell_file(
    session_init, tmp_path, monkeypatch,
):
    """CODEX=1 seeds credentials but never writes a shared executable env file."""
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    root = tmp_path / "raptor"
    (root / "bin").mkdir(parents=True)
    env_file = tmp_path / "raptor.env"
    monkeypatch.setenv("RAPTOR_ENV_FILE", str(env_file))
    monkeypatch.delenv("CLAUDE_ENV_FILE", raising=False)
    monkeypatch.setattr(session_init, "REPO_ROOT", root)

    fake_pid = 99999
    with mock_patch(
        "core.project.sessions.resolve_codex_owner_pid",
        return_value=fake_pid,
    ), mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ):
        session_init._seed_codex_session()
        session_init.write_env_file()

    assert not env_file.exists()
    assert session_init.os.environ["RAPTOR_SESSION_PID"] == str(fake_pid)
    assert session_init.os.environ["RAPTOR_SESSION_TOKEN"]
    entry = sessions_dir / str(fake_pid)
    assert entry.exists()
    entry_text = entry.read_text(encoding="utf-8")
    assert "seeded_by=codex-hook" in entry_text


def test_codex_session_reentry_preserves_project(
    session_init, tmp_path, monkeypatch,
):
    """Repeated _seed_codex_session must not destroy an existing project."""
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    root = tmp_path / "raptor"
    (root / "bin").mkdir(parents=True)
    monkeypatch.setattr(session_init, "REPO_ROOT", root)

    fake_pid = 99998
    with mock_patch(
        "core.project.sessions.resolve_codex_owner_pid",
        return_value=fake_pid,
    ), mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ), mock_patch(
        "core.project.sessions._identity_matches",
        return_value=True,
    ):
        result1 = session_init._seed_codex_session()
        assert result1 is not None
        pid1, token1 = result1

        from core.project.sessions import bind_session
        bind_session("myproject", pid=fake_pid)

        result2 = session_init._seed_codex_session()
        assert result2 is not None
        pid2, token2 = result2

    assert pid1 == pid2
    assert token1 == token2
    from core.project.sessions import _parse_entry
    fields = _parse_entry(sessions_dir / str(fake_pid))
    assert fields.get("project") == "myproject"


def test_codex_session_default_registry_no_crash(
    session_init, tmp_path, monkeypatch,
):
    """Without RAPTOR_REGISTRY_HOME, the seeder must not TypeError."""
    _, _, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))
    monkeypatch.delenv("RAPTOR_REGISTRY_HOME", raising=False)

    with mock_patch(
        "core.project.sessions.resolve_codex_owner_pid",
        return_value=99997,
    ), mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ):
        result = session_init._seed_codex_session()
    assert result is not None


def test_codex_session_concurrent_init_same_token(
    session_init, tmp_path, monkeypatch,
):
    """Two concurrent ensure_codex_session calls must yield the same token."""
    import threading
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    fake_pid = 99996
    results = [None, None]

    from core.project.sessions import ensure_codex_session

    def seeder(idx):
        results[idx] = ensure_codex_session(fake_pid)

    with mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ), mock_patch(
        "core.project.sessions._identity_matches",
        return_value=True,
    ):
        t1 = threading.Thread(target=seeder, args=(0,))
        t2 = threading.Thread(target=seeder, args=(1,))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

    assert results[0] is not None
    assert results[1] is not None
    _, tok1 = results[0]
    _, tok2 = results[1]
    assert tok1 == tok2, "concurrent seeders must converge on one token"


def test_codex_session_failed_write_returns_none(
    session_init, tmp_path, monkeypatch,
):
    """If the atomic write fails, ensure_codex_session returns None."""
    _, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    fake_pid = 99995
    from core.project.sessions import ensure_codex_session

    with mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ), mock_patch(
        "core.project.sessions._atomic_write",
        side_effect=OSError("disk full"),
    ):
        result = ensure_codex_session(fake_pid)
    assert result is None


def test_codex_session_respects_active_bookmark(
    session_init, tmp_path, monkeypatch,
):
    """A fresh Codex session with an .active bookmark inherits the project."""
    import json
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    projects_dir = registry / "projects"
    projects_dir.mkdir(parents=True)
    proj_file = projects_dir / "myproj.json"
    proj_file.write_text(json.dumps({"name": "myproj"}), encoding="utf-8")
    active_link = projects_dir / ".active"
    active_link.symlink_to("myproj.json")

    fake_pid = 99994
    from core.project.sessions import ensure_codex_session

    with mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ):
        result = ensure_codex_session(fake_pid)

    assert result is not None
    from core.project.sessions import _parse_entry
    fields = _parse_entry(sessions_dir / str(fake_pid))
    assert fields.get("project") == "myproj"


def test_codex_stale_identity_clears_predecessor_ledger(
    session_init, tmp_path, monkeypatch,
):
    """A stale v2 predecessor's run ledger must not survive identity replacement."""
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    fake_pid = 99993
    sessions_dir.mkdir(parents=True, exist_ok=True)
    # Write a stale v2 entry with a DIFFERENT starttime (predecessor).
    old_entry = sessions_dir / str(fake_pid)
    old_entry.write_text(
        "v=2\nproject=oldproj\nsince=2026-01-01T00:00:00+00:00\n"
        "starttime=00000\nboot_id=old-boot\npidns=111\n"
        "token=oldtoken\nseeded_by=flag\n",
        encoding="utf-8",
    )
    # Write a predecessor run ledger and a pin witness.
    old_ledger = sessions_dir / f"{fake_pid}.run"
    old_ledger.write_text("old-run-id scan /target 2026-01-01T00:00:00\n",
                          encoding="utf-8")

    from core.project.sessions import ensure_codex_session

    with mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ):
        result = ensure_codex_session(fake_pid)

    assert result is not None
    _, token = result
    assert token != "oldtoken"
    # Predecessor ledger must be gone.
    assert not old_ledger.exists(), "stale predecessor ledger survived"
    # New entry must have fresh identity.
    from core.project.sessions import _parse_entry
    fields = _parse_entry(sessions_dir / str(fake_pid))
    assert fields["starttime"] == fake_identity["starttime"]
    assert fields.get("token") == token


def test_codex_valid_identity_retains_ledger_and_since(
    session_init, tmp_path, monkeypatch,
):
    """A valid existing entry retains its run records, token, project, since."""
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    fake_pid = 99992
    sessions_dir.mkdir(parents=True, exist_ok=True)
    entry = sessions_dir / str(fake_pid)
    original_since = "2026-06-15T12:00:00+00:00"
    entry.write_text(
        f"v=2\nproject=kept\nsince={original_since}\n"
        f"starttime={fake_identity['starttime']}\n"
        f"boot_id={fake_identity['boot_id']}\n"
        f"pidns={fake_identity['pidns']}\n"
        "token=existingtoken\nseeded_by=codex-hook\n",
        encoding="utf-8",
    )
    ledger = sessions_dir / f"{fake_pid}.run"
    ledger.write_text("run-001 scan /tgt 2026-06-15T12:01:00\n",
                      encoding="utf-8")

    from core.project.sessions import ensure_codex_session

    with mock_patch(
        "core.project.sessions._identity_matches",
        return_value=True,
    ):
        result = ensure_codex_session(fake_pid)

    assert result is not None
    pid_str, token = result
    assert token == "existingtoken"
    assert ledger.exists(), "live session ledger must survive"
    from core.project.sessions import _parse_entry
    fields = _parse_entry(entry)
    assert fields["project"] == "kept"
    assert fields["since"] == original_since


def test_codex_tokenless_upgrade_preserves_since_and_binding(
    session_init, tmp_path, monkeypatch,
):
    """Token-only upgrade preserves since, project, and identity."""
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    fake_pid = 99991
    sessions_dir.mkdir(parents=True, exist_ok=True)
    entry = sessions_dir / str(fake_pid)
    original_since = "2026-03-01T09:00:00+00:00"
    entry.write_text(
        f"v=2\nproject=bound\nsince={original_since}\n"
        f"starttime={fake_identity['starttime']}\n"
        f"boot_id={fake_identity['boot_id']}\n"
        f"pidns={fake_identity['pidns']}\n"
        "seeded_by=codex-hook\n",
        encoding="utf-8",
    )
    ledger = sessions_dir / f"{fake_pid}.run"
    ledger.write_text("run-x scan /tgt 2026-03-01T09:01:00\n",
                      encoding="utf-8")

    from core.project.sessions import ensure_codex_session

    with mock_patch(
        "core.project.sessions._identity_matches",
        return_value=True,
    ):
        result = ensure_codex_session(fake_pid)

    assert result is not None
    _, token = result
    assert token  # got a fresh token
    from core.project.sessions import _parse_entry
    fields = _parse_entry(entry)
    assert fields["project"] == "bound"
    assert fields["since"] == original_since
    assert ledger.exists(), "ledger must survive token-only upgrade"


def test_codex_bookmark_invalid_name_ignored(
    session_init, tmp_path, monkeypatch,
):
    """A bookmark pointing at 'invalid name.json' must not be followed."""
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    projects_dir = registry / "projects"
    projects_dir.mkdir(parents=True)
    bad_file = projects_dir / "invalid name.json"
    bad_file.write_text("{}", encoding="utf-8")
    (projects_dir / ".active").symlink_to("invalid name.json")

    fake_pid = 99990
    from core.project.sessions import ensure_codex_session

    with mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ):
        result = ensure_codex_session(fake_pid)

    assert result is not None
    from core.project.sessions import _parse_entry, NONE_SENTINEL
    fields = _parse_entry(sessions_dir / str(fake_pid))
    assert fields["project"] == NONE_SENTINEL


def test_codex_bookmark_directory_ignored(
    session_init, tmp_path, monkeypatch,
):
    """A bookmark pointing at a directory (not a file) must not be followed."""
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    projects_dir = registry / "projects"
    projects_dir.mkdir(parents=True)
    (projects_dir / "dirproj.json").mkdir()  # directory, not file
    (projects_dir / ".active").symlink_to("dirproj.json")

    fake_pid = 99989
    from core.project.sessions import ensure_codex_session

    with mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ):
        result = ensure_codex_session(fake_pid)

    assert result is not None
    from core.project.sessions import _parse_entry, NONE_SENTINEL
    fields = _parse_entry(sessions_dir / str(fake_pid))
    assert fields["project"] == NONE_SENTINEL


def test_codex_credentials_not_in_claude_env_file(
    session_init, tmp_path, monkeypatch,
):
    """Without CODEX=1, credentials must not leak into the env file."""
    root = tmp_path / "raptor"
    (root / "bin").mkdir(parents=True)
    env_file = tmp_path / "claude.env"
    monkeypatch.delenv("CODEX", raising=False)
    monkeypatch.delenv("RAPTOR_ENV_FILE", raising=False)
    monkeypatch.setenv("CLAUDE_ENV_FILE", str(env_file))
    monkeypatch.setattr(session_init, "REPO_ROOT", root)
    monkeypatch.setenv("RAPTOR_SESSION_PID", "12345")
    monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "secret")

    session_init.write_env_file()

    content = env_file.read_text(encoding="utf-8")
    assert "RAPTOR_SESSION_PID" not in content
    assert "RAPTOR_SESSION_TOKEN" not in content


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


def test_codex_own_repair_preserves_token_and_project(
    session_init, tmp_path, monkeypatch,
):
    """Own-repair (corrupt stamp, matching env credential) must preserve
    the existing token and project — not mint a fresh token or read the
    bookmark."""
    registry, sessions_dir, fake_identity, mock_patch = (
        _codex_session_fixtures(monkeypatch, tmp_path))

    fake_pid = 99988
    existing_token = "own-repair-tok-abc"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    entry = sessions_dir / str(fake_pid)
    entry.write_text(
        "v=2\nproject=chosen\nsince=2026-05-01T10:00:00+00:00\n"
        "starttime=CORRUPT\nboot_id=CORRUPT\npidns=CORRUPT\n"
        f"token={existing_token}\nseeded_by=codex-hook\n",
        encoding="utf-8",
    )
    ledger = sessions_dir / f"{fake_pid}.run"
    ledger.write_text("run-repair scan /tgt 2026-05-01T10:01:00\n",
                      encoding="utf-8")

    monkeypatch.setenv("RAPTOR_SESSION_PID", str(fake_pid))
    monkeypatch.setenv("RAPTOR_SESSION_TOKEN", existing_token)

    from core.project.sessions import ensure_codex_session

    with mock_patch(
        "core.project.sessions._identity_for",
        return_value=fake_identity,
    ):
        result = ensure_codex_session(fake_pid)

    assert result is not None
    pid_str, token = result
    assert token == existing_token, "own-repair must keep the existing token"
    assert ledger.exists(), "own-repair must preserve the run ledger"
    from core.project.sessions import _parse_entry
    fields = _parse_entry(entry)
    assert fields["project"] == "chosen", "own-repair must keep the project"
    assert fields["starttime"] == fake_identity["starttime"], \
        "identity stamp must be repaired"


def test_import_does_not_leak_test_module(session_init):
    # exec_module registers nothing in sys.modules by default; keep it so.
    assert "raptor_session_init_under_test" not in sys.modules


def test_claude_host_with_inherited_codex_marker_keeps_native_env_file(session_init, tmp_path, monkeypatch):
    monkeypatch.setenv('CLAUDECODE', '1')
    monkeypatch.setenv('CODEX', '1')
    monkeypatch.delenv('RAPTOR_CODEX_HOOK', raising=False)
    monkeypatch.setenv('RAPTOR_SESSION_PID', '12345')
    monkeypatch.setenv('RAPTOR_SESSION_TOKEN', 'inherited-codex-token')
    file = tmp_path / 'claude-env'
    monkeypatch.setenv('CLAUDE_ENV_FILE', str(file))
    assert session_init._seed_codex_session() is None
    session_init.write_env_file()
    text = file.read_text()
    assert 'RAPTOR_DIR=' in text
    assert 'inherited-codex-token' not in text
    assert 'RAPTOR_SESSION_PID=' not in text


@pytest.mark.parametrize('session_id', ['', 'not-a-session', 'A' * 36])
def test_explicit_codex_bootstrap_rejects_invalid_session(monkeypatch, session_id):
    import runpy
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    monkeypatch.setenv('CODEX_THREAD_ID', session_id)
    monkeypatch.setattr(sys, 'argv', [str(SCRIPT), '--codex-bootstrap'])
    with pytest.raises(SystemExit, match='valid CODEX_THREAD_ID'):
        runpy.run_path(str(SCRIPT))


def test_native_codex_startup_still_reads_hook_stdin(session_init, monkeypatch):
    import io
    monkeypatch.setattr(sys, 'stdin', io.StringIO(
        '{"hook_event_name":"SessionStart","session_id":"from-native-hook"}'))
    assert session_init.read_codex_start_payload()['session_id'] == 'from-native-hook'


def test_explicit_codex_bootstrap_does_not_read_stdin(monkeypatch):
    import runpy
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    sid = '11111111-1111-1111-1111-111111111111'
    monkeypatch.setenv('CODEX_THREAD_ID', sid)
    monkeypatch.setenv('RAPTOR_DIR', str(REPO_ROOT))
    monkeypatch.setenv('CODEX', '')
    monkeypatch.setenv('RAPTOR_CODEX_HOOK', '')
    monkeypatch.setattr(sys, 'argv', [str(SCRIPT), '--codex-bootstrap'])
    module = runpy.run_path(str(SCRIPT))
    assert module['_is_codex_host']()
    assert module['read_codex_start_payload']() == {
        'hook_event_name': 'SessionStart', 'session_id': sid}


def test_launcher_context_formatting_needs_no_codex_startup(tmp_path):
    import json
    import os
    caller = str(tmp_path / 'caller with spaces')
    target = 'a target; $(false); "quoted"'
    result = subprocess.run(
        [sys.executable, '-I', str(SCRIPT), '--codex-launch-context', caller, target],
        env={**os.environ, '_RAPTOR_TRUSTED': '1', 'HOME': str(tmp_path),
             'CODEX_THREAD_ID': '11111111-1111-1111-1111-111111111111',
             'RAPTOR_CODEX_ENVIRONMENT': '1'},
        capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'caller_dir': caller, 'launch_target': target}
    assert not list(tmp_path.iterdir())
