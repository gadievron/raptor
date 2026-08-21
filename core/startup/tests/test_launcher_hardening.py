"""Behavioural tests for the ``bin/raptor`` exec-boundary hardening block.

CLI-smoke style (cf. ``test_cli_smoke.py`` / the behavioural half of
``core/security/tests/test_launcher_env_strip.py``): the launcher is a
bash script, so every test spawns it as a subprocess with a controlled
environment and asserts on observable effects — stderr scrub lines, the
per-session TMPDIR tree, and (via a stub ``claude`` on PATH that prints
its inherited state) the umask floor and soft core-dump cap at the
final exec boundary.

Two invocation shapes are used:

* ``raptor -h`` — runs the hardening block, prints help, exits 0
  before the claude-required gate. Cheap; used for the PATH-scrub and
  TMPDIR-sweep assertions.
* full launch with a stub ``claude`` — exercises the whole path
  through ``exec claude``; the stub prints ``umask``, ``ulimit -S -c``
  and ``$TMPDIR`` so the exec-boundary state is directly observable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "bin" / "raptor"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="bash launcher"
)


def _system_path_dirs() -> list[str]:
    """Real dirs the launcher needs: python3's home plus the usual
    system bins (bash utilities: stat, dirname, du, find, clear)."""
    dirs = []
    py_dir = str(Path(sys.executable).resolve().parent)
    dirs.append(py_dir)
    for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if os.path.isdir(d):
            dirs.append(d)
    return dirs


def _run_launcher(
    tmp_path: Path,
    *args: str,
    path_entries: list[str] | None = None,
    extra_env: dict | None = None,
) -> subprocess.CompletedProcess:
    """Run bin/raptor with an isolated HOME/TMPDIR and a controlled PATH."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir(exist_ok=True)
    path = ":".join((path_entries or []) + _system_path_dirs())
    env = {
        "PATH": path,
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "TERM": "xterm",
        "_RAPTOR_TRUSTED": "1",
        **(extra_env or {}),
    }
    return subprocess.run(
        ["bash", str(LAUNCHER), *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=str(home),
        check=False,
    )


def _make_stub_claude(tmp_path: Path) -> Path:
    """A fake `claude` that prints the exec-boundary state and exits."""
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "claude"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "echo STUB_CLAUDE_RAN\n"
        'echo "UMASK=$(umask)"\n'
        'echo "ULIMIT_C=$(ulimit -S -c)"\n'
        'echo "TMPDIR_SEEN=${TMPDIR:-}"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub_dir


# ---------------------------------------------------------------------------
# PATH scrub (raptor -h — exits before the claude gate)
# ---------------------------------------------------------------------------


def test_world_writable_path_entry_dropped(tmp_path):
    ww = tmp_path / "ww"
    ww.mkdir()
    ww.chmod(0o777)
    r = _run_launcher(tmp_path, "-h", path_entries=[str(ww)])
    assert r.returncode == 0, r.stderr
    assert f"dropped unsafe PATH entry (world-writable dir): {ww}" in r.stderr


def test_sticky_bit_does_not_save_world_writable_entry(tmp_path):
    """o+w drops regardless of sticky — /tmp squatting works despite it."""
    ww = tmp_path / "sticky"
    ww.mkdir()
    ww.chmod(0o1777)
    r = _run_launcher(tmp_path, "-h", path_entries=[str(ww)])
    assert r.returncode == 0, r.stderr
    assert str(ww) in r.stderr
    assert "world-writable dir" in r.stderr


def test_empty_and_relative_entries_dropped(tmp_path):
    # Deliberate empty entry (leading colon) + relative entry.
    r = _run_launcher(
        tmp_path, "-h", path_entries=["", "relative/dir"]
    )
    assert r.returncode == 0, r.stderr
    assert "empty entry (resolves as cwd)" in r.stderr
    assert "relative entry): relative/dir" in r.stderr


def test_nonexistent_dir_kept_silently(tmp_path):
    missing = tmp_path / "does-not-exist"
    r = _run_launcher(tmp_path, "-h", path_entries=[str(missing)])
    assert r.returncode == 0, r.stderr
    assert str(missing) not in r.stderr


def test_allow_unsafe_path_keeps_with_warning(tmp_path):
    ww = tmp_path / "ww"
    ww.mkdir()
    ww.chmod(0o777)
    r = _run_launcher(
        tmp_path, "-h",
        path_entries=[str(ww)],
        extra_env={"RAPTOR_ALLOW_UNSAFE_PATH": "1"},
    )
    assert r.returncode == 0, r.stderr
    assert "keeping unsafe PATH entry" in r.stderr
    assert str(ww) in r.stderr
    assert "dropped unsafe PATH entry" not in r.stderr


def test_opt_out_skips_all_hardening(tmp_path):
    ww = tmp_path / "ww"
    ww.mkdir()
    ww.chmod(0o777)
    r = _run_launcher(
        tmp_path, "-h",
        path_entries=[str(ww), "relative/dir", ""],
        extra_env={"RAPTOR_NO_LAUNCHER_HARDENING": "1"},
    )
    assert r.returncode == 0, r.stderr
    assert "PATH entry" not in r.stderr
    # No session dir was created either.
    assert not list((tmp_path / "tmp").glob("raptor-*")), (
        "session TMPDIR machinery ran despite the opt-out"
    )


# ---------------------------------------------------------------------------
# The hardening's own helpers must not resolve through unvetted PATH
# ---------------------------------------------------------------------------


def _hostile_helpers(dirpath: Path, log: Path, *tools: str) -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    for tool in tools:
        stub = dirpath / tool
        stub.write_text(
            f"#!/bin/sh\necho PWNED-{tool} >> {log}\n"
            f"exec /usr/bin/{tool} \"$@\"\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)


def test_hostile_cwd_helpers_never_execute(tmp_path):
    """A leading empty (or relative) PATH entry + hostile stat/dirname/
    readlink in the cwd must never execute: the builtins-only pre-pass
    drops those entries before ANY external command runs, and the
    pinned resolver covers the hardening's own helpers."""
    log = tmp_path / "pwned.log"
    evil = tmp_path / "evil"
    _hostile_helpers(evil, log, "stat", "dirname", "readlink")
    for path_prefix in ["", "evil-rel"]:
        home = tmp_path / "home"
        home.mkdir(exist_ok=True)
        r = subprocess.run(
            ["bash", str(LAUNCHER), "-h"],
            capture_output=True, text=True, timeout=120, check=False,
            env={
                "PATH": ":".join([path_prefix] + _system_path_dirs()),
                "HOME": str(home), "TERM": "xterm",
                "TMPDIR": str(tmp_path / "tmp"),
            },
            cwd=str(evil),
        )
        assert r.returncode == 0, r.stderr
        assert "dropped unsafe PATH entry" in r.stderr
        assert not log.exists(), (
            f"hostile helper executed (PATH prefix {path_prefix!r}): "
            f"{log.read_text()}"
        )


def test_world_writable_entry_cannot_shadow_stat(tmp_path):
    """The stat(1) inspecting a world-writable PATH entry must not
    itself resolve through that entry."""
    log = tmp_path / "pwned.log"
    ww = tmp_path / "ww"
    _hostile_helpers(ww, log, "stat")
    ww.chmod(0o777)
    r = _run_launcher(tmp_path, "-h", path_entries=[str(ww)])
    assert r.returncode == 0, r.stderr
    assert f"world-writable dir): {ww}" in r.stderr
    assert not log.exists(), "fake stat inside the inspected entry ran"


def test_kept_empty_entry_warns_exactly_once(tmp_path):
    """Pre-pass warns; the full scrub honours that decision silently."""
    r = _run_launcher(
        tmp_path, "-h", path_entries=[""],
        extra_env={"RAPTOR_ALLOW_UNSAFE_PATH": "1"},
    )
    assert r.returncode == 0, r.stderr
    assert r.stderr.count("empty entry") == 1, r.stderr


def test_symlinked_launcher_still_resolves(tmp_path):
    """The pinned-resolver rewrite must not break symlink installs."""
    link_dir = tmp_path / "linkbin"
    link_dir.mkdir()
    (link_dir / "raptor").symlink_to(LAUNCHER)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    r = subprocess.run(
        ["bash", str(link_dir / "raptor"), "-h"],
        capture_output=True, text=True, timeout=120, check=False,
        env={
            "PATH": ":".join(_system_path_dirs()),
            "HOME": str(home), "TERM": "xterm",
            "TMPDIR": str(tmp_path / "tmp"),
        },
        cwd=str(home),
    )
    assert r.returncode == 0, r.stderr
    assert "Usage: raptor" in r.stdout


# ---------------------------------------------------------------------------
# Session TMPDIR + stale-sibling sweep (raptor -h)
# ---------------------------------------------------------------------------


def _uid_base(tmp_path: Path) -> Path:
    return tmp_path / "tmp" / f"raptor-{os.getuid()}"


def test_session_dir_created_under_custom_tmpdir(tmp_path):
    r = _run_launcher(tmp_path, "-h")
    assert r.returncode == 0, r.stderr
    base = _uid_base(tmp_path)
    assert base.is_dir()
    assert (base.stat().st_mode & 0o777) == 0o700
    sessions = list(base.glob("session-*-*"))
    assert len(sessions) == 1
    assert (sessions[0].stat().st_mode & 0o777) == 0o700


def test_stale_dead_pid_session_swept_live_kept(tmp_path):
    base = _uid_base(tmp_path)
    base.mkdir(parents=True, mode=0o700)
    # PID 1 exists (init) but is not ours to signal as non-root —
    # kill -0 still returns 0? No: EPERM makes kill -0 FAIL for an
    # unowned pid, which the sweep treats as dead. Use our own pid
    # for the live case and an impossible pid for the dead case.
    dead = base / "session-999999999-1234"
    dead.mkdir(mode=0o700)
    (dead / "litter.txt").write_text("x", encoding="utf-8")
    live = base / f"session-{os.getpid()}-42"
    live.mkdir(mode=0o700)
    nonmatching = base / "session-not-a-pid"
    nonmatching.mkdir(mode=0o700)
    r = _run_launcher(tmp_path, "-h")
    assert r.returncode == 0, r.stderr
    assert not dead.exists(), "dead-pid session dir survived the sweep"
    assert live.is_dir(), "live-pid session dir was swept"
    assert nonmatching.is_dir(), "non-pattern dir must never be touched"


def test_sweep_skips_symlinked_session_dir(tmp_path):
    base = _uid_base(tmp_path)
    base.mkdir(parents=True, mode=0o700)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("k", encoding="utf-8")
    link = base / "session-999999999-7"
    link.symlink_to(victim)
    r = _run_launcher(tmp_path, "-h")
    assert r.returncode == 0, r.stderr
    assert (victim / "keep.txt").exists(), (
        "sweep followed a symlink out of the session base"
    )


def test_squatted_base_disables_session_tmpdir(tmp_path):
    # A symlink at the base path simulates a squat: launcher must
    # refuse it and say so, not nest sessions inside it.
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "tmp").mkdir(exist_ok=True)
    _uid_base(tmp_path).symlink_to(target)
    r = _run_launcher(tmp_path, "-h")
    assert r.returncode == 0, r.stderr
    assert "session TMPDIR disabled" in r.stderr
    assert not list(target.glob("session-*")), (
        "session dir created through the squatted symlink"
    )


# ---------------------------------------------------------------------------
# Exec boundary (stub claude): umask floor, soft core cap, TMPDIR export
# ---------------------------------------------------------------------------


def _run_full_launch(tmp_path: Path, umask: str = "0") -> subprocess.CompletedProcess:
    stub_dir = _make_stub_claude(tmp_path)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir(exist_ok=True)
    env = {
        "PATH": ":".join([str(stub_dir)] + _system_path_dirs()),
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "TERM": "xterm",
    }
    # Outer bash loosens umask + core limit; the launcher must
    # restore the floor / cap before exec'ing the stub.
    script = (
        f"umask {umask}; ulimit -S -c unlimited 2>/dev/null; "
        f"exec bash '{LAUNCHER}'"
    )
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=str(home),
        check=False,
    )


def _stub_value(out: str, key: str) -> str:
    # `in`, not startswith: the launcher's `clear` prefixes the first
    # output line with terminal escape codes.
    for line in out.splitlines():
        if f"{key}=" in line:
            return line.split(f"{key}=", 1)[1]
    raise AssertionError(f"{key} not reported by stub claude: {out!r}")


def test_exec_boundary_umask_floored_and_core_capped(tmp_path):
    r = _run_full_launch(tmp_path, umask="0")
    assert "STUB_CLAUDE_RAN" in r.stdout, (r.stdout, r.stderr)
    assert _stub_value(r.stdout, "UMASK").endswith("022")
    assert _stub_value(r.stdout, "ULIMIT_C") == "0"


def test_exec_boundary_stricter_umask_preserved(tmp_path):
    r = _run_full_launch(tmp_path, umask="077")
    assert "STUB_CLAUDE_RAN" in r.stdout, (r.stdout, r.stderr)
    assert _stub_value(r.stdout, "UMASK").endswith("077")


def test_exec_boundary_session_tmpdir_exported(tmp_path):
    r = _run_full_launch(tmp_path)
    assert "STUB_CLAUDE_RAN" in r.stdout, (r.stdout, r.stderr)
    seen = _stub_value(r.stdout, "TMPDIR_SEEN")
    base = _uid_base(tmp_path)
    assert Path(seen).parent == base
    assert Path(seen).name.startswith("session-")


def test_soft_core_cap_child_can_reraise(tmp_path):
    """The cap is SOFT on purpose: crash-analysis / fuzz legs re-raise
    it for their targets. A child under the launcher must be able to
    lift the soft limit back up to the hard limit."""
    import resource
    hard = resource.getrlimit(resource.RLIMIT_CORE)[1]
    if hard == 0:
        pytest.skip("hard RLIMIT_CORE is 0 on this host — nothing to re-raise")
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "claude"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "ulimit -S -c unlimited 2>/dev/null || ulimit -S -c hard\n"
        'echo "RERAISED=$(ulimit -S -c)"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir(exist_ok=True)
    r = subprocess.run(
        ["bash", str(LAUNCHER)],
        capture_output=True, text=True, timeout=120, check=False,
        env={
            "PATH": ":".join([str(stub_dir)] + _system_path_dirs()),
            "HOME": str(home), "TMPDIR": str(tmpdir), "TERM": "xterm",
        },
        cwd=str(home),
    )
    assert "RERAISED=" in r.stdout, (r.stdout, r.stderr)
    assert _stub_value(r.stdout, "RERAISED") != "0"


def test_launcher_passes_bash_syntax_check():
    bash = shutil.which("bash")
    assert bash, "bash required"
    r = subprocess.run(
        [bash, "-n", str(LAUNCHER)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert r.returncode == 0, r.stderr
