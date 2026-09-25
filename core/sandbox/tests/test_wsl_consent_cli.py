"""The TTY-gated WSL host-consent CLI (libexec/raptor-wsl-consent).

Subprocess probes of the ceremony's boundary behaviour: the non-TTY
grant refusal (the gate that stops agent self-granting), the
fail-safe non-TTY revoke, the read-only status, the trust-marker
preamble, and — where a pty is available — the TTY-side preflight
refusal on a non-WSL host. The grant/write mechanics themselves are
unit-tested in test_host_consent.py; these tests pin the surface an
operator (or a hostile automation attempt) actually touches.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-wsl-consent"


def _env(tmp_path: Path, *, trusted: bool = True) -> dict:
    env = dict(os.environ)
    env.pop("CLAUDECODE", None)
    env.pop("_RAPTOR_TRUSTED", None)
    if trusted:
        env["_RAPTOR_TRUSTED"] = "1"
    env["XDG_DATA_HOME"] = str(tmp_path / "xdg")
    return env


def _run(tmp_path: Path, *args: str, trusted: bool = True,
         stdin=subprocess.DEVNULL) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        stdin=stdin, capture_output=True, text=True, timeout=60,
        env=_env(tmp_path, trusted=trusted), check=False)


def _marker(tmp_path: Path) -> Path:
    return tmp_path / "xdg" / "raptor" / "wsl-host-consent.json"


def test_trust_preamble_refuses_unmarked_invocation(tmp_path):
    r = _run(tmp_path, "status", trusted=False)
    assert r.returncode == 2
    assert "internal dispatch script" in r.stderr


def test_grant_refuses_non_tty_stdin(tmp_path):
    """The load-bearing gate: a piped/devnull stdin (every agent and
    script shape) is refused BEFORE any host probing, and nothing is
    written."""
    r = _run(tmp_path, "grant")
    assert r.returncode == 3
    assert "requires an interactive terminal" in r.stderr
    assert "cannot self-grant" in r.stderr
    assert not _marker(tmp_path).exists()


def test_grant_refuses_piped_confirmation(tmp_path):
    """Piping the confirmation text does not help — the TTY check
    fires regardless of what stdin would say."""
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "grant"],
        input="ns-only\n", capture_output=True, text=True, timeout=60,
        env=_env(tmp_path), check=False)
    assert r.returncode == 3
    assert "requires an interactive terminal" in r.stderr
    assert not _marker(tmp_path).exists()


@pytest.mark.skipif(sys.platform != "linux", reason="pty probe")
def test_grant_on_tty_still_preflights_the_host(tmp_path):
    """With a real (pseudo-)terminal on stdin the gate passes and the
    NEXT defence engages: grant-time preflight refuses on a host whose
    kernel is not WSL (this runner) — the ceremony can never record a
    marker whose premise does not hold."""
    import pty
    if os.path.exists("/proc/sys/kernel/osrelease"):
        release = Path("/proc/sys/kernel/osrelease").read_text(
            encoding="ascii", errors="replace")
        if "microsoft" in release.lower():
            pytest.skip("runner is a real WSL host")
    master, slave = pty.openpty()
    try:
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "grant"],
            stdin=slave, capture_output=True, text=True, timeout=60,
            env=_env(tmp_path), check=False)
    finally:
        os.close(master)
        os.close(slave)
    assert r.returncode == 3
    assert "grant refused" in r.stderr
    assert "does not identify as WSL" in r.stderr
    assert not _marker(tmp_path).exists()


def test_status_is_read_only_and_reports_absent(tmp_path):
    r = _run(tmp_path, "status")
    assert r.returncode == 0
    assert "present: no" in r.stdout
    assert "applies: no" in r.stdout
    assert not _marker(tmp_path).exists()


def test_revoke_without_marker_is_a_noop(tmp_path):
    r = _run(tmp_path, "revoke")
    assert r.returncode == 0
    assert "nothing to revoke" in r.stdout


def test_revoke_works_non_tty(tmp_path):
    """The documented asymmetry: revocation only raises the floor, so
    it stays available to unattended sessions."""
    marker = _marker(tmp_path)
    marker.parent.mkdir(parents=True)
    marker.write_text("{}", encoding="utf-8")
    r = _run(tmp_path, "revoke")
    assert r.returncode == 0
    assert "Revoked" in r.stdout
    assert "fail-closed default" in r.stdout
    assert not marker.exists()


def test_unknown_subcommand_and_usage(tmp_path):
    r = _run(tmp_path, "bogus")
    assert r.returncode == 1
    assert "unknown subcommand" in r.stderr
    r = _run(tmp_path)  # no args
    assert r.returncode == 1
    assert "Usage" in r.stderr
    r = _run(tmp_path, "--help")
    assert r.returncode == 0
    assert "grant" in r.stdout and "revoke" in r.stdout
