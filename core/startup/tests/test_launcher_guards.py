"""Behavioural tests for ``bin/raptor`` launch-path guards.

Same CLI-smoke shape as ``test_launcher_hardening.py``: the launcher is
a bash script, so each test spawns it with a controlled environment and
asserts on observable effects (stderr messages, exit codes, and — via a
stub ``claude`` on PATH — the state and argv at the final exec
boundary).

Covered guards:

* RAPTOR_CALLER_DIR control-byte refusal — must actually match C0
  bytes (newline, ESC, tab, ...). NUL needs no case: bash variables
  cannot hold NUL, so ``$(pwd)`` can never carry one into the check.
* ``--version`` fast path — must run AFTER the dangerous-env strip so
  the exec'd interpreter cannot be steered by PYTHONPATH et al.
* ``clear`` is best-effort — a TERM-less environment must not abort
  the launcher under ``set -e``.
* Control-stripped TARGET — the trust-check target and the initial
  prompt must name the same (stripped) path.
* ``bin/cve-env`` / ``bin/cve-diff`` — the PYTHON*-family sweep from
  ``bin/raptor-sca`` applies before their interpreters start.
"""

from __future__ import annotations

import os
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
    dirs = [str(Path(sys.executable).resolve().parent)]
    for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if os.path.isdir(d):
            dirs.append(d)
    return dirs


def _make_stub_claude(tmp_path: Path) -> Path:
    """A fake ``claude`` that reports its argv and inherited env."""
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "claude"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "echo STUB_CLAUDE_RAN\n"
        'echo "CALLER_DIR_SEEN=${RAPTOR_CALLER_DIR:-}"\n'
        'printf \'ARG:%s\\n\' "$@"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub_dir


def _launch(
    tmp_path: Path,
    *args: str,
    cwd: Path | None = None,
    term: str | None = "xterm",
    extra_env: dict | None = None,
) -> subprocess.CompletedProcess:
    stub_dir = _make_stub_claude(tmp_path)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir(exist_ok=True)
    env = {
        "PATH": ":".join([str(stub_dir)] + _system_path_dirs()),
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        **(extra_env or {}),
    }
    if term is not None:
        env["TERM"] = term
    return subprocess.run(
        ["bash", str(LAUNCHER), *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=str(cwd or home),
        check=False,
    )


# ---------------------------------------------------------------------------
# RAPTOR_CALLER_DIR control-byte guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("byte,label", [("\n", "newline"), ("\x1b", "esc")])
def test_caller_dir_with_control_byte_refused(tmp_path, byte, label):
    hostile = tmp_path / f"a{byte}b"
    hostile.mkdir()
    r = _launch(tmp_path, cwd=hostile)
    assert r.returncode == 1, (label, r.stdout, r.stderr)
    assert "control bytes" in r.stderr, (label, r.stderr)
    assert "STUB_CLAUDE_RAN" not in r.stdout, label


def test_caller_dir_plain_path_allowed(tmp_path):
    plain = tmp_path / "plain-dir"
    plain.mkdir()
    r = _launch(tmp_path, cwd=plain)
    assert "STUB_CLAUDE_RAN" in r.stdout, (r.stdout, r.stderr)
    seen = [
        ln.split("CALLER_DIR_SEEN=", 1)[1]
        for ln in r.stdout.splitlines()
        if "CALLER_DIR_SEEN=" in ln
    ]
    assert seen and seen[0] == str(plain), r.stdout


# ---------------------------------------------------------------------------
# --version fast path runs after the dangerous-env strip
# ---------------------------------------------------------------------------


def test_version_fast_path_env_stripped(tmp_path):
    """PYTHONPATH must not survive into the --version interpreter.

    Mechanism: a ``sitecustomize.py`` on PYTHONPATH is imported at
    interpreter start and drops a marker file. The control leg proves
    the mechanism fires for a plain python3; the launcher leg proves
    the strip removed PYTHONPATH before exec'ing python3.
    """
    payload = tmp_path / "payload"
    payload.mkdir()
    marker = tmp_path / "marker"
    (payload / "sitecustomize.py").write_text(
        f"import pathlib\npathlib.Path({str(marker)!r}).write_text('x')\n",
        encoding="utf-8",
    )
    env = {
        "PATH": ":".join(_system_path_dirs()),
        "HOME": str(tmp_path / "home"),
        "TERM": "xterm",
        "PYTHONPATH": str(payload),
    }
    (tmp_path / "home").mkdir(exist_ok=True)

    # Control: the payload mechanism works for an unstripped interpreter.
    subprocess.run(
        [sys.executable, "-c", "pass"],
        env=env, capture_output=True, timeout=60, check=False,
    )
    assert marker.exists(), "control leg: sitecustomize never fired"
    marker.unlink()

    r = subprocess.run(
        ["bash", str(LAUNCHER), "--version"],
        env=env, capture_output=True, text=True, timeout=120,
        cwd=str(tmp_path / "home"), check=False,
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert not marker.exists(), (
        "PYTHONPATH survived into the --version interpreter"
    )


# ---------------------------------------------------------------------------
# clear is best-effort under set -e
# ---------------------------------------------------------------------------


def test_termless_launch_survives_clear(tmp_path):
    r = _launch(tmp_path, term=None)
    assert "STUB_CLAUDE_RAN" in r.stdout, (r.stdout, r.stderr)


# ---------------------------------------------------------------------------
# Control-stripped TARGET: prompt and trust-gate name the same path
# ---------------------------------------------------------------------------


def test_control_byte_target_stripped_consistently(tmp_path):
    stripped = tmp_path / "targetdir"
    stripped.mkdir()
    raw = str(stripped.parent / "target\ndir")
    r = _launch(tmp_path, raw)
    assert "contained control bytes" in r.stderr, r.stderr
    assert "STUB_CLAUDE_RAN" in r.stdout, (r.stdout, r.stderr)
    prompt_args = [
        ln for ln in r.stdout.splitlines() if ln.startswith("ARG:/raptor")
    ]
    assert prompt_args, r.stdout
    # The prompt names the stripped spelling; the raw (unstripped)
    # spelling must not leak into the exec'd argv.
    assert prompt_args[-1] == f"ARG:/raptor {stripped.parent}/targetdir"


# ---------------------------------------------------------------------------
# cve-env / cve-diff: PYTHON*-family sweep before exec python3
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("launcher", ["cve-env", "cve-diff"])
def test_cve_launchers_sweep_python_family(tmp_path, launcher):
    """PYTHONWARNINGS et al. must not survive into the interpreter.

    A stub ``python3`` on PATH reports the PYTHON* env it inherits, so
    no real CLI deps are needed. PYTHONPATH is exempt: the launcher
    re-sets it explicitly after the sweep.
    """
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "python3"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "env | grep '^PYTHON' || true\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    env = {
        "PATH": ":".join([str(stub_dir)] + _system_path_dirs()),
        "HOME": str(tmp_path),
        "PYTHONWARNINGS": "error::UserWarning",
        "PYTHONFAULTHANDLER": "1",
    }
    r = subprocess.run(
        ["bash", str(REPO_ROOT / "bin" / launcher)],
        env=env, capture_output=True, text=True, timeout=60,
        cwd=str(tmp_path), check=False,
    )
    assert "PYTHONWARNINGS" not in r.stdout, (r.stdout, r.stderr)
    assert "PYTHONFAULTHANDLER" not in r.stdout, (r.stdout, r.stderr)
    # Two-direction: the launcher still hands the interpreter its own
    # explicit PYTHONPATH (repo root first).
    assert "PYTHONPATH=" in r.stdout, (r.stdout, r.stderr)
