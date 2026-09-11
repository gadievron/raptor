"""Env-strip and keep-trust dispatch tests for libexec/raptor-seatbelt-shim.

Platform-agnostic: the shim's child branch simply execs its argv, so the
tests run it as a subprocess with a python probe target and no
sandbox-exec — exactly the mechanics test_seatbelt_shim.py uses. No
macOS, no seatbelt profile, no fds required.

Contract under test (mirrors raptor-pid1-shim):
  * default: everything in core.config's TARGET_ENV_STRIP_SET is
    stripped before the target execs;
  * `--keep-trust-markers` (argv, first token — only the spawn side can
    set it) keeps the trust markers and session credential but still
    strips the consumed fd markers and the untrusted legacy env flag.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="the shim forks; POSIX only",
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SHIM_PATH = REPO_ROOT / "libexec" / "raptor-seatbelt-shim"

_PROBE = ("import json, os, sys;"
          "print(json.dumps({'env': dict(os.environ),"
          " 'argv': sys.argv[1:]}))")


def _run_shim(*shim_args: str, env_extra: dict | None = None,
              target=None) -> subprocess.CompletedProcess:
    env = dict(os.environ, _RAPTOR_TRUSTED="1")
    env.update(env_extra or {})
    target = target if target is not None else [sys.executable, "-c", _PROBE]
    return subprocess.run(
        [sys.executable, "-I", str(SHIM_PATH), *shim_args, *target],
        capture_output=True, text=True, env=env, timeout=30,
    )


def _child_env(proc: subprocess.CompletedProcess) -> dict:
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["env"]


def test_default_strip_covers_target_env_strip_set():
    """Every name in the canonical strip set must be gone in the target —
    keeps the shim's inline tuple honest against core.config drift."""
    from core.config import RaptorConfig
    strip_set = RaptorConfig.TARGET_ENV_STRIP_SET
    extra = {name: "leaktest" for name in strip_set}
    extra["_RAPTOR_KEEP_TRUST_MARKERS"] = "1"  # legacy env flag: never trusted
    env = _child_env(_run_shim(env_extra=extra))
    for name in strip_set:
        assert name not in env, f"{name} leaked into the sandboxed target"
    assert "_RAPTOR_KEEP_TRUST_MARKERS" not in env


def test_keep_trust_markers_keeps_markers_and_credential():
    extra = {
        "CLAUDECODE": "1",
        "RAPTOR_SESSION_PID": "12345",
        "RAPTOR_SESSION_TOKEN": "tok",
        "RAPTOR_DIR": "somewhere",
        "_RAPTOR_KEEP_TRUST_MARKERS": "1",
    }
    proc = _run_shim("--keep-trust-markers", env_extra=extra)
    env = _child_env(proc)
    # Trust markers + session credential survive so the dispatched child
    # can drive libexec helpers past their inline trust gates.
    assert env.get("_RAPTOR_TRUSTED") == "1"
    assert env.get("CLAUDECODE") == "1"
    assert env.get("RAPTOR_SESSION_PID") == "12345"
    assert env.get("RAPTOR_SESSION_TOKEN") == "tok"
    # Consumed fd markers and the untrusted legacy env flag never cross.
    assert "_RAPTOR_STATUS_FD" not in env
    assert "_RAPTOR_DEATH_FD" not in env
    assert "_RAPTOR_KEEP_TRUST_MARKERS" not in env
    # The flag is consumed by the shim, never seen by the target argv.
    assert json.loads(proc.stdout)["argv"] == []


def test_keep_flag_without_argv_is_an_error():
    proc = _run_shim(target=["--keep-trust-markers"])
    assert proc.returncode == 2
    assert "missing sandbox-exec argv after --keep-trust-markers" in proc.stderr


def test_legacy_env_flag_alone_does_not_keep_markers():
    """Only the argv flag (spawn-side-controlled) grants keep-trust; a
    caller-supplied env key must not."""
    env = _child_env(_run_shim(env_extra={
        "_RAPTOR_KEEP_TRUST_MARKERS": "1", "CLAUDECODE": "1"}))
    assert "_RAPTOR_TRUSTED" not in env
    assert "CLAUDECODE" not in env


def test_exit_status_mirrored_with_keep_flag():
    proc = _run_shim(
        "--keep-trust-markers",
        target=["/bin/sh", "-c", "exit 5"],
    )
    assert proc.returncode == 5
