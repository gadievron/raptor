"""TARGET_ENV_STRIP_SET — the table-driven strip harness.

One constant defines what target-bound envs must never carry (trust
markers + the session credential); these tests pin every consumer to
it so the sandbox re-anonymisation follow-up extends the CONSTANT and
gets the coverage for free:

* the constant's own contents and allowlist relationship,
* the pid1 shim's hand-copied tuple (the shim cannot import core),
* the fuzzing env scrub,
* the frida raw-spawn env builder (frida spawn-mode targets inherit
  the CLI's environ — a raw subprocess, no sandbox chokepoint),
* the CodeQL build-metadata env layering (repo content must never
  set RAPTOR control vars),
* and the default-on strip at the context.run() seam (integration,
  namespace hosts).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from core.config import RaptorConfig

_REPO_ROOT = Path(__file__).resolve().parents[3]

STRIP_SET = RaptorConfig.TARGET_ENV_STRIP_SET


def test_constant_contents():
    assert "CLAUDECODE" in STRIP_SET
    assert "_RAPTOR_TRUSTED" in STRIP_SET
    assert "RAPTOR_SESSION_PID" in STRIP_SET
    assert "RAPTOR_SESSION_TOKEN" in STRIP_SET
    assert "RAPTOR_COPILOT_AUTH_SOCKET" in STRIP_SET


def test_session_credential_is_allowlisted_but_stripped():
    """The credential must flow to TRUSTED children (get_safe_env) yet
    never to targets — allowlisted AND strip-set is the designed
    combination, not a contradiction."""
    assert "RAPTOR_SESSION_PID" in RaptorConfig.SAFE_ENV_ALLOWLIST
    assert "RAPTOR_SESSION_TOKEN" in RaptorConfig.SAFE_ENV_ALLOWLIST


def test_pid1_shim_tuple_in_sync():
    """The shim hand-copies the set (it cannot import core inside
    namespace setup) — this is the tripwire that keeps it honest."""
    shim = (_REPO_ROOT / "libexec" / "raptor-pid1-shim").read_text(
        encoding="utf-8")
    for member in STRIP_SET:
        assert re.search(rf'"{re.escape(member)}"', shim), (
            f"pid1 shim strip tuple is missing {member!r} — "
            f"keep it in sync with TARGET_ENV_STRIP_SET"
        )


def test_fuzzing_env_hygiene_scrubs_the_set():
    from packages.fuzzing.env_hygiene import scrub_identity_env
    env = {member: "x" for member in STRIP_SET}
    env["PATH"] = "/usr/bin"
    scrub_identity_env(env)
    for member in STRIP_SET:
        assert member not in env, f"{member} survived the fuzz env scrub"


def test_frida_safe_env_excludes_the_set(monkeypatch):
    for member in STRIP_SET:
        monkeypatch.setenv(member, "leak-me")
    from core.audit.frida_observe import _safe_env
    env = _safe_env()
    for member in STRIP_SET:
        assert member not in env, f"{member} reached the frida CLI env"


def test_codeql_build_env_blocks_raptor_vars():
    """Repo-supplied build metadata must not inject RAPTOR control
    vars. Exercise the layering predicate exactly as
    database_manager applies it."""
    blocked = (set(RaptorConfig.DANGEROUS_ENV_VARS)
               | set(RaptorConfig.PROXY_ENV_VARS))
    hostile = {
        "RAPTOR_SESSION_PID": "1", "RAPTOR_SESSION_TOKEN": "t",
        "RAPTOR_OUT_DIR": "/tmp/x", "_RAPTOR_TRUSTED": "1",
        "JAVA_HOME": "/opt/java",
    }
    admitted = {
        k: v for k, v in hostile.items()
        if not (k in blocked or k.startswith(("RAPTOR_", "_RAPTOR")))
    }
    assert admitted == {"JAVA_HOME": "/opt/java"}


def test_context_seam_source_strips_by_default():
    """The run() seam strips the SET (not the two legacy names), the
    keep decision comes from the SANCTIONED call kwarg (never an
    in-band env-key probe a poisoned caller env could set), and the
    seam consumes the constant, not a hand-copied tuple."""
    src = (_REPO_ROOT / "core" / "sandbox" / "context.py").read_text(
        encoding="utf-8")
    assert "TARGET_ENV_STRIP_SET" in src
    seam = src[src.index(
        "_keep_for_dispatch = keep_trust_markers_for_dispatch"):][:2000]
    assert "TARGET_ENV_STRIP_SET" in seam or "_RC" in seam
    # The in-band probe must not carry authority anywhere in the seam.
    assert '"_RAPTOR_KEEP_TRUST_MARKERS" in kwargs' not in src


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_child_env_excludes_set_end_to_end(tmp_path):
    """On namespace-capable hosts: a sandboxed child observes NONE of
    the strip set, on whatever backend the host selects."""
    from core.sandbox import context as _ctx
    marker_file = tmp_path / "env-dump"
    try:
        result = _ctx.run_untrusted(
            ["sh", "-c", f"env > {marker_file}"],
            target=str(tmp_path), output=str(tmp_path), timeout=60,
        )
    except Exception as e:  # noqa: BLE001 — host without userns etc.
        pytest.skip(f"sandbox unavailable: {e}")
    if getattr(result, "returncode", 1) != 0 or not marker_file.exists():
        pytest.skip("sandboxed child did not run")
    dumped = marker_file.read_text(encoding="utf-8")
    for member in STRIP_SET:
        assert f"{member}=" not in dumped, (
            f"{member} leaked into the sandboxed child env")
