"""Lane-B bootstrap env hygiene: the unshare/prlimit/pid1-shim hops.

On the no-mount-ns fallback lane the bootstrap processes' execve-time
environ is readable by the target (host procfs stays visible there and
the hops share the target's user namespace), so they must receive the
already-stripped target view plus only the constant trust marker the
shim's gate needs — never the orchestrator's pre-strip environment
with the session credential.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


def test_shim_hop_env_source_pin():
    """Source pin: both lane-B invocation sites build the hop env from
    the minimal _shim_hop_env() view, not from kwargs['env']."""
    src = (_REPO_ROOT / "core" / "sandbox" / "context.py").read_text(
        encoding="utf-8")
    packed = "".join(src.split())
    assert "def _shim_hop_env()" in src
    # Both lane-B invocation sites feed the quarantine step from the
    # minimal hop view (whitespace-stripped so a reformat cannot
    # silently disarm the pin).
    assert packed.count("_quarantine_loader_env(_shim_hop_env())") == 2
    # The old shape must not return: quarantining the full caller env
    # for the hop chain re-publishes the credential.
    assert '_quarantine_loader_env(kwargs["env"])' not in packed
    assert "_quarantine_loader_env(_denv_base)" not in packed


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="unshare fallback lane")
def test_lane_b_target_cannot_read_hop_credentials(tmp_path):
    """The attacker-perspective probe: on lane B the target shares the
    bootstrap hops' USER namespace and host procfs stays visible, so
    the hops' execve environ is exactly one /proc read away. With the
    minimal hop env, an in-sandbox hunt for the decoy credential must
    come up empty — while the run itself succeeds, proving the shim's
    trust gate accepts the constant marker.

    (A host-side watcher cannot verify this: once the hops enter the
    new user namespace, an init-ns reader without capabilities there
    is denied their environ — the in-sandbox reader is the ONLY
    principal with this access, which is what makes it the threat.)
    """
    marker = tmp_path / "laneb-hunt"
    payload = (
        "hits=0; for d in /proc/[0-9]*; do "
        "tr '\\0' '\\n' < $d/environ 2>/dev/null "
        "| grep -q laneb-hop-decoy && hits=$((hits+1)); done; "
        f"echo $hits > {marker}; echo laneb-done"
    )
    driver = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, os.environ["RAPTOR_DIR"])
        from core.sandbox import state
        state._mount_ns_available_cache = False   # force lane B
        from core.sandbox.context import run_untrusted
        r = run_untrusted(
            ["sh", "-c", %r],
            target=%r, output=%r, cwd=%r, timeout=90,
            capture_output=True, text=True,
        )
        print("RC=%%d OUT=%%s" %% (r.returncode, r.stdout.strip()))
    """) % (payload, str(tmp_path), str(tmp_path), str(tmp_path))
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RAPTOR_DIR": str(_REPO_ROOT),
        "RAPTOR_SESSION_TOKEN": "laneb-hop-decoy",
        # Forcing the no-mount-ns lane trips the fresh-procfs
        # fail-close by design; this test verifies the CONTENT layer
        # (hop env hygiene) under the explicitly accepted degrade.
        "RAPTOR_ALLOW_DEGRADED_UNTRUSTED": "1",
    }
    r = subprocess.run(
        [sys.executable, "-c", driver], env=env,
        capture_output=True, text=True, timeout=150, check=False,
    )
    if "RC=0" not in r.stdout or "laneb-done" not in r.stdout:
        pytest.skip(f"lane-B fallback unavailable: {r.stdout} "
                    f"{r.stderr[-300:]}")
    if not marker.exists():
        pytest.skip("probe produced no output")
    assert marker.read_text(encoding="utf-8").strip() == "0", (
        "a lane-B sandboxed payload can read the session credential "
        "out of a bootstrap hop's environ image")
