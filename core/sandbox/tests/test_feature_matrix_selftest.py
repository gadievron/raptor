"""Wiring check for the sandbox feature-matrix harness.

`run-matrix.sh --self-test` is the docker-free lane: it generates the
derived seccomp profiles, runs the capability probe on this host, and
exercises the report aggregator on synthetic clean/diverged fixtures
(asserting the divergence gate actually gates). Running it here keeps
the weekly workflow's substrate from bit-rotting between Saturdays —
a broken profile generator or report schema surfaces in the PR tier.
"""

import os
import sys

import pytest

from core.testing.standalone_cli import run_standalone_cli

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="harness targets the Linux sandbox",
)

_REPO_ROOT = os.path.realpath(
    os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_SCRIPT = os.path.join(_REPO_ROOT, "core", "sandbox", "scripts",
                       "feature-matrix", "run-matrix.sh")


@pytest.mark.parametrize("stale_launch", [False, True], ids=["clean", "retired-parent"])
def test_self_test_passes(tmp_path, stale_launch):
    before = dict(os.environ)
    with pytest.MonkeyPatch.context() as parent:
        if stale_launch:
            retired = tmp_path / "retired-parent"
            retired.mkdir()
            retired.rmdir()
            parent.setenv("TMPDIR", str(retired))
            parent.setenv("_RAPTOR_SCRATCH_AUTH", "retired-self-test-authorization")
            parent.setenv("RAPTOR_SESSION_PID", "99999999")
            parent.setenv("RAPTOR_SESSION_TOKEN", "retired-self-test-session")
        else:
            for name in ("_RAPTOR_SCRATCH_AUTH", "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN"):
                parent.delenv(name, raising=False)
        borrowed = dict(os.environ)
        r = run_standalone_cli([_SCRIPT, "--self-test"], capture_output=True,
                               text=True, timeout=120, check=False,
                               cwd=_REPO_ROOT)
        unchanged = dict(os.environ) == borrowed
        assert unchanged, "self-test changed its parent's launch state"
    restored = dict(os.environ) == before
    assert restored, "launch-state regression did not restore its caller"
    assert r.returncode == 0, (
        f"feature-matrix self-test failed:\n{r.stdout[-800:]}"
        f"\n{r.stderr[-800:]}")
    assert "self-test OK" in r.stdout
