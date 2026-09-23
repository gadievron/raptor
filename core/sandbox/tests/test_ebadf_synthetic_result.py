"""The plain-lane EBADF teardown-race result must be marked synthetic.

The plain subprocess dispatch absorbs OSError(EBADF) — a
concurrently-closed fd inside the Popen plumbing — by minting a
CompletedProcess(returncode=-9). That shape is indistinguishable from
a genuine SIGKILL: rc < 0 reads as signal death (mechanical crash
evidence) to observe._interpret_result and every crash oracle, yet
the target's real execution state is UNKNOWN and no output was
captured. Evidence records must reflect what actually happened, so
the synthetic result carries a distinguishing sandbox_info marker
consumers can exclude on.
"""

from __future__ import annotations

import errno
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="plain-lane dispatch under test is Linux",
)


def test_ebadf_race_result_is_stamped_synthetic(monkeypatch):
    from core.sandbox import context, state

    # Operator-disabled run rides the plain subprocess dispatch — the
    # lane that owns the EBADF absorption.
    monkeypatch.setattr(state, "_cli_sandbox_profile", "none")
    monkeypatch.setattr(state, "_cli_sandbox_disabled", True)

    real_run = subprocess.run
    mark = "__ebadf_target__"

    def selective(cmd, *args, **kwargs):
        if (isinstance(cmd, (list, tuple))
                and mark in " ".join(map(str, cmd))):
            raise OSError(errno.EBADF, "Bad file descriptor")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(context.subprocess, "run", selective)

    res = context.run(["/bin/echo", mark], capture_output=True, text=True)

    # The absorbed shape is unchanged (callers keep getting a result,
    # not a raise) ...
    assert res.returncode == -9
    # ... but it can no longer masquerade as a genuine SIGKILL.
    assert res.sandbox_info.get("synthetic_result") == (
        "ebadf-teardown-race"
    ), (
        "EBADF-fabricated rc=-9 carries no distinguishing marker — "
        "crash oracles will read it as mechanical signal-death "
        "evidence"
    )


def test_genuine_result_carries_no_synthetic_marker(monkeypatch):
    from core.sandbox import context, state

    monkeypatch.setattr(state, "_cli_sandbox_profile", "none")
    monkeypatch.setattr(state, "_cli_sandbox_disabled", True)

    res = context.run(["/bin/echo", "ok"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "synthetic_result" not in (res.sandbox_info or {})
