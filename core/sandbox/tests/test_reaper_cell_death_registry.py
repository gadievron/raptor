"""The reaper cell's death pipe joins the cross-spawn write-end registry.

The plain-subprocess (no-namespace) lane's teardown containment hangs
off a per-run death pipe: the preexec-forked subreaper sweeper polls
the read end and SIGKILL-sweeps the payload subtree on EOF. That EOF
has the same fork-inheritance exposure as the mount-ns spawn path's
pipe: a mount-ns intermediate forked in another thread while a
plain-lane run is in flight inherits a copy of the run's death_w, and
pre-fix nothing ever closed it — the sweeper's teardown signal was
pinned to that unrelated spawn's lifetime. Registered creation makes
the intermediate's child-entry sweep close the copy; registry-routed
closes keep the registry exact so the two parent-side close paths
(teardown-first timeout, then run()'s finally — either order) stay
safe against fd-number reuse.
"""

from __future__ import annotations

import sys as _sys

import pytest as _pytest

pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="the reaper cell exists on the Linux plain-subprocess lane only",
)

import contextlib  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402
from unittest.mock import patch  # noqa: E402

from core.sandbox.tests.capability import requires_landlock  # noqa: E402

_SYS_PY = "/usr/bin/python3"


@requires_landlock
def test_plain_lane_death_w_registered_while_run_in_flight(
        tmp_path: Path) -> None:
    """Mid-flight, the run's death_w must be in the registry (so a
    concurrently-forked spawn child closes its inherited copy), and
    gone from it once the run completes."""
    if not os.path.exists(_SYS_PY):
        _pytest.skip("system python3 not present")
    from core.sandbox import _spawn, sandbox

    with _spawn._DEATH_W_LOCK:
        baseline = set(_spawn._LIVE_DEATH_W)

    errors: list[BaseException] = []

    def _run() -> None:
        try:
            # Same probe patching as the teardown-sweep suite: force
            # the plain-subprocess lane so the reaper cell engages.
            with patch("core.sandbox.context.check_net_available",
                       return_value=False), \
                 patch("core.sandbox.context.check_mount_available",
                       return_value=False):
                with sandbox(target=str(tmp_path), output=str(tmp_path),
                             block_network=False,
                             restrict_reads=True) as run:
                    run([_SYS_PY, "-c", "import time; time.sleep(2)"],
                        capture_output=True, text=True, timeout=30)
        except BaseException as e:
            errors.append(e)

    t = threading.Thread(target=_run)
    t.start()
    try:
        registered = False
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and t.is_alive():
            with _spawn._DEATH_W_LOCK:
                if set(_spawn._LIVE_DEATH_W) - baseline:
                    registered = True
                    break
            time.sleep(0.02)
        assert registered, (
            "plain-lane run held no REGISTERED death-pipe write end "
            "mid-flight — a concurrently forked spawn child cannot "
            "close its inherited copy, pinning the sweeper's teardown "
            f"EOF (run errors: {errors})"
        )
    finally:
        t.join(timeout=30)
    assert not errors, f"plain-lane run failed: {errors}"
    with _spawn._DEATH_W_LOCK:
        leaked = set(_spawn._LIVE_DEATH_W) - baseline
    assert not leaked, (
        f"death-pipe write end(s) {leaked} still registered after the "
        "run completed — stale entries steer sibling children into "
        "closing reused fd numbers"
    )


def test_teardown_first_timeout_close_is_registry_routed() -> None:
    """The timeout path's death_w close must unregister atomically;
    the follow-up close from run()'s finally (either order) must
    refuse rather than double-close a possibly-reused fd number."""
    from core.sandbox._spawn import (
        _DEATH_W_LOCK,
        _LIVE_DEATH_W,
        close_death_w,
        open_death_pipe,
    )
    from core.sandbox.context import _run_teardown_first_timeout

    death_r, death_w = open_death_pipe()
    holder: list = [death_w]
    try:
        with _pytest.raises(subprocess.TimeoutExpired):
            _run_teardown_first_timeout(
                ["sleep", "5"],
                {"timeout": 0.3, "capture_output": True},
                holder,
                True,
            )
        assert holder[0] is None, "timeout path must consume the holder"
        with _DEATH_W_LOCK:
            assert death_w not in _LIVE_DEATH_W, (
                "timeout-path close left the death_w registered — a "
                "sibling child would close whatever fd reuses the "
                "number"
            )
        # run()'s finally arriving second — must refuse, not re-close.
        assert close_death_w(death_w) is False
    finally:
        with contextlib.suppress(OSError):
            os.close(death_r)
        if holder[0] is not None:
            close_death_w(holder[0])


def test_finally_first_then_timeout_order_tolerated() -> None:
    """Reverse order: run()'s finally closes first (normal-return
    shape), any later close attempt on the same number refuses."""
    from core.sandbox._spawn import close_death_w, open_death_pipe

    death_r, death_w = open_death_pipe()
    try:
        assert close_death_w(death_w) is True
        assert close_death_w(death_w) is False
    finally:
        os.close(death_r)
