"""A wedged-but-alive tracer must be killed at the ready deadline.

``run_landlock_audit`` forks a tracer and waits (bounded select) for
its 1-byte ready signal. When the select times out the tracer may be
ALIVE but wedged (interpreter stall, PTRACE_SEIZE hang, SIGSTOP) — it
never writes the byte and never exits, so a diagnostic
``os.waitpid(tracer_pid, 0)`` with no prior kill blocks the audit
parent unboundedly, with the target child parked on its go-pipe for
the same duration and the caller's ``timeout=`` never engaged (the
deadline is computed after the handshake). The spawn lane's twin
kills the timed-out tracer BEFORE the diagnostic waitpid for exactly
this reason; this pins the same contract on the audit lane.

The wedge stands in for the tracer interpreter through the exec seam
(``sys.executable``): alive, silent, never ready — the same
observable state as a wedged interpreter.
"""

from __future__ import annotations

import sys
import time

import pytest

from core.sandbox import _landlock_audit as mod
from core.testing.wallclock import check_wall_deadline

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock audit path is Linux-only",
)

_WEDGE_SLEEP_S = 30.0


def test_wedged_tracer_is_killed_not_awaited(tmp_path, monkeypatch):
    wedge = tmp_path / "wedge.sh"
    wedge.write_text(
        "#!/bin/sh\n"
        "# stands in for the tracer interpreter: alive, never writes\n"
        "# the ready byte\n"
        f"exec sleep {_WEDGE_SLEEP_S:g}\n"
    )
    wedge.chmod(0o755)
    # Short ready deadline for test speed — the pin is the kill-first
    # MECHANISM at the deadline, not the production budget.
    monkeypatch.setattr(mod, "_TRACER_READY_TIMEOUT_S", 0.5)
    monkeypatch.setattr(mod.sys, "executable", str(wedge))

    t0 = time.monotonic()
    with pytest.raises(RuntimeError, match="did not signal ready"):
        mod.run_landlock_audit(
            ["/bin/true"],
            audit_run_dir=str(tmp_path),
            timeout=8.0,
            capture_output=True,
        )
    # Pre-fix the parent blocked in waitpid until the wedge's own
    # exit (the sleep above; unbounded with a genuinely wedged
    # interpreter). Post-fix the tracer is SIGKILLed at the ready
    # deadline and the raise arrives promptly.
    check_wall_deadline(
        time.monotonic() - t0, 10.0, code_bound_s=_WEDGE_SLEEP_S,
        what="wedged-tracer teardown",
    )
