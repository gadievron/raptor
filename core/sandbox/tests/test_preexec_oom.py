"""OOM child scoring — spawned children become preferred OOM victims.

Doctrine: analysis children are sacrificial, the session is not. Both
spawn chokepoints must stamp oom_score_adj=+500 on the child —
``set_pdeathsig()`` (the shared preexec for non-sandboxed tool spawns)
and ``_make_preexec_fn`` (the composed sandbox preexec, which calls it
first). Unwritable /proc (locked-down containers) must skip silently.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from core.sandbox import preexec
from core.sandbox.preexec import (
    _make_preexec_fn,
    raise_oom_score_adj,
    set_pdeathsig,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not Path("/proc/self/oom_score_adj").exists(),
    reason="oom_score_adj is a Linux /proc interface",
)


def _child_score(preexec_fn) -> str:
    r = subprocess.run(
        ["cat", "/proc/self/oom_score_adj"],
        preexec_fn=preexec_fn,
        capture_output=True, text=True, timeout=30, check=True,
    )
    return r.stdout.strip()


def _skip_if_unwritable():
    """The silent-skip environments (containers denying the write) are
    legitimate — probe in a throwaway child and skip rather than fail."""
    probe = subprocess.run(
        [sys.executable, "-c",
         "import os; fd = os.open('/proc/self/oom_score_adj', os.O_WRONLY);"
         "os.write(fd, b'500'); os.close(fd); print('writable')"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if "writable" not in probe.stdout:
        pytest.skip("oom_score_adj not writable in this environment")


def test_set_pdeathsig_children_get_500():
    _skip_if_unwritable()
    assert _child_score(set_pdeathsig()) == "500"


def test_sandbox_composed_preexec_children_get_500():
    _skip_if_unwritable()
    # Bare limits, no Landlock/seccomp — exercises _set_limits' shared
    # path (which applies pdeathsig + oom score before any layering).
    assert _child_score(_make_preexec_fn({})) == "500"


def test_score_inherited_by_grandchildren():
    _skip_if_unwritable()
    r = subprocess.run(
        ["sh", "-c", "sh -c 'cat /proc/self/oom_score_adj'"],
        preexec_fn=set_pdeathsig(),
        capture_output=True, text=True, timeout=30, check=True,
    )
    assert r.stdout.strip() == "500"


def test_raise_is_silent_when_path_unwritable(monkeypatch):
    monkeypatch.setattr(
        preexec, "_OOM_SCORE_ADJ_PATH", "/nonexistent/oom_score_adj")
    raise_oom_score_adj()  # must not raise


def test_parent_process_score_untouched():
    """Only CHILDREN are stamped — this (orchestrator-side) process
    keeps its inherited score after spawning."""
    before = Path("/proc/self/oom_score_adj").read_text().strip()
    _child_score(set_pdeathsig())
    after = Path("/proc/self/oom_score_adj").read_text().strip()
    assert before == after


def test_own_pid_untouched_by_import():
    """Importing the module must never stamp the importing process."""
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys, os; sys.path.insert(0, os.environ['RAPTOR_DIR']); "
         "import core.sandbox.preexec; "
         "print(open('/proc/self/oom_score_adj').read().strip())"],
        capture_output=True, text=True, timeout=60, check=False,
        env={**os.environ,
             "RAPTOR_DIR": str(Path(__file__).resolve().parents[3])},
    )
    assert r.returncode == 0, r.stderr
    parent = Path("/proc/self/oom_score_adj").read_text().strip()
    assert r.stdout.strip() == parent


def test_child_can_lower_back_to_inherited_floor_but_not_below():
    """Pins the REAL kernel contract the block comment states: outside
    the sandbox the +500 stamp is a cooperative default — a child may
    drop back to its inherited floor, but not below it."""
    _skip_if_unwritable()
    inherited = int(Path("/proc/self/oom_score_adj").read_text().strip())
    code = (
        "import os\n"
        "def w(v):\n"
        "    try:\n"
        "        fd = os.open('/proc/self/oom_score_adj', os.O_WRONLY)\n"
        "        os.write(fd, str(v).encode()); os.close(fd)\n"
        "        return 'ok'\n"
        "    except OSError:\n"
        "        return 'denied'\n"
        f"print('floor', w({inherited}))\n"
        f"print('below', w({inherited - 100}))\n"
        "print('final', open('/proc/self/oom_score_adj').read().strip())\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code],
        preexec_fn=set_pdeathsig(),  # stamps +500 first
        capture_output=True, text=True, timeout=30, check=True,
    )
    if os.geteuid() == 0:
        pytest.skip("root can lower below the floor — contract untestable")
    assert "floor ok" in r.stdout, r.stdout
    if "below ok" in r.stdout:
        # Unprivileged lowering is denied below the task's
        # oom_score_adj_min, which equals our stamp only when nothing
        # privileged set a lower min earlier. CI supervisors and some
        # container runtimes set the job's min below our +500 floor,
        # so lowering legitimately succeeds there — the kernel
        # contract holds; the environment's floor is simply lower
        # than ours and the denial is untestable on this host.
        pytest.skip(
            "environment's oom_score_adj_min is below the stamped "
            "floor (privileged supervisor set it) — below-floor "
            "denial not testable here")
    assert "below denied" in r.stdout, r.stdout
    assert f"final {inherited}" in r.stdout, r.stdout
