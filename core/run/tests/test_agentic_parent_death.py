"""Parent-death containment wiring for the agentic spawn chokepoints.

The long-lived children raptor_agentic detaches with
``start_new_session=True`` (analysis phases, the static-analysis
scanner, the codeql agent) must not survive a SIGKILLed / OOM-killed
orchestrator. Two layers, both asserted here:

* PR_SET_PDEATHSIG via the shared ``core.sandbox.set_pdeathsig``
  preexec at every detached Popen site (behavioural probe: a real
  child reads its own pdeathsig back).
* The ``RAPTOR_PARENT_WATCHDOG`` opt-in on the scanner/agent envs, so
  the in-child watchdog (``core.run.parent_liveness``) covers the
  cases PDEATHSIG misses (double-fork, setuid exec, non-Linux).

Group-kill semantics of the watchdog itself are covered by
test_parent_liveness.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_agentic():
    if str(_RAPTOR_ROOT) not in sys.path:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor_agentic
    return raptor_agentic


# Child probe: read PR_GET_PDEATHSIG (prctl op 2) back and exit with
# the configured signal number — 0 means "no parent-death signal".
_PDEATHSIG_PROBE = (
    "import ctypes, sys\n"
    "libc = ctypes.CDLL(None, use_errno=True)\n"
    "sig = ctypes.c_int(0)\n"
    "rc = libc.prctl(2, ctypes.byref(sig), 0, 0, 0)\n"
    "sys.exit(sig.value if rc == 0 else 99)\n"
)


@pytest.mark.linux_native
class TestPdeathsigAtTheChokepoint:
    def test_run_command_streaming_child_carries_sigkill_pdeathsig(self):
        import signal
        agentic = _import_agentic()
        rc, _stdout, _stderr = agentic.run_command_streaming(
            [sys.executable, "-c", _PDEATHSIG_PROBE],
            "pdeathsig probe", timeout=60,
        )
        assert rc == int(signal.SIGKILL), (
            "detached analysis children must carry PR_SET_PDEATHSIG — "
            "a SIGKILLed orchestrator otherwise strands the whole tree"
        )


class TestMainThreadGuard:
    """PDEATHSIG binds to the SPAWNING THREAD — armed off the main
    thread, the kernel SIGKILLs a healthy child when that thread
    exits. The chokepoint helper is the runtime tripwire: the main
    thread arms, any other thread gets the watchdog-only fallback
    with a loud warning — never a mis-scoped kill, never a silent
    skip of parent-death protection."""

    def test_main_thread_arms(self):
        agentic = _import_agentic()
        assert callable(agentic._parent_death_preexec())

    def test_worker_thread_refuses_with_loud_warning(self, caplog):
        import threading
        agentic = _import_agentic()
        result: list = []
        with caplog.at_level("WARNING"):
            t = threading.Thread(
                target=lambda: result.append(
                    agentic._parent_death_preexec()),
            )
            t.start()
            t.join(timeout=10)
        assert result == [None]
        assert "non-main thread" in caplog.text

    @pytest.mark.linux_native
    def test_worker_thread_spawn_falls_back_to_no_pdeathsig(self, caplog):
        # Behavioural direction through the real chokepoint: a
        # worker-thread spawn produces a child WITHOUT pdeathsig
        # (probe exits 0) instead of one armed against the worker
        # thread's lifetime.
        import threading
        agentic = _import_agentic()
        out: list = []
        with caplog.at_level("WARNING"):
            t = threading.Thread(
                target=lambda: out.append(agentic.run_command_streaming(
                    [sys.executable, "-c", _PDEATHSIG_PROBE],
                    "worker-thread pdeathsig probe", timeout=60,
                )),
            )
            t.start()
            t.join(timeout=60)
        assert out and out[0][0] == 0
        assert "non-main thread" in caplog.text


class TestSpawnSiteWiring:
    """Source-level pins: the wiring must stay on every detached
    long-lived spawn site, not just the one the behavioural probe
    exercises."""

    def test_agentic_popen_sites_carry_the_guarded_preexec(self):
        src = (_RAPTOR_ROOT / "raptor_agentic.py").read_text(
            encoding="utf-8")
        assert src.count("start_new_session=True,") == 3
        assert src.count("preexec_fn=_parent_death_preexec(),") == 3

    def test_agentic_scanner_and_codeql_envs_opt_into_the_watchdog(self):
        src = (_RAPTOR_ROOT / "raptor_agentic.py").read_text(
            encoding="utf-8")
        assert src.count(
            '["RAPTOR_PARENT_WATCHDOG"] = str(os.getpid())') == 2

    def test_scanner_arms_watchdog_and_signs_its_agent_spawn(self):
        src = (
            _RAPTOR_ROOT / "packages" / "static-analysis" / "scanner.py"
        ).read_text(encoding="utf-8")
        assert 'maybe_start_orphan_watchdog("static-analysis-scanner")' in src
        assert "preexec_fn=_PDEATHSIG_PREEXEC," in src
        assert '["RAPTOR_PARENT_WATCHDOG"] = str(os.getpid())' in src

    def test_codeql_agent_arms_the_watchdog(self):
        src = (
            _RAPTOR_ROOT / "packages" / "codeql" / "agent.py"
        ).read_text(encoding="utf-8")
        assert 'maybe_start_orphan_watchdog("codeql-agent")' in src
