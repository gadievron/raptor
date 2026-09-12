"""Fresh-procfs degradation noise control: probe once, warn once, stamp per run.

The pid-ns spawn grandchild remounts /proc so /proc/<ns-pid> resolves for
ptrace-family tools. On hosts where the kernel refuses that remount
(static policy — e.g. containers with a masked host /proc), runs that
accept the degrade used to repeat one identical stderr warning on EVERY
spawn: pure noise that buries real signals over a long run.

Contract under test:
- the host condition is probed once per process and cached
  (core.sandbox.probes.check_pidns_fresh_proc_available);
- the degradation is logged ONCE at WARNING with the posture
  consequence, then per-spawn at DEBUG;
- the grandchild's per-spawn stderr repeat is suppressed ONLY for the
  exact probed condition — a divergent failure (probe said the remount
  works, or libc failed to load) still warns on every spawn;
- the per-run posture stamp (sandbox_info["pidns_proc_mount_unavailable"])
  is applied independently of log dedup, so forensic readers never
  depend on log throttling for the degradation record.
"""

from __future__ import annotations

import sys as _sys

import pytest as _pytest

pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (pid-ns fresh procfs remount)",
)

import logging  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import textwrap  # noqa: E402
import unittest  # noqa: E402
from pathlib import Path  # noqa: E402
from unittest import mock  # noqa: E402
from core.sandbox.tests.capability import requires_landlock, requires_userns

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _mount_ns_usable() -> bool:
    """True iff the fork+newuidmap+pivot_root spawn path works here."""
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


class TestPerSpawnWarningKeying(unittest.TestCase):
    """_should_warn_proc_mount_failure — suppression is keyed to the
    exact probed condition, never blanket (a dedup that hid a genuinely
    DIFFERENT degradation on a later spawn would defeat the point of
    the warning)."""

    def _should_warn(self, **kw):
        from core.sandbox._spawn import _should_warn_proc_mount_failure
        return _should_warn_proc_mount_failure(**kw)

    def test_probed_static_condition_suppresses_the_per_spawn_repeat(self):
        self.assertFalse(self._should_warn(
            proc_rc=-1, libc_loaded=True, expected_unavailable=True))

    def test_unexpected_failure_on_a_capable_host_still_warns(self):
        """Probe said the remount works — a failing spawn is new signal,
        not the known static condition; it must stay loud every time."""
        self.assertTrue(self._should_warn(
            proc_rc=-1, libc_loaded=True, expected_unavailable=False))

    def test_libc_load_failure_is_a_different_condition_and_still_warns(self):
        """The probe vouched for the KERNEL refusing the mount; it never
        vouched for libc failing to load. Different condition — the
        expectation must not silence it."""
        self.assertTrue(self._should_warn(
            proc_rc=-1, libc_loaded=False, expected_unavailable=True))

    def test_successful_mount_never_warns(self):
        self.assertFalse(self._should_warn(
            proc_rc=0, libc_loaded=True, expected_unavailable=False))
        self.assertFalse(self._should_warn(
            proc_rc=0, libc_loaded=True, expected_unavailable=True))


class TestExpectationLogging(unittest.TestCase):
    """_pidns_proc_mount_expectation — once-per-process WARNING, then
    per-spawn DEBUG; nothing at all on capable hosts."""

    def setUp(self):
        from core.sandbox import state
        state._pidns_proc_mount_unavailable_warned = False

    def _expectation(self, skip_pid_ns=False):
        from core.sandbox._spawn import _pidns_proc_mount_expectation
        return _pidns_proc_mount_expectation(skip_pid_ns)

    def test_static_condition_logged_once_at_warning_then_debug(self):
        with mock.patch(
            "core.sandbox.probes.check_pidns_fresh_proc_available",
            return_value=False,
        ):
            with self.assertLogs("core.sandbox._spawn",
                                 level=logging.DEBUG) as cm:
                first = self._expectation()
                second = self._expectation()
        self.assertTrue(first)
        self.assertTrue(second)
        warnings = [r for r in cm.records if r.levelno == logging.WARNING
                    and "fresh procfs" in r.getMessage()]
        debugs = [r for r in cm.records if r.levelno == logging.DEBUG
                  and "fresh procfs" in r.getMessage()]
        self.assertEqual(
            len(warnings), 1,
            "an identical static environmental condition must be "
            "WARNING-logged exactly once per process",
        )
        self.assertEqual(
            len(debugs), 1,
            "later spawns must record the condition at DEBUG",
        )
        self.assertIn(
            "pidns_proc_mount_unavailable", warnings[0].getMessage(),
            "the WARNING must name the per-run posture stamp",
        )

    def test_capable_host_logs_nothing_and_expects_no_failure(self):
        logger = logging.getLogger("core.sandbox._spawn")
        with mock.patch(
            "core.sandbox.probes.check_pidns_fresh_proc_available",
            return_value=True,
        ), mock.patch.object(logger, "warning") as warn, \
                mock.patch.object(logger, "debug") as debug:
            self.assertFalse(self._expectation())
        warn.assert_not_called()
        debug.assert_not_called()

    def test_skip_pid_ns_lane_never_consults_the_probe(self):
        """No new pid-ns → no remount attempt → no expectation to form.
        The probe must not even run (it costs a subprocess)."""
        with mock.patch(
            "core.sandbox.probes.check_pidns_fresh_proc_available",
            side_effect=AssertionError("probe must not be consulted"),
        ):
            self.assertFalse(self._expectation(skip_pid_ns=True))


class TestProbeCaching(unittest.TestCase):
    """check_pidns_fresh_proc_available — one subprocess probe per
    process; determinate kernel verdicts cached, infrastructure
    failures re-probed."""

    def setUp(self):
        from core.sandbox import state
        state._pidns_fresh_proc_cache = None

    @staticmethod
    def _completed(rc, args=("unshare",)):
        return subprocess.CompletedProcess(
            list(args), rc, stdout=b"", stderr=b"probe stderr")

    def _check(self):
        from core.sandbox.probes import check_pidns_fresh_proc_available
        return check_pidns_fresh_proc_available()

    def test_probe_runs_once_per_process_and_caches(self):
        with mock.patch(
            "core.sandbox.probes._find_sandbox_binary",
            return_value="/usr/bin/unshare",
        ), mock.patch(
            "core.sandbox.probes.subprocess.run",
            return_value=self._completed(0),
        ) as run_mock:
            self.assertTrue(self._check())
            self.assertTrue(self._check())
        self.assertEqual(
            run_mock.call_count, 1,
            "the host condition is static — the probe subprocess must "
            "run at most once per process",
        )

    def test_mount_specific_refusal_is_detected_when_namespaces_engage(self):
        def fake_run(cmd, **kw):
            rc = 1 if "--mount-proc" in cmd else 0
            return self._completed(rc, cmd)

        from core.sandbox import state
        with mock.patch(
            "core.sandbox.probes._find_sandbox_binary",
            return_value="/usr/bin/unshare",
        ), mock.patch(
            "core.sandbox.probes.subprocess.run",
            side_effect=fake_run,
        ):
            self.assertFalse(self._check())
        self.assertIs(state._pidns_fresh_proc_cache, False,
                      "a determinate kernel refusal is static — cache it")

    def test_namespace_layer_refusal_does_not_claim_proc_mount_unavailable(
            self):
        """When unshare fails even WITHOUT --mount-proc, the evidence is
        about the namespace layer, not the proc mount — report available
        so no spawn warning is ever suppressed on it."""
        with mock.patch(
            "core.sandbox.probes._find_sandbox_binary",
            return_value="/usr/bin/unshare",
        ), mock.patch(
            "core.sandbox.probes.subprocess.run",
            return_value=self._completed(1),
        ):
            self.assertTrue(self._check())

    def test_probe_infrastructure_failure_is_not_cached(self):
        from core.sandbox import state
        with mock.patch(
            "core.sandbox.probes._find_sandbox_binary",
            return_value="/usr/bin/unshare",
        ), mock.patch(
            "core.sandbox.probes.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["unshare"], 5),
        ):
            self.assertTrue(
                self._check(),
                "an indeterminate probe must fail visible (available), "
                "never suppress on unverified evidence",
            )
        self.assertIsNone(
            state._pidns_fresh_proc_cache,
            "infrastructure failures are transient — do not cache; "
            "the next call must re-probe",
        )

    def test_missing_unshare_reports_available(self):
        """No unshare → the pid-ns spawn path can never run → there is
        nothing to suppress or stamp."""
        with mock.patch(
            "core.sandbox.probes._find_sandbox_binary",
            return_value=None,
        ):
            self.assertTrue(self._check())


class TestPostureStampE2E(unittest.TestCase):
    """The per-run posture stamp survives log dedup: every pid-ns run on
    a degraded host carries pidns_proc_mount_unavailable in
    sandbox_info, whether or not this spawn's warning was throttled."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _run(self):
        from core.sandbox import run
        return run(["true"], timeout=30,
                   target=self.tmp.name, output=self.tmp.name)

    @requires_landlock
    @requires_userns
    def test_degraded_host_run_is_stamped_pidns_proc_mount_unavailable(self):
        from core.sandbox import state
        state._pidns_fresh_proc_cache = False  # degraded host class
        state._pidns_proc_mount_unavailable_warned = True  # log already deduped
        r = self._run()
        self.assertEqual(r.returncode, 0)
        self.assertIs(
            r.sandbox_info.get("pidns_proc_mount_unavailable"), True,
            "the degradation must be stamped on EVERY affected run — "
            "the once-per-process log throttle must not thin the "
            "per-run forensic record",
        )

    @requires_landlock
    def test_capable_host_run_carries_no_degradation_stamp(self):
        from core.sandbox import state
        state._pidns_fresh_proc_cache = True
        r = self._run()
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("pidns_proc_mount_unavailable", r.sandbox_info)

    @requires_landlock
    @requires_userns
    def test_contract_lane_run_is_never_stamped_from_a_divergent_probe(self):
        """A require_fresh_procfs run that completed PROVED its procfs
        was fresh (a grandchild remount failure aborts before any
        result exists) — a divergent probe verdict must not mislabel
        it degraded. Needs the namespace backend for real: on a
        userns-denied host the contract call refuses up front (the
        containment floor, by design) instead of completing."""
        from core.sandbox import run, state
        state._pidns_fresh_proc_cache = False  # probe disagrees
        r = run(["true"], timeout=30,
                target=self.tmp.name, output=self.tmp.name,
                require_fresh_procfs=True)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("pidns_proc_mount_unavailable", r.sandbox_info)


@requires_landlock
@requires_userns
class TestNoWarningWhenRemountWorksE2E(unittest.TestCase):
    """On a host that CAN remount the fresh procfs, spawns must emit no
    proc-mount warning at all (the pre-Landlock mount ordering makes the
    remount succeed; the probe and dedup machinery stay silent)."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        from core.sandbox.probes import check_pidns_fresh_proc_available
        if not check_pidns_fresh_proc_available():
            self.skipTest("host cannot remount a fresh procfs in a "
                          "nested user+pid ns")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_spawn_stderr_carries_no_proc_mount_warning(self):
        from core.sandbox._spawn import run_sandboxed
        r = run_sandboxed(
            ["sh", "-c", "readlink /proc/self"],
            target=self.tmp.name, output=self.tmp.name,
            block_network=True,
            nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            writable_paths=[self.tmp.name, "/tmp"],
            readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile=None, seccomp_block_udp=False,
            env=None, cwd=None, timeout=15,
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertNotIn("fresh proc mount", r.stderr or "")
        # And the remount genuinely happened: /proc/self resolves to a
        # pid-ns-local pid, not a host pid.
        pid = int((r.stdout or "0").strip() or 0)
        self.assertLess(
            pid, 16,
            f"/proc/self resolved to {pid} — looks like the HOST-pid "
            f"procfs bind, not the fresh pid-ns-local procfs",
        )


# Fork-inherited CDLL wrapper that refuses exactly the fresh-proc mount
# (everything else passes through), so the whole real spawn chain runs
# while the grandchild's remount deterministically fails — the same
# forced-failure idiom test_fresh_procfs_contract.py uses for the
# contract lane, here driving the accepted-degrade lane's warning
# behaviour.
_FORCED_MOUNT_FAIL_PRELUDE = """
import ctypes, os, sys
sys.path.insert(0, os.environ["RAPTOR_DIR"])
_real_CDLL = ctypes.CDLL
class _FakeLibc:
    def __init__(self, real): self._r = real
    def __getattr__(self, n): return getattr(self._r, n)
    def __getitem__(self, k): return self._r[k]
    def mount(self, *a):
        if a and a[0] == b"proc":
            return -1
        return self._r.mount(*a)
def _patched(name=None, *a, **k):
    real = _real_CDLL(name, *a, **k)
    return _FakeLibc(real) if (name is None or "libc" in str(name)) else real
ctypes.CDLL = _patched
"""


@requires_userns
class TestDegradeLaneWarningDedupE2E(unittest.TestCase):
    """End-to-end log-once semantics on the accepted-degrade lane, with
    the remount failure forced through the real spawn chain: the
    probed static condition produces ONE process-level WARNING and no
    per-spawn stderr repeats; a failure the probe did NOT predict
    warns on every spawn."""

    WARN_LINE = "grandchild fresh proc mount failed"
    ONCE_LINE = "refuses a fresh procfs mount"

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )

    def _drive(self, tmp: str, probe_cache: str) -> str:
        driver = _FORCED_MOUNT_FAIL_PRELUDE + textwrap.dedent(f"""
            import logging, sys
            logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
            from core.sandbox import run, state
            state._pidns_fresh_proc_cache = {probe_cache}
            for i in range(3):
                r = run(["true"], target={tmp!r}, output={tmp!r},
                        timeout=60)
                print("rc%d=%d" % (i, r.returncode))
        """)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "RAPTOR_DIR": str(_REPO_ROOT),
        }
        import sys
        r = subprocess.run([sys.executable, "-c", driver], env=env,
                           capture_output=True, text=True, timeout=200,
                           check=False)
        if r.returncode != 0:
            self.skipTest(f"driver failed: {r.stderr[-300:]}")
        if "rc2=0" not in r.stdout:
            self.skipTest(f"sandboxed spawns did not complete: "
                          f"{r.stdout} {r.stderr[-300:]}")
        return r.stderr

    def test_probed_condition_warns_once_not_once_per_spawn(self):
        with tempfile.TemporaryDirectory() as tmp:
            stderr = self._drive(tmp, probe_cache="False")
        self.assertEqual(
            stderr.count(self.WARN_LINE), 0,
            f"per-spawn stderr repeats of the probed static condition "
            f"must be suppressed:\n{stderr[-800:]}",
        )
        self.assertEqual(
            stderr.count(self.ONCE_LINE), 1,
            f"the static condition must be WARNING-logged exactly once "
            f"per process:\n{stderr[-800:]}",
        )
        self.assertGreaterEqual(
            stderr.count("stamped pidns_proc_mount_unavailable"), 2,
            f"later spawns must still record the condition at DEBUG:"
            f"\n{stderr[-800:]}",
        )

    def test_unpredicted_failure_warns_on_every_spawn(self):
        """Probe says the host CAN remount, yet the mount fails — a
        genuinely different degradation; the dedup must not hide it."""
        with tempfile.TemporaryDirectory() as tmp:
            stderr = self._drive(tmp, probe_cache="True")
        self.assertEqual(
            stderr.count(self.WARN_LINE), 3,
            f"an unpredicted per-spawn failure must stay loud on every "
            f"spawn:\n{stderr[-800:]}",
        )


if __name__ == "__main__":
    unittest.main()
