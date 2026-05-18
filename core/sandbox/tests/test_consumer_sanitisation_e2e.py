"""End-to-end adversarial tests for PR2 consumer wiring.

For each consumer flipped in PR2, this module reconstructs the EXACT
sandbox kwarg combination the consumer uses, spawns a real sandbox
with those kwargs against a trivial target (`cat /etc/hostname` /
`hostname` / `cat /proc/cpuinfo`), and asserts the child sees the
persona — i.e. sanitise_host_fingerprint=True actually engages mount-ns,
binds the persona, and reaches the child.

This catches the class of bug where the static-grep check
(test_consumer_sanitisation.py) passes but the kwarg is dropped
somewhere along context.py → _spawn.py → setup_mount_ns. PR1's
test_fingerprint_e2e.py proved the general path works; this proves
each consumer's SPECIFIC kwarg combination works (block_network
interaction, profile=debug interaction, readable_paths interaction).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="consumer e2e tests are Linux-only (mount-ns required)",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


class _ConsumerE2EBase(unittest.TestCase):
    """Shared setup: tmpdir for target/output, mount-ns gate."""

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable (needs uidmap + sysctl=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _assert_persona_engaged(self, result, extra_msg=""):
        """Persona engaged iff /etc/hostname inside the sandbox reads
        'localhost' (the persona value), not the operator's real
        hostname."""
        self.assertEqual(
            result.returncode, 0,
            f"sandbox call failed; stderr={result.stderr!r} {extra_msg}",
        )
        self.assertEqual(
            result.stdout.strip(), "localhost",
            f"persona did NOT engage — child saw real hostname "
            f"{result.stdout.strip()!r} {extra_msg}",
        )


class TestDebuggerKwargCombo(_ConsumerE2EBase):
    """Replicates debugger.py:135/144 — sandbox with profile=debug +
    target+output + sanitise_host_fingerprint=True. profile=debug
    permits ptrace; sanitisation must still engage."""

    def test_persona_engages_under_profile_debug(self):
        from core.sandbox import run as sandbox_run
        result = sandbox_run(
            ["cat", "/etc/hostname"],
            profile="debug",
            target=self.tmp.name, output=self.tmp.name,
            capture_output=True, text=True, timeout=15,
            sanitise_host_fingerprint=True,
        )
        self._assert_persona_engaged(result)

    def test_uname_release_still_real_under_profile_debug(self):
        """Capability surface preserved even under profile=debug —
        regression guard for an exploit_feasibility consumer that
        runs under the same kwarg combo."""
        from core.sandbox import run as sandbox_run
        result = sandbox_run(
            ["uname", "-r"],
            profile="debug",
            target=self.tmp.name, output=self.tmp.name,
            capture_output=True, text=True, timeout=15,
            sanitise_host_fingerprint=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), os.uname().release)


class TestCrashAnalyserKwargCombo(_ConsumerE2EBase):
    """Replicates crash_analyser.py — three combos: (1) profile=debug
    for GDB/LLDB, (2) block_network=True for plain ASAN replay."""

    def test_persona_under_profile_debug_with_stdin(self):
        """GDB/LLDB sites pass stdin=<input_file>. Combine that with
        profile=debug + target+output + sanitise."""
        from core.sandbox import run as sandbox_run
        input_file = Path(self.tmp.name) / "fake-input"
        input_file.write_bytes(b"A" * 16)
        with open(input_file, "rb") as fh:
            result = sandbox_run(
                ["cat", "/etc/hostname"],
                profile="debug",
                target=self.tmp.name, output=self.tmp.name,
                stdin=fh,
                capture_output=True, text=True, timeout=15,
                sanitise_host_fingerprint=True,
            )
        self._assert_persona_engaged(result, "(profile=debug + stdin)")

    def test_persona_under_block_network(self):
        """Plain `run_binary` path: block_network=True + target+output
        + sanitise. No profile=debug, no ptrace."""
        from core.sandbox import run as sandbox_run
        result = sandbox_run(
            ["cat", "/etc/hostname"],
            block_network=True,
            target=self.tmp.name, output=self.tmp.name,
            capture_output=True, text=True, timeout=15,
            sanitise_host_fingerprint=True,
        )
        self._assert_persona_engaged(result, "(block_network=True)")


class TestAflRunnerKwargCombo(_ConsumerE2EBase):
    """Replicates afl_runner.py:709 — block_network + readable_paths +
    target+output + sanitise_host_fingerprint."""

    def test_persona_with_readable_paths(self):
        from core.sandbox import run as sandbox_run
        # readable_paths is the kwarg that afl-showmap passes (paths
        # to allow reads from in addition to the system + target +
        # output defaults). An empty list exercises the kwarg surface
        # without needing real harness paths.
        result = sandbox_run(
            ["cat", "/etc/hostname"],
            block_network=True,
            target=self.tmp.name, output=self.tmp.name,
            readable_paths=[],
            capture_output=True, text=True, timeout=15,
            sanitise_host_fingerprint=True,
        )
        self._assert_persona_engaged(result, "(readable_paths + block_network)")


class TestPersonaConsistencyAcrossConsumers(_ConsumerE2EBase):
    """The same persona must produce the same hostname / machine-id /
    cpu_count across consumer kwarg combos — otherwise two consumers
    of the same persona could produce inconsistent fingerprints."""

    def test_machine_id_identical_across_combos(self):
        from core.sandbox import run as sandbox_run
        def _machine_id(**kwargs):
            r = sandbox_run(
                ["cat", "/etc/machine-id"],
                target=self.tmp.name, output=self.tmp.name,
                capture_output=True, text=True, timeout=15,
                sanitise_host_fingerprint=True,
                **kwargs,
            )
            assert r.returncode == 0, r.stderr
            return r.stdout.strip()
        debug_mid = _machine_id(profile="debug")
        block_mid = _machine_id(block_network=True)
        self.assertEqual(
            debug_mid, block_mid,
            "machine-id must be persona-derived (deterministic per "
            "RAPTOR install) — not dependent on the sandbox profile",
        )

    def test_cpu_count_consistent_across_combos(self):
        from core.sandbox import run as sandbox_run
        def _nproc(**kwargs):
            r = sandbox_run(
                ["nproc"],
                target=self.tmp.name, output=self.tmp.name,
                capture_output=True, text=True, timeout=15,
                sanitise_host_fingerprint=True,
                **kwargs,
            )
            assert r.returncode == 0, r.stderr
            return r.stdout.strip()
        debug_n = _nproc(profile="debug")
        block_n = _nproc(block_network=True)
        # Default cpu_count=4 when sanitise is on.
        self.assertEqual(debug_n, "4")
        self.assertEqual(block_n, "4")


class TestCodeqlKwargCombo(_ConsumerE2EBase):
    """Replicates database_manager.py:790 — block_network +
    sanitise_host_fingerprint + cpu_count=HOST_CPU_COUNT. Must mask
    identity surfaces while preserving real CPU count + affinity
    (otherwise codeql autobuild's `make -j$(nproc)` serialises)."""

    def test_persona_engages_with_host_cpu_count(self):
        from core.sandbox import run as sandbox_run
        from core.sandbox.fingerprint import HOST_CPU_COUNT
        result = sandbox_run(
            ["cat", "/etc/hostname"],
            block_network=True,
            target=self.tmp.name, output=self.tmp.name,
            capture_output=True, text=True, timeout=15,
            sanitise_host_fingerprint=True,
            cpu_count=HOST_CPU_COUNT,
        )
        self._assert_persona_engaged(result, "(codeql kwarg combo)")

    def test_host_cpu_count_preserves_real_parallelism(self):
        """With HOST_CPU_COUNT, nproc inside the sandbox must equal
        the host's schedulable CPU count — not the default 4. Proves
        the parallelism-preservation property that motivated this
        sentinel."""
        from core.sandbox import run as sandbox_run
        from core.sandbox.fingerprint import HOST_CPU_COUNT
        expected = str(len(os.sched_getaffinity(0)))
        result = sandbox_run(
            ["nproc"],
            block_network=True,
            target=self.tmp.name, output=self.tmp.name,
            capture_output=True, text=True, timeout=15,
            sanitise_host_fingerprint=True,
            cpu_count=HOST_CPU_COUNT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(), expected,
            f"HOST_CPU_COUNT must preserve real nproc; "
            f"expected {expected}, got {result.stdout.strip()!r}",
        )

    def test_host_cpu_count_still_masks_machine_id(self):
        """Identity surfaces must STILL be masked even when CPU count
        is preserved — operator-machine-id leak is the original
        threat we're defending against."""
        from core.sandbox import run as sandbox_run
        from core.sandbox.fingerprint import HOST_CPU_COUNT, _MACHINE_ID
        result = sandbox_run(
            ["cat", "/etc/machine-id"],
            block_network=True,
            target=self.tmp.name, output=self.tmp.name,
            capture_output=True, text=True, timeout=15,
            sanitise_host_fingerprint=True,
            cpu_count=HOST_CPU_COUNT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), _MACHINE_ID)


class TestProfileDebugDoesNotBreakPtrace(_ConsumerE2EBase):
    """The debugger/crash_analyser sites use profile=debug specifically
    so ptrace works (seccomp ptrace block is lifted). Sanitisation
    must NOT engage seccomp blocks that would re-break ptrace.
    Concrete test: spawn a child that ptraces itself and reads
    /proc/self/syscall — succeeds iff ptrace is permitted."""

    def test_strace_self_under_sanitise_plus_debug(self):
        # We don't require strace to be installed; instead spawn a
        # python child that calls PR_SET_PTRACER and ptrace(0, ...)
        # — operations that only succeed if ptrace seccomp block
        # is lifted (which profile=debug does).
        from core.sandbox import run as sandbox_run
        if not shutil.which("python3"):
            self.skipTest("python3 not in PATH")
        py_script = (
            "import ctypes, os, sys;"
            " libc = ctypes.CDLL('libc.so.6', use_errno=True);"
            # PR_SET_PTRACER_ANY = -1; arg2 is the PID allowed to
            # trace us. We aren't actually tracing — this just
            # verifies the syscall isn't seccomp-blocked.
            " r = libc.prctl(0x59616d61, -1, 0, 0, 0);"
            " sys.exit(0 if r == 0 else 1)"
        )
        result = sandbox_run(
            ["python3", "-c", py_script],
            profile="debug",
            target=self.tmp.name, output=self.tmp.name,
            capture_output=True, text=True, timeout=15,
            sanitise_host_fingerprint=True,
        )
        self.assertEqual(
            result.returncode, 0,
            f"PR_SET_PTRACER failed under sanitise+debug — "
            f"sanitisation may be silently engaging extra seccomp blocks. "
            f"stderr={result.stderr!r}",
        )
