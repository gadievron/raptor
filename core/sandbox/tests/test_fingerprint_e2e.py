"""End-to-end tests for host-fingerprint sanitisation.

Exercises the full chain: caller passes persona → unshare(CLONE_NEWUTS)
→ set_uts() → mount_ns with persona → apply_overlay → sched_setaffinity
→ child execs and reads the masked surfaces.

Skips gracefully where mount-ns isn't usable (missing uidmap,
apparmor_restrict_unprivileged_userns=1) — same pattern as
test_spawn_mount_ns.py.
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
    reason="fingerprint sanitisation is Linux-only (mount-ns + UTS-ns)",
)


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


class TestFingerprintEndToEnd(unittest.TestCase):
    """Full sandbox spawn with sanitise_host_fingerprint → child reads
    masked files. Each test runs a small sh snippet inside the sandbox
    and asserts the captured stdout matches the persona, not the host.
    """

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.persona_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.persona_dir.cleanup)
        # cpu_count=2 keeps the persona small and avoids the single-CPU
        # affinity-test footgun (sched_setaffinity to {0} is a no-op on
        # already-pinned systems and doesn't exercise the multi-bit case).
        from core.sandbox.fingerprint import build_persona
        self.persona = build_persona(Path(self.persona_dir.name), cpu_count=2)

    def _spawn(self, sh_argv: str):
        from core.sandbox._spawn import run_sandboxed
        return run_sandboxed(
            ["sh", "-c", sh_argv],
            target=self.tmp.name, output=self.tmp.name,
            block_network=True,
            nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240, "cpu_seconds": 300},
            writable_paths=[self.tmp.name, "/tmp"],
            readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile=None,
            seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
            persona=self.persona,
        )

    # --- /proc/cpuinfo ---

    def test_cpuinfo_model_name_masked(self):
        """Child sees the canonical Xeon string, not the host's real CPU."""
        r = self._spawn("grep 'model name' /proc/cpuinfo | head -1")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("Intel(R) Xeon(R)", r.stdout)

    def test_cpuinfo_identity_triple_is_real_xeon(self):
        """family/model/stepping must match the real Skylake-X Xeon
        identity, not the (6,1,0) Pentium-Pro signature."""
        r = self._spawn(
            "egrep '^(cpu family|model|stepping)' /proc/cpuinfo | sort -u"
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        out = r.stdout
        self.assertIn("cpu family\t: 6", out)
        self.assertIn("model\t\t: 85", out)
        self.assertIn("stepping\t: 7", out)

    def test_cpuinfo_processor_count_matches_persona(self):
        """cpuinfo blocks N must equal persona.cpu_count (= 2 in setUp)."""
        r = self._spawn("grep -c '^processor' /proc/cpuinfo")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(r.stdout.strip(), "2")

    def test_cpuinfo_flags_still_real(self):
        """Capability surface preserved: child's cpuinfo flags include
        a feature flag present on every modern x86 (sse2). The exact
        flag set is host-derived, so this is a "non-empty" check."""
        r = self._spawn("grep '^flags' /proc/cpuinfo | head -1")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        # sse2 is mandatory in the x86_64 ABI; any Linux host running
        # this test will have it. If we ever port to aarch64 / riscv64
        # this assertion needs revisiting (different baseline flag).
        if "x86" in os.uname().machine:
            self.assertIn("sse2", r.stdout)

    # --- /etc/hostname + uname() nodename ---

    def test_etc_hostname_is_localhost(self):
        r = self._spawn("cat /etc/hostname")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(r.stdout.strip(), "localhost")

    def test_gethostname_is_localhost(self):
        """uname() nodename — what gethostname() syscall returns. Must
        match /etc/hostname so a cross-check isn't a sandbox tell."""
        r = self._spawn("hostname")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(r.stdout.strip(), "localhost")

    def test_uname_release_preserved_from_host(self):
        """Capability surface: uname -r returns the real host kernel
        release. exploit_feasibility's `uname -r` call depends on this."""
        r = self._spawn("uname -r")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(r.stdout.strip(), os.uname().release)

    def test_uname_machine_preserved_from_host(self):
        """Capability surface: uname -m returns the real arch. Shellcode
        dispatch (pwntools context.arch) depends on this."""
        r = self._spawn("uname -m")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(r.stdout.strip(), os.uname().machine)

    # --- /etc/{os-release,machine-id} ---

    def test_os_release_is_debian_12(self):
        r = self._spawn("cat /etc/os-release")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("ID=debian", r.stdout)
        self.assertIn('VERSION_ID="12"', r.stdout)

    def test_machine_id_is_deterministic_pseudo_random(self):
        from core.sandbox.fingerprint import _MACHINE_ID
        r = self._spawn("cat /etc/machine-id")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(r.stdout.strip(), _MACHINE_ID)

    # --- /proc/version trim ---

    def test_proc_version_is_trimmed(self):
        r = self._spawn("cat /proc/version")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        line = r.stdout.strip()
        self.assertTrue(line.startswith("Linux version "), line)
        # No fingerprint markers — build-host / compiler / build number.
        self.assertNotIn("(", line)
        self.assertNotIn("@", line)
        self.assertNotIn("#", line)

    # --- /sys/devices/system/cpu ---

    def test_cpu_online_matches_persona(self):
        r = self._spawn("cat /sys/devices/system/cpu/online")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        # persona has cpu_count=2 → expect "0-1"
        self.assertEqual(r.stdout.strip(), "0-1")

    def test_nproc_returns_persona_cpu_count(self):
        """`nproc` reads sysconf(_SC_NPROCESSORS_ONLN) → sysfs cpu/online
        (or affinity mask). Either path should give persona.cpu_count."""
        r = self._spawn("nproc")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(r.stdout.strip(), "2")

    def test_sched_getaffinity_matches_persona(self):
        """Python's os.sched_getaffinity reads the kernel affinity mask
        set by sched_setaffinity in step 9.5. Must match cpu_count
        bits — disagreement with cpuinfo would be a cross-check tell."""
        r = self._spawn(
            "python3 -c 'import os; print(sorted(os.sched_getaffinity(0)))'"
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(r.stdout.strip(), "[0, 1]")

    # --- DMI ---

    def test_dmi_sys_vendor_is_qemu(self):
        r = self._spawn("cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo MISSING")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        # Host may not have DMI at all (container, some VMs); the
        # bind-mount apply_overlay skips missing targets silently.
        # When DMI is present on host, our bind takes effect.
        if "MISSING" not in r.stdout:
            self.assertEqual(r.stdout.strip(), "QEMU")

    # --- preservation: /proc/sys/kernel/* untouched ---

    def test_sysctl_randomize_va_space_preserved(self):
        """exploit_feasibility reads this sysctl to detect ASLR. Must
        remain host-real; sanitisation only touches identity files."""
        host = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
        r = self._spawn("cat /proc/sys/kernel/randomize_va_space")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertEqual(r.stdout.strip(), host)

    def test_proc_self_status_pid_preserved(self):
        """/proc/self/* is pid-ns-local but otherwise real. ASAN, GDB,
        pwntools depend on it."""
        r = self._spawn("grep '^Pid:' /proc/self/status")
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        # Inside the sandbox pid-ns the grandchild runs as PID 1.
        self.assertIn("Pid:\t", r.stdout)
