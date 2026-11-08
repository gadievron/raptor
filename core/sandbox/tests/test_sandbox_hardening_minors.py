"""Hardening-gap closures: plain-lane namespace creation, sysfs
host-NIC fingerprint.

Two independent controls pinned here, each with its no-overblocking
direction:

- The PLAIN subprocess lane (no unshare bootstrap — the payload execs
  directly under the preexec filter) now carries the same
  namespace-creation deny rules the fork backend always had.
  Pre-fix it was the one lane where ``unshare(CLONE_NEWUSER)`` still
  landed in the kernel (copy_namespaces / nested-userns attack
  surface, reachable with no capability). The unshare-CLI lane keeps
  the permissive filter — its own bootstrap must unshare.

- Mount-ns runs that own a FRESH network namespace mount a fresh
  sysfs instead of rbinding the host's: sysfs's net class is
  netns-tagged, so ``/sys/class/net`` shows only ns-local devices
  where it used to enumerate every host NIC name and MAC address from
  inside a "network-blocked" sandbox.
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if __name__ == "__main__":
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))

from core.sandbox import check_seccomp_available  # noqa: E402
from core.sandbox.tests.capability import requires_landlock, requires_mount

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux sandbox"),
]

# A system-dir interpreter: the venv/user python lives outside the
# mount-ns bind tree, which would (correctly) drop the run to the
# fallback tier and test the wrong path.
_PY = "/usr/bin/python3"

_NS_PROBE = textwrap.dedent("""
    import os, sys
    CLONE_NEWUSER = 0x10000000
    try:
        os.unshare(CLONE_NEWUSER)
        print("NS-CREATED")
        sys.exit(1)
    except OSError as e:
        print("NS-DENIED errno=%d" % (e.errno or -1))
    # Control: plain fork/threads must keep working — the deny rules
    # are per-CLONE_NEW*-flag MASKED_EQ, never a blanket clone block.
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    print("FORK OK")
""")


@pytest.mark.skipif(
    not check_seccomp_available(),
    reason="libseccomp / seccomp filter unavailable on this host",
)
@requires_landlock
class TestPlainLaneNsCreationDenied:
    def test_plain_subprocess_lane_denies_unshare(self):
        from core.sandbox import run

        # No block_network / target / output / restrict_reads →
        # need_unshare is False and the payload execs directly under
        # the preexec filter (the plain lane).
        r = run([_PY, "-c", _NS_PROBE], block_network=False,
                capture_output=True, text=True, timeout=60)
        if r.sandbox_info.get("containment_tier") != "landlock":
            pytest.skip("plain subprocess lane not taken on this host")
        assert "NS-CREATED" not in r.stdout, r.stdout + r.stderr
        assert "NS-DENIED errno=1" in r.stdout, r.stdout + r.stderr
        assert "FORK OK" in r.stdout, r.stdout + r.stderr

    def test_unshare_cli_lane_still_bootstraps(self):
        # No-overblocking direction: a lane whose own bootstrap must
        # unshare keeps working (the ns-blocking variant is never
        # installed under the unshare wrapper).
        from core.sandbox import run

        r = run([_PY, "-c", "print('BOOTSTRAP OK')"], block_network=True,
                capture_output=True, text=True, timeout=60)
        assert "BOOTSTRAP OK" in r.stdout, r.stdout + r.stderr


@requires_mount
class TestFreshSysfsHidesHostNics:
    def _run(self, tmp_path, child, **kwargs):
        from core.sandbox import run

        target = tmp_path / "t"
        output = tmp_path / "o"
        target.mkdir(exist_ok=True)
        output.mkdir(exist_ok=True)
        return run([_PY, "-c", child], target=str(target),
                   output=str(output), capture_output=True, text=True,
                   timeout=60, **kwargs)

    def test_netns_isolated_run_shows_only_ns_local_devices(
            self, tmp_path):
        host_nics = set(os.listdir("/sys/class/net"))
        if host_nics <= {"lo"}:
            pytest.skip("host has no non-loopback NICs to hide")
        child = "import os; print(sorted(os.listdir('/sys/class/net')))"
        r = self._run(tmp_path, child, block_network=True)
        if not r.sandbox_info.get("mount_ns_active"):
            pytest.skip("mount-ns lane not taken on this host")
        if "fresh sysfs mount failed" in (r.stderr or ""):
            pytest.skip("kernel refused the fresh sysfs instance")
        assert r.returncode == 0, r.stdout + r.stderr
        inside = set(eval(r.stdout.strip()))  # noqa: S307 — test-owned literal
        leaked = inside & (host_nics - {"lo"})
        assert not leaked, (
            f"host NICs visible inside the netns-isolated sandbox: "
            f"{leaked}")

    def test_sysfs_still_usable_inside(self, tmp_path):
        # No-overblocking direction: the fresh instance is a full
        # sysfs — hardware/kernel views tools read must still be
        # there.
        child = textwrap.dedent("""
            import os
            assert os.path.isdir("/sys/devices"), "no /sys/devices"
            assert os.path.isdir("/sys/kernel"), "no /sys/kernel"
            print("SYSFS OK")
        """)
        r = self._run(tmp_path, child, block_network=True)
        if not r.sandbox_info.get("mount_ns_active"):
            pytest.skip("mount-ns lane not taken on this host")
        assert "SYSFS OK" in r.stdout, r.stdout + r.stderr

    def test_shared_netns_run_keeps_host_sysfs(self, tmp_path):
        # Boundary pin: without a fresh netns the kernel refuses a
        # fresh sysfs, so the host rbind (and its device visibility)
        # is the documented behaviour there — this test exists so a
        # future change to that boundary is a conscious one.
        child = "import os; print(sorted(os.listdir('/sys/class/net')))"
        r = self._run(tmp_path, child, block_network=False)
        if not r.sandbox_info.get("mount_ns_active"):
            pytest.skip("mount-ns lane not taken on this host")
        assert r.returncode == 0, r.stdout + r.stderr
        inside = set(eval(r.stdout.strip()))  # noqa: S307 — test-owned literal
        assert inside == set(os.listdir("/sys/class/net")), (
            "shared-netns /sys view diverged from the host's")
