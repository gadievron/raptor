"""Default resource-limit caps (NOFILE everywhere, NPROC on the
no-namespace path).

Battery shapes pinned here:
- fd exhaustion: a sandboxed child could previously open descriptors
  up to the host's per-process ceiling (commonly 2^20) — RLIMIT_NOFILE
  now defaults to 4096.
- fork storm on the Landlock-only path: with no user namespace there
  was NO process bound at all (a flat RLIMIT_NPROC would count the
  operator's unrelated same-uid processes). The child now gets an
  absolute ceiling of current-same-uid-count + the configured nproc
  headroom.
"""

import os
import resource
import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="sandbox rlimit defaults are Linux-only",
)

_PRINT_LIMITS = (
    "import resource, json; "
    "print(json.dumps({"
    "'nofile': resource.getrlimit(resource.RLIMIT_NOFILE), "
    "'nproc': resource.getrlimit(resource.RLIMIT_NPROC)}))"
)


def _child_limits(**sandbox_kwargs):
    import json

    from core.sandbox import sandbox
    with sandbox(**sandbox_kwargs) as run:
        r = run([sys.executable, "-c", _PRINT_LIMITS],
                capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


class TestNofileDefault(unittest.TestCase):
    def setUp(self):
        self._out = tempfile.TemporaryDirectory(prefix="raptor-rlim-")
        self.addCleanup(self._out.cleanup)
        self.out = self._out.name

    def test_child_nofile_soft_limit_capped(self):
        limits = _child_limits(output=self.out)
        soft, _hard = limits["nofile"]
        host_hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        want = 4096 if host_hard == resource.RLIM_INFINITY else min(
            4096, host_hard)
        self.assertEqual(soft, want,
                         "sandboxed child must get the RLIMIT_NOFILE "
                         "default cap")

    def test_fd_exhaustion_bounded(self):
        """Battery shape: open /dev/null until failure — must cap out
        at the default instead of running to the host ceiling."""
        from core.sandbox import sandbox
        prog = (
            "import os\n"
            "n = 0\n"
            "try:\n"
            "    while n < 100000:\n"
            "        os.open('/dev/null', os.O_RDONLY); n += 1\n"
            "except OSError:\n"
            "    pass\n"
            "print('OPENED', n)\n"
        )
        with sandbox(output=self.out) as run:
            r = run([sys.executable, "-c", prog],
                    capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        opened = int(r.stdout.split("OPENED", 1)[1].strip())
        self.assertLess(opened, 5000,
                        "fd exhaustion must hit the NOFILE cap, "
                        f"not run away (opened {opened})")

    def test_operator_override_wins(self):
        limits = _child_limits(output=self.out, limits={"nofile": 8192})
        soft, _hard = limits["nofile"]
        host_hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        want = 8192 if host_hard == resource.RLIM_INFINITY else min(
            8192, host_hard)
        self.assertEqual(soft, want)


class TestHostNprocCapOnNoNamespacePath(unittest.TestCase):
    """Landlock-only posture (no userns/netns) — the fork-storm bound."""

    def setUp(self):
        self._out = tempfile.TemporaryDirectory(prefix="raptor-rlim-")
        self.addCleanup(self._out.cleanup)
        self.out = self._out.name

    def _ll_only_limits(self):
        with patch("core.sandbox.context.check_net_available",
                   return_value=False), \
             patch("core.sandbox.context.check_mount_available",
                   return_value=False):
            return _child_limits(output=self.out, block_network=False)

    def test_nproc_finite_on_ll_only_path(self):
        limits = self._ll_only_limits()
        soft, _hard = limits["nproc"]
        self.assertNotEqual(soft, -1,
                            "LL-only child must not run with unlimited "
                            "RLIMIT_NPROC (fork-storm bound missing)")
        # Ceiling = same-uid TASK (thread) count at setup + default
        # nproc headroom (1024) — RLIMIT_NPROC counts tasks, so the
        # cap must too. Allow generous slack for concurrent activity.
        uid = os.geteuid()
        count = 0
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            try:
                if os.stat(f"/proc/{d}").st_uid != uid:
                    continue
                with open(f"/proc/{d}/status", "rb") as f:
                    for line in f.read(4096).splitlines():
                        if line.startswith(b"Threads:"):
                            count += int(line.split()[1])
                            break
                    else:
                        count += 1
            except (OSError, ValueError, IndexError):
                continue
        self.assertLess(soft, count + 1024 + 512,
                        "nproc ceiling should track same-uid task "
                        "count + configured headroom")
        self.assertGreater(soft, 1024 - 1,
                           "headroom must not starve legitimate work")


if __name__ == "__main__":
    unittest.main()
