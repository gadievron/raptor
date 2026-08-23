"""Restricted Landlock-only posture: private scratch instead of
host-shared /tmp and /dev/shm.

Without a mount namespace, the Landlock writable baseline used to
grant ALL of the host-shared /tmp and /dev/shm:

- a target repo living under /tmp was writable despite a read-only
  profile (scanned-tree self-modification);
- host /dev/shm was a cross-process plant/poison surface.

With restrict_reads engaged on a mount-ns-less host, the baseline is
now a fresh per-context 0700 scratch dir, TMPDIR/TEMP/TMP steer tools
to it, and writes to host /tmp, the /tmp-resident target, and host
/dev/shm all fail closed. The unrestricted posture keeps the old
compatible baseline.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock-only posture is Linux-only",
)

_PROBE = r"""
import json, os
res = {"tmpdir": os.environ.get("TMPDIR")}
def try_write(tag, path):
    try:
        with open(path, "w") as f:
            f.write("x")
        res[tag] = "written"
        os.unlink(path)
    except OSError as e:
        res[tag] = "denied:%d" % (e.errno or 0)
try_write("host_tmp", "/tmp/.raptor-scratch-test-%d" % os.getpid())
try_write("dev_shm", "/dev/shm/.raptor-scratch-test-%d" % os.getpid())
try_write("target", os.path.join(__TARGET__, "planted.txt"))
try_write("scratch", os.path.join(os.environ.get("TMPDIR", "/tmp"),
                                  "scratch-ok.txt"))
try_write("output", os.path.join(__OUTPUT__, "out-ok.txt"))
print(json.dumps(res))
"""


def _landlock_ok():
    from core.sandbox import check_landlock_available
    return check_landlock_available()


# System python, not sys.executable: a venv interpreter needs to read
# pyvenv.cfg under the operator's home, which restrict_reads denies.
_SYS_PY = "/usr/bin/python3"


class TestRestrictedLandlockOnlyScratch(unittest.TestCase):
    def setUp(self):
        if not _landlock_ok():
            self.skipTest("Landlock unavailable on this host")
        if not os.path.exists(_SYS_PY):
            self.skipTest("system python3 not present")
        # Target deliberately under /tmp — the battery's policy-gap
        # shape (write baseline used to cover it wholesale).
        self._target = tempfile.TemporaryDirectory(prefix="raptor-tgt-")
        self._out = tempfile.TemporaryDirectory(prefix="raptor-out-")
        self.addCleanup(self._target.cleanup)
        self.addCleanup(self._out.cleanup)
        self.target = os.path.realpath(self._target.name)
        self.out = os.path.realpath(self._out.name)

    def _run_probe(self, **sandbox_kwargs):
        from core.sandbox import sandbox
        prog = (_PROBE.replace("__TARGET__", repr(self.target))
                .replace("__OUTPUT__", repr(self.out)))
        with patch("core.sandbox.context.check_net_available",
                   return_value=False), \
             patch("core.sandbox.context.check_mount_available",
                   return_value=False):
            with sandbox(target=self.target, output=self.out,
                         block_network=False, **sandbox_kwargs) as run:
                r = run([_SYS_PY, "-c", prog],
                        capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1]), r

    def test_restricted_posture_denies_shared_surfaces(self):
        res, r = self._run_probe(restrict_reads=True)
        self.assertTrue(res["host_tmp"].startswith("denied"),
                        f"host /tmp writable in restricted LL posture: {res}")
        self.assertTrue(res["dev_shm"].startswith("denied"),
                        f"host /dev/shm writable in restricted LL posture: {res}")
        self.assertTrue(res["target"].startswith("denied"),
                        f"/tmp-resident target writable despite read-only "
                        f"profile: {res}")
        self.assertEqual(res["scratch"], "written",
                         f"private scratch must be writable: {res}")
        self.assertEqual(res["output"], "written",
                         f"output dir must stay writable: {res}")
        self.assertIn(".raptor-scratch-", res["tmpdir"] or "",
                      "TMPDIR must steer tools to the private scratch")
        self.assertTrue(r.sandbox_info.get("private_scratch"),
                        "sandbox_info must stamp the private-scratch posture")

    def test_scratch_dir_cleaned_up_at_context_exit(self):
        res, _ = self._run_probe(restrict_reads=True)
        scratch = res["tmpdir"]
        self.assertFalse(os.path.exists(scratch),
                         "private scratch dir must be removed at context "
                         "exit")

    def test_unrestricted_posture_keeps_compatible_baseline(self):
        res, r = self._run_probe()
        self.assertEqual(res["host_tmp"], "written",
                         f"unrestricted LL posture must keep /tmp writable "
                         f"for tool compatibility: {res}")
        self.assertNotIn("private_scratch", r.sandbox_info)


if __name__ == "__main__":
    unittest.main()
