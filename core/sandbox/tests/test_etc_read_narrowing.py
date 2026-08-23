"""``omit_etc_reads``: swap the wholesale /etc read grant for the
loader/TLS minimum under ``restrict_reads=True``.

The read allowlist grants ``/etc`` wholesale because the dynamic loader
and NSS need pieces of it — but that hands ``/etc/passwd`` and the rest
of the host-identity surface to any restricted child. Callers whose
payload has no business enumerating the host (the compose resolver) opt
into the narrowed per-file set; the narrowing must hold on BOTH tiers:
the mount-ns backend and the Landlock-only subprocess path, where no
private mount view exists.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Landlock read restriction is Linux-only",
)

_PROBE = textwrap.dedent("""
    try:
        open('/etc/passwd').read(1)
        print('PASSWD_READ')
    except OSError as e:
        print('PASSWD_DENIED', e.errno)
    open('/etc/ld.so.cache', 'rb').read(1)
    print('LOADER_OK')
""")


class TestOmitEtcReads(unittest.TestCase):
    def setUp(self) -> None:
        from core.sandbox.landlock import check_landlock_available
        if not check_landlock_available():
            self.skipTest("Landlock unavailable on this kernel")
        self._tmp = tempfile.TemporaryDirectory(prefix="raptor-etcnarrow-")
        self.addCleanup(self._tmp.cleanup)

    def _run(self, *, omit: bool, **kw) -> subprocess.CompletedProcess:
        from core.sandbox import run as sandbox_run
        return sandbox_run(
            ["/usr/bin/python3", "-c", _PROBE],
            block_network=True,
            target=self._tmp.name,
            restrict_reads=True,
            omit_etc_reads=omit,
            capture_output=True, text=True, timeout=60,
            caller_label="etc-narrow-test",
            **kw,
        )

    def test_etc_passwd_denied_when_narrowed(self) -> None:
        r = self._run(omit=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PASSWD_DENIED", r.stdout,
                      f"/etc/passwd must be unreadable under "
                      f"omit_etc_reads: {r.stdout!r}")
        self.assertIn("LOADER_OK", r.stdout,
                      "the loader minimum (/etc/ld.so.cache) must stay "
                      "readable — the tool has to be able to start")

    def test_etc_wholesale_kept_without_flag(self) -> None:
        """Pin the default: restrict_reads alone keeps /etc wholesale
        (NSS and tool configs depend on it)."""
        r = self._run(omit=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PASSWD_READ", r.stdout, r.stdout)

    def test_landlock_only_tier_also_narrowed(self) -> None:
        """input= demotes the call to the Landlock-only subprocess path
        — exactly the tier where no private mount view narrows /etc, so
        the per-file grant swap must hold there too."""
        r = self._run(omit=True, input="")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PASSWD_DENIED", r.stdout, r.stdout)
        self.assertIn("LOADER_OK", r.stdout, r.stdout)
