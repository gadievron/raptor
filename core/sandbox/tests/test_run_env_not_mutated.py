"""run() must not mutate a caller-supplied env dict.

Pins the fix for the pid1-shim trust-marker injection: run() used
``kwargs["env"].setdefault("_RAPTOR_TRUSTED", "1")`` on what could
still BE the caller's dictionary (the proxy / fake-home /
degraded-net paths rebuild it, but only when those features are
active). A caller reusing its env dict for a later non-sandbox
subprocess then handed the sandbox-internal trust marker to
processes that must not carry it.
"""

import sys as _sys

import pytest as _pytest

pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals",
)


import unittest

from core.sandbox import check_net_available
from core.sandbox import run as sandbox_run


class TestCallerEnvNotMutated(unittest.TestCase):

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")

    def test_run_does_not_mutate_caller_env(self):
        caller_env = {"LC_ALL": "C"}
        snapshot = dict(caller_env)
        r = sandbox_run(
            ["/bin/true"],
            env=caller_env,
            env_caller_filtered=True,
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0)
        self.assertNotIn(
            "_RAPTOR_TRUSTED", caller_env,
            "sandbox trust marker leaked into the caller's env dict",
        )
        self.assertEqual(caller_env, snapshot,
                         "run() mutated the caller-supplied env dict")
