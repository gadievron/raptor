"""--trust-repo must reach the subprocess mode handlers' children.

The unified ``raptor.py`` launcher strips ``--trust-repo`` from argv and sets
the trust override in its OWN process. But codeql/agentic spawn the target work
in a SUBPROCESS, which neither inherits that module-level flag nor sees the
stripped argv — so the handlers must re-inject ``--trust-repo`` into the child
args. Without this, ``raptor.py codeql --trust-repo`` silently fails to lift the
child's target-repo trust checks (fail-closed: it over-blocks, but the documented
override is broken). These tests pin the re-injection.
"""
from __future__ import annotations

import unittest
from unittest import mock

import raptor


class TestTrustRepoReinjection(unittest.TestCase):
    def setUp(self):
        saved = raptor._TRUST_REPO_SEEN
        self.addCleanup(setattr, raptor, "_TRUST_REPO_SEEN", saved)

    def _captured_args(self, mode_fn, argv):
        captured = {}

        def fake_lifecycle(command, script_path, args, *a, **k):
            captured["args"] = args
            return 0

        with mock.patch.object(raptor, "_run_with_lifecycle", fake_lifecycle):
            rc = mode_fn(list(argv))
        self.assertEqual(rc, 0)
        return captured["args"]

    def test_codeql_reinjects_when_seen(self):
        raptor._TRUST_REPO_SEEN = True
        self.assertIn("--trust-repo",
                      self._captured_args(raptor.mode_codeql, ["--repo", "/tgt"]))

    def test_agentic_reinjects_when_seen(self):
        raptor._TRUST_REPO_SEEN = True
        self.assertIn("--trust-repo",
                      self._captured_args(raptor.mode_agentic, ["--repo", "/tgt"]))

    def test_no_reinjection_when_not_seen(self):
        raptor._TRUST_REPO_SEEN = False
        self.assertNotIn("--trust-repo",
                         self._captured_args(raptor.mode_codeql, ["--repo", "/tgt"]))
        self.assertNotIn("--trust-repo",
                         self._captured_args(raptor.mode_agentic, ["--repo", "/tgt"]))

    def test_no_duplicate_when_already_present(self):
        raptor._TRUST_REPO_SEEN = True
        args = self._captured_args(
            raptor.mode_codeql, ["--trust-repo", "--repo", "/tgt"])
        self.assertEqual(args.count("--trust-repo"), 1)


if __name__ == "__main__":
    unittest.main()
