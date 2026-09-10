"""Tri-state repo trust must cross every unified-launcher child boundary."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import raptor


_MODES = (
    raptor.mode_agentic,
    raptor.mode_codeql,
    raptor.mode_scan,
    raptor.mode_llm_analysis,
)


class TestTrustRepoPropagation(unittest.TestCase):
    def setUp(self):
        saved = raptor._REPO_TRUST_OVERRIDE
        self.addCleanup(setattr, raptor, "_REPO_TRUST_OVERRIDE", saved)
        from core.project.trust import set_repo_trust_override
        self.addCleanup(set_repo_trust_override, None)
        raptor._REPO_TRUST_OVERRIDE = None

    def _captured_args(self, mode_fn, argv):
        captured = {}

        def fake_lifecycle(command, script_path, args, *a, **k):
            captured["args"] = args
            return 0

        def fake_script(script_path, args, *a, **k):
            captured["args"] = args
            return 0

        runner = (
            mock.patch.object(raptor, "_run_script", fake_script)
            if mode_fn is raptor.mode_llm_analysis
            else mock.patch.object(
                raptor, "_run_with_lifecycle", fake_lifecycle,
            )
        )
        with runner:
            rc = mode_fn(list(argv))
        self.assertEqual(rc, 0)
        return captured["args"]

    def _assert_canonical(self, args, expected):
        trust_flags = [
            arg for arg in args
            if arg in ("--trust-repo", "--no-trust-repo")
        ]
        self.assertEqual(trust_flags, expected)

    def test_positive_reaches_every_child(self):
        raptor._REPO_TRUST_OVERRIDE = True
        for mode_fn in _MODES:
            with self.subTest(mode=mode_fn.__name__):
                args = self._captured_args(mode_fn, ["--repo", "/tgt"])
                self._assert_canonical(args, ["--trust-repo"])

    def test_negative_reaches_every_child(self):
        raptor._REPO_TRUST_OVERRIDE = False
        for mode_fn in _MODES:
            with self.subTest(mode=mode_fn.__name__):
                args = self._captured_args(mode_fn, ["--repo", "/tgt"])
                self._assert_canonical(args, ["--no-trust-repo"])

    def test_unspecified_reaches_every_child_as_no_flag(self):
        raptor._REPO_TRUST_OVERRIDE = None
        for mode_fn in _MODES:
            with self.subTest(mode=mode_fn.__name__):
                args = self._captured_args(mode_fn, ["--repo", "/tgt"])
                self._assert_canonical(args, [])

    def test_no_duplicates_and_negative_decision_wins(self):
        raptor._REPO_TRUST_OVERRIDE = False
        polluted = [
            "--trust-repo",
            "--repo", "/tgt",
            "--no-trust-repo",
            "--trust-repo",
        ]
        for mode_fn in _MODES:
            with self.subTest(mode=mode_fn.__name__):
                args = self._captured_args(mode_fn, polluted)
                self._assert_canonical(args, ["--no-trust-repo"])

    def test_direct_mode_flags_are_preserved_and_canonicalized(self):
        raptor._REPO_TRUST_OVERRIDE = None
        for mode_fn in _MODES:
            with self.subTest(mode=mode_fn.__name__, decision="positive"):
                args = self._captured_args(
                    mode_fn,
                    ["--trust-repo", "--trust-repo", "--repo", "/tgt"],
                )
                self._assert_canonical(args, ["--trust-repo"])
            with self.subTest(mode=mode_fn.__name__, decision="both"):
                args = self._captured_args(
                    mode_fn,
                    [
                        "--trust-repo",
                        "--no-trust-repo",
                        "--repo", "/tgt",
                    ],
                )
                self._assert_canonical(args, ["--no-trust-repo"])

    def _captured_main(self, argv):
        captured = {}

        def fake_script(script_path, args, *a, **k):
            captured["args"] = args
            return 0

        with mock.patch.object(sys, "argv", ["raptor.py", *argv]), \
                mock.patch.object(raptor, "_run_script", fake_script):
            rc = raptor.main()
        self.assertEqual(rc, 0)
        return captured["args"]

    def test_top_level_both_flags_forward_only_negative(self):
        args = self._captured_main([
            "analyze",
            "--repo", "/tgt",
            "--sarif", "findings.sarif",
            "--trust-repo",
            "--no-trust-repo",
        ])
        self._assert_canonical(args, ["--no-trust-repo"])
        self.assertIs(raptor._REPO_TRUST_OVERRIDE, False)

    def test_unspecified_resets_stale_state_and_inherits_session(self):
        import core.security.cc_trust as cct
        import core.security.codeql_trust as qlt

        with tempfile.TemporaryDirectory() as td:
            target = Path(td)
            (target / "qlpack.yml").write_text(
                "name: attacker/pack\nextractor: ./unsafe\n",
                encoding="utf-8",
            )
            cct.set_trust_override(True)
            qlt.set_trust_override(True)
            raptor._REPO_TRUST_OVERRIDE = True
            with mock.patch(
                "core.project.sessions.session_repo_trusted",
                side_effect=lambda repo: Path(repo).resolve()
                == target.resolve(),
            ):
                args = self._captured_main([
                    "analyze",
                    "--repo", str(target),
                    "--sarif", "findings.sarif",
                ])
                self._assert_canonical(args, [])
                self.assertIsNone(raptor._REPO_TRUST_OVERRIDE)
                self.assertIsNone(cct._trust_override_set)
                self.assertIsNone(qlt._trust_override_set)
                self.assertTrue(cct.is_trust_overridden(target))
                self.assertFalse(qlt.check_repo_codeql_trust(str(target)))

    def test_explicit_negative_overrides_trusted_session(self):
        import core.security.cc_trust as cct
        import core.security.codeql_trust as qlt

        with tempfile.TemporaryDirectory() as td:
            target = Path(td)
            (target / "qlpack.yml").write_text(
                "name: attacker/pack\nextractor: ./unsafe\n",
                encoding="utf-8",
            )
            with mock.patch(
                "core.project.sessions.session_repo_trusted",
                return_value=True,
            ):
                args = self._captured_main([
                    "analyze",
                    "--repo", str(target),
                    "--sarif", "findings.sarif",
                    "--no-trust-repo",
                ])
                self._assert_canonical(args, ["--no-trust-repo"])
                self.assertFalse(cct.is_trust_overridden(target))
                self.assertTrue(qlt.check_repo_codeql_trust(str(target)))


class TestNestedAgenticPropagation(unittest.TestCase):
    def test_both_agentic_children_use_canonical_helper(self):
        root = Path(__file__).resolve().parents[3]
        src = (root / "raptor_agentic.py").read_text(encoding="utf-8")
        self.assertEqual(
            src.count("repo_trust_cli_args(repo_trust_override)"),
            2,
        )
        self.assertNotIn('analysis_cmd.append("--trust-repo")', src)


if __name__ == "__main__":
    unittest.main()
