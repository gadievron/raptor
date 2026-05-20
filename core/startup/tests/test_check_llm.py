"""Tests for check_llm() validator-prerequisite + warning dedup."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock


class TestCheckLLMValidatorPrereq(unittest.TestCase):

    def _models_file(self, tmpdir: Path) -> Path:
        cfg_dir = tmpdir / ".config" / "raptor"
        cfg_dir.mkdir(parents=True)
        path = cfg_dir / "models.json"
        path.write_text(json.dumps({"models": [
            {"provider": "gemini",    "model": "gemini-2.5-pro",   "api_key": "k1", "role": "analysis"},
            {"provider": "gemini",    "model": "gemini-2.5-flash", "api_key": "k1", "role": "fallback"},
            {"provider": "anthropic", "model": "claude-haiku-4-5", "api_key": "k2", "role": "consensus"},
        ]}))
        return path

    def test_missing_requests_emits_single_warning_no_per_provider_failures(self):
        """Validator dep missing → one 'skipped' warning, zero key-failure warnings."""
        from core.startup import init

        with TemporaryDirectory() as d:
            tmp = Path(d)
            self._models_file(tmp)
            with mock.patch.object(Path, "home", return_value=tmp), \
                 mock.patch("core.startup.init._validator_available", return_value=False), \
                 mock.patch("core.startup.init._test_key") as test_key:
                lines, warnings = init.check_llm()

        skipped = [w for w in warnings if "validation skipped" in w]
        failed = [w for w in warnings if "API key validation failed" in w]
        self.assertEqual(len(skipped), 1, f"expected one 'skipped' warning, got: {warnings}")
        self.assertIn("requests", skipped[0])
        self.assertEqual(failed, [], f"expected zero key-failure warnings when validator missing, got: {failed}")
        # And the threadpool path must never have called _test_key.
        test_key.assert_not_called()

    def test_duplicate_provider_emits_warning_once(self):
        """Two gemini entries with a failing key → one warning, not two."""
        from core.startup import init

        with TemporaryDirectory() as d:
            tmp = Path(d)
            self._models_file(tmp)
            with mock.patch.object(Path, "home", return_value=tmp), \
                 mock.patch("core.startup.init._validator_available", return_value=True), \
                 mock.patch("core.startup.init._test_key", return_value=False):
                lines, warnings = init.check_llm()

        gemini_failures = [w for w in warnings if w == "gemini API key validation failed"]
        self.assertEqual(len(gemini_failures), 1,
                         f"expected one gemini failure warning despite two gemini entries, got: {warnings}")

    def test_all_providers_pass_emits_no_failure_warnings(self):
        """Sanity: when keys pass, no failure warnings even with duplicate providers."""
        from core.startup import init

        with TemporaryDirectory() as d:
            tmp = Path(d)
            self._models_file(tmp)
            with mock.patch.object(Path, "home", return_value=tmp), \
                 mock.patch("core.startup.init._validator_available", return_value=True), \
                 mock.patch("core.startup.init._test_key", return_value=True):
                lines, warnings = init.check_llm()

        failures = [w for w in warnings if "API key validation failed" in w]
        self.assertEqual(failures, [])

    def test_per_provider_failure_distinguishes_providers(self):
        """When gemini fails but anthropic passes, only gemini is warned."""
        from core.startup import init

        with TemporaryDirectory() as d:
            tmp = Path(d)
            self._models_file(tmp)

            def status(provider, api_key, api_base=None):
                return provider != "gemini"

            with mock.patch.object(Path, "home", return_value=tmp), \
                 mock.patch("core.startup.init._validator_available", return_value=True), \
                 mock.patch("core.startup.init._test_key", side_effect=status):
                lines, warnings = init.check_llm()

        failures = sorted(w for w in warnings if "API key validation failed" in w)
        self.assertEqual(failures, ["gemini API key validation failed"])


if __name__ == "__main__":
    unittest.main()
