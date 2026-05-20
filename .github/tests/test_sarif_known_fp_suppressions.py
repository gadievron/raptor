"""Tests for ``sarif_known_fp_suppressions``.

The script applies SARIF 2.1.0 ``suppressions`` entries to results
matching a documented ``(rule_id, sink_file_prefix)`` tuple. These
tests pin the contract so the suppression table can't grow silently
and the match logic can't regress to over- or under-suppression.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# .github/tests/test_sarif_known_fp_suppressions.py → parents[2] = repo root
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / ".github" / "scripts"))
import sarif_known_fp_suppressions as mod  # noqa: E402


def _make_result(rule_id: str, uri: str | None) -> dict:
    locations = []
    if uri is not None:
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        )
    return {"ruleId": rule_id, "locations": locations}


def _wrap_in_sarif(results: list[dict]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": results,
            }
        ],
    }


class MatchKnownFPTests(unittest.TestCase):
    def test_matches_sandbox_logging_sink(self):
        result = _make_result(
            "py/clear-text-logging-sensitive-data",
            "core/sandbox/context.py",
        )
        self.assertIsNotNone(mod._matches_known_fp(result))

    def test_matches_sandbox_observe_logging_sink(self):
        result = _make_result(
            "py/clear-text-logging-sensitive-data",
            "core/sandbox/observe.py",
        )
        self.assertIsNotNone(mod._matches_known_fp(result))

    def test_matches_storage_sink_in_summary(self):
        result = _make_result(
            "py/clear-text-storage-of-sensitive-information",
            "core/sandbox/summary.py",
        )
        self.assertIsNotNone(mod._matches_known_fp(result))

    def test_does_not_match_other_rules_on_sandbox_files(self):
        """Suppression is rule-specific — other rules on the same
        files must still surface."""
        result = _make_result(
            "py/sql-injection", "core/sandbox/context.py"
        )
        self.assertIsNone(mod._matches_known_fp(result))

    def test_does_not_match_known_rule_on_other_files(self):
        """Suppression is path-specific — the same rule on a
        non-sandbox file must still surface."""
        result = _make_result(
            "py/clear-text-logging-sensitive-data",
            "packages/llm_analysis/agent.py",
        )
        self.assertIsNone(mod._matches_known_fp(result))

    def test_handles_missing_location(self):
        result = _make_result(
            "py/clear-text-logging-sensitive-data", uri=None
        )
        self.assertIsNone(mod._matches_known_fp(result))

    def test_handles_missing_rule_id(self):
        result = _make_result("py/clear-text-logging-sensitive-data", "x")
        del result["ruleId"]
        self.assertIsNone(mod._matches_known_fp(result))


class ApplySuppressionsTests(unittest.TestCase):
    def test_stamps_suppression_on_match(self):
        sarif = _wrap_in_sarif(
            [
                _make_result(
                    "py/clear-text-logging-sensitive-data",
                    "core/sandbox/context.py",
                )
            ]
        )
        matched, newly = mod.apply_suppressions(sarif)
        self.assertEqual(matched, 1)
        self.assertEqual(newly, 1)
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(len(result["suppressions"]), 1)
        sup = result["suppressions"][0]
        self.assertEqual(sup["kind"], "external")
        self.assertEqual(sup["status"], "accepted")
        self.assertIn("Triaged FP", sup["justification"])

    def test_idempotent_on_already_suppressed(self):
        """Re-running the script on a SARIF that's already had this
        suppression applied must not double-stamp."""
        sarif = _wrap_in_sarif(
            [
                _make_result(
                    "py/clear-text-logging-sensitive-data",
                    "core/sandbox/context.py",
                )
            ]
        )
        mod.apply_suppressions(sarif)  # first pass
        matched, newly = mod.apply_suppressions(sarif)  # second pass
        self.assertEqual(matched, 1)
        self.assertEqual(newly, 0)
        self.assertEqual(
            len(sarif["runs"][0]["results"][0]["suppressions"]), 1
        )

    def test_leaves_unrelated_results_untouched(self):
        sarif = _wrap_in_sarif(
            [
                _make_result(
                    "py/sql-injection", "core/sandbox/context.py"
                ),
                _make_result(
                    "py/clear-text-logging-sensitive-data",
                    "packages/llm_analysis/agent.py",
                ),
            ]
        )
        matched, newly = mod.apply_suppressions(sarif)
        self.assertEqual(matched, 0)
        self.assertEqual(newly, 0)
        for r in sarif["runs"][0]["results"]:
            self.assertNotIn("suppressions", r)

    def test_multiple_runs_handled(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL"}},
                    "results": [
                        _make_result(
                            "py/clear-text-logging-sensitive-data",
                            "core/sandbox/context.py",
                        )
                    ],
                },
                {
                    "tool": {"driver": {"name": "CodeQL"}},
                    "results": [
                        _make_result(
                            "py/clear-text-storage-of-sensitive-information",
                            "core/sandbox/summary.py",
                        )
                    ],
                },
            ],
        }
        matched, newly = mod.apply_suppressions(sarif)
        self.assertEqual(matched, 2)
        self.assertEqual(newly, 2)


class TableShapeTests(unittest.TestCase):
    """Pin the suppression table shape so growth stays auditable."""

    def test_table_nonempty(self):
        self.assertTrue(mod.KNOWN_FP_RULES)

    def test_every_entry_has_justification(self):
        for entry in mod.KNOWN_FP_RULES:
            self.assertTrue(
                entry.justification.strip(),
                msg=f"empty justification on {entry.rule_id}",
            )
            self.assertGreaterEqual(
                len(entry.justification), 60,
                msg=(
                    f"justification too terse on {entry.rule_id} — "
                    "explain why this is an FP, not just that it is"
                ),
            )

    def test_every_entry_has_sink_files(self):
        for entry in mod.KNOWN_FP_RULES:
            self.assertTrue(
                entry.sink_file_prefixes,
                msg=f"empty sink_file_prefixes on {entry.rule_id}",
            )


if __name__ == "__main__":
    unittest.main()
