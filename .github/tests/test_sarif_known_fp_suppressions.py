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


def _make_result_with_flow(
    rule_id: str,
    sink_uri: str,
    flow_steps: list[tuple[str, str]],
) -> dict:
    """Build a result with codeFlows. Each flow_step is (uri, message)."""
    result = _make_result(rule_id, sink_uri)
    locations = []
    for step_uri, step_msg in flow_steps:
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": step_uri},
                    "region": {"startLine": 1},
                },
                "message": {"text": step_msg},
            }
        })
    result["codeFlows"] = [{"threadFlows": [{"locations": locations}]}]
    return result


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

    def test_matches_raptor_audit_logging_sink(self):
        """libexec/raptor-audit is covered by a KnownFP entry because
        CodeQL intermittently omits flow steps through redact_secrets."""
        result = _make_result(
            "py/clear-text-logging-sensitive-data",
            "libexec/raptor-audit",
        )
        match = mod._matches_known_fp(result)
        self.assertIsNotNone(match)
        self.assertIsInstance(match, mod.KnownFP)

    def test_raptor_audit_matched_even_without_sanitiser_flow(self):
        """The KnownFP entry catches raptor-audit regardless of whether
        CodeQL includes or omits flow steps through the sanitiser."""
        result = _make_result_with_flow(
            "py/clear-text-logging-sensitive-data",
            "libexec/raptor-audit",
            [
                ("libexec/raptor-audit", "ctx from assemble_context"),
                ("libexec/raptor-audit", "print raw output"),
            ],
        )
        match = mod._matches_known_fp(result)
        self.assertIsNotNone(match)
        self.assertIsInstance(match, mod.KnownFP)


class SanitizerFPTests(unittest.TestCase):
    """Test the SanitizerFP flow-matching logic.

    These tests use a sink URI NOT covered by KnownFP so the flow-based
    matching is exercised independently.  The raptor-audit KnownFP is
    tested separately in MatchKnownFPTests.
    """

    def test_matches_flow_through_redact_secrets(self):
        result = _make_result_with_flow(
            "py/clear-text-logging-sensitive-data",
            "packages/llm_analysis/agent.py",
            [
                ("packages/llm_analysis/agent.py", "ctx"),
                ("core/security/redaction.py", "call to redact_secrets"),
                ("packages/llm_analysis/agent.py", "print sanitised"),
            ],
        )
        match = mod._matches_known_fp(result)
        self.assertIsNotNone(match)
        self.assertIsInstance(match, mod.SanitizerFP)

    def test_no_match_without_sanitiser_in_flow(self):
        result = _make_result_with_flow(
            "py/clear-text-logging-sensitive-data",
            "packages/llm_analysis/agent.py",
            [
                ("packages/llm_analysis/agent.py", "ctx"),
                ("packages/llm_analysis/agent.py", "print raw output"),
            ],
        )
        match = mod._matches_known_fp(result)
        self.assertIsNone(match)

    def test_no_match_for_different_rule(self):
        result = _make_result_with_flow(
            "py/sql-injection",
            "packages/llm_analysis/agent.py",
            [
                ("core/security/redaction.py", "call to redact_secrets"),
            ],
        )
        self.assertIsNone(mod._matches_known_fp(result))

    def test_matches_interior_line_without_func_name(self):
        """CodeQL flow steps inside redact_secrets() reference interior
        lines (e.g. ``result = _redact_with_patterns(...)``) whose
        message/snippet text doesn't contain 'redact_secrets'. The
        matcher must still recognise the flow as passing through the
        sanitiser file."""
        result = _make_result_with_flow(
            "py/clear-text-logging-sensitive-data",
            "packages/llm_analysis/agent.py",
            [
                ("packages/llm_analysis/agent.py", "ctx"),
                ("core/security/redaction.py", "value"),
                ("core/security/redaction.py", "text"),
                ("packages/llm_analysis/agent.py", "print output"),
            ],
        )
        match = mod._matches_known_fp(result)
        self.assertIsNotNone(match)
        self.assertIsInstance(match, mod.SanitizerFP)

    def test_matches_via_related_locations(self):
        result = _make_result(
            "py/clear-text-logging-sensitive-data",
            "packages/llm_analysis/agent.py",
        )
        result["relatedLocations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "core/security/redaction.py"},
                    "region": {"startLine": 161},
                },
                "message": {"text": "redact_secrets sanitises the output"},
            }
        ]
        match = mod._matches_known_fp(result)
        self.assertIsNotNone(match)
        self.assertIsInstance(match, mod.SanitizerFP)

    def test_matches_via_snippet(self):
        result = _make_result(
            "py/clear-text-logging-sensitive-data",
            "packages/llm_analysis/agent.py",
        )
        result["codeFlows"] = [{
            "threadFlows": [{
                "locations": [{
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "core/security/redaction.py"},
                            "region": {"startLine": 161},
                            "contextRegion": {
                                "snippet": {"text": "sanitised = redact_secrets(raw)"},
                            },
                        },
                        "message": {"text": "step 2 of 3"},
                    }
                }]
            }]
        }]
        match = mod._matches_known_fp(result)
        self.assertIsNotNone(match)

    def test_suppresses_sanitiser_match(self):
        sarif = _wrap_in_sarif([
            _make_result_with_flow(
                "py/clear-text-logging-sensitive-data",
                "packages/llm_analysis/agent.py",
                [
                    ("core/security/redaction.py", "call to redact_secrets"),
                ],
            )
        ])
        matched, newly = mod.apply_suppressions(sarif)
        self.assertEqual(matched, 1)
        self.assertEqual(newly, 1)
        sup = sarif["runs"][0]["results"][0]["suppressions"][0]
        self.assertIn("redact_secrets", sup["justification"])


class SanitizerTableShapeTests(unittest.TestCase):
    def test_sanitiser_table_nonempty(self):
        self.assertTrue(mod.SANITIZER_FP_RULES)

    def test_every_sanitiser_entry_has_justification(self):
        for entry in mod.SANITIZER_FP_RULES:
            self.assertTrue(
                entry.justification.strip(),
                msg=f"empty justification on {entry.rule_id}",
            )
            self.assertGreaterEqual(
                len(entry.justification), 60,
                msg=f"justification too terse on {entry.rule_id}",
            )

    def test_every_sanitiser_entry_has_file_and_func(self):
        for entry in mod.SANITIZER_FP_RULES:
            self.assertTrue(entry.sanitizer_file)
            self.assertTrue(entry.sanitizer_function)


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

    def test_known_fp_count_pinned(self):
        """Adding a KnownFP entry requires updating this count.
        If this test fails, you added a suppression — update the
        expected count after confirming the new entry is justified."""
        self.assertEqual(len(mod.KNOWN_FP_RULES), 4)

    def test_sanitizer_fp_count_pinned(self):
        """Adding a SanitizerFP entry requires updating this count."""
        self.assertEqual(len(mod.SANITIZER_FP_RULES), 1)

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

    def test_no_overly_broad_prefixes(self):
        """Every sink_file_prefix must contain '/' — bare names like
        'core' would suppress entire directory trees."""
        for entry in mod.KNOWN_FP_RULES:
            for prefix in entry.sink_file_prefixes:
                self.assertIn(
                    "/", prefix,
                    msg=f"prefix {prefix!r} is too broad (no '/')",
                )

    def test_no_overly_broad_sanitizer_files(self):
        for entry in mod.SANITIZER_FP_RULES:
            self.assertIn(
                "/", entry.sanitizer_file,
                msg=f"sanitizer_file {entry.sanitizer_file!r} is too broad",
            )


if __name__ == "__main__":
    unittest.main()
