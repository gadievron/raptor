#!/usr/bin/env python3
"""Tests for reporting formatting utilities."""

import unittest
from core.reporting.formatting import (
    display_rule_id,
    format_elapsed,
    get_display_status,
    title_case_type,
    truncate_path,
)


class TestDisplayRuleId(unittest.TestCase):
    """Operator-facing short form of SARIF rule ids."""

    def test_strips_registry_cache_prefix(self):
        long = (
            "engine.semgrep.rules.registry-cache.c.lang.security."
            "insecure-use-string-copy-fn.insecure-use-string-copy-fn"
        )
        # Prefix gone AND trailing leaf-duplication collapsed.
        self.assertEqual(
            display_rule_id(long),
            "c.lang.security.insecure-use-string-copy-fn",
        )

    def test_collapses_leaf_duplication_only(self):
        # Trailing `.foo.foo` collapses to `.foo`.
        self.assertEqual(
            display_rule_id("ns.path.foo.foo"),
            "ns.path.foo",
        )

    def test_no_duplication_unchanged(self):
        # When the leaf isn't duplicated, no collapse.
        self.assertEqual(
            display_rule_id("ns.path.foo.bar"),
            "ns.path.foo.bar",
        )

    def test_codeql_rule_id_unchanged(self):
        # CodeQL ids are already short (lang/rule-id).
        self.assertEqual(display_rule_id("cpp/uncontrolled-format-string"),
                         "cpp/uncontrolled-format-string")

    def test_coccinelle_rule_id_unchanged(self):
        # Cocci ids are already short (snake_case).
        self.assertEqual(display_rule_id("lock_imbalance"), "lock_imbalance")

    def test_none_returns_unknown(self):
        self.assertEqual(display_rule_id(None), "unknown")

    def test_empty_returns_unknown(self):
        self.assertEqual(display_rule_id(""), "unknown")

    def test_prefix_only_handles_gracefully(self):
        # Degenerate input: just the prefix. Don't crash; leaf
        # collapse is a no-op since there's no trailing dup.
        result = display_rule_id(
            "engine.semgrep.rules.registry-cache.x"
        )
        self.assertEqual(result, "x")

    def test_does_not_overcollapse_substrings(self):
        # The leaf-dup collapse must split on '.', not substring.
        # `foo.foobar` is NOT a leaf-dup (the segments differ).
        self.assertEqual(
            display_rule_id("ns.foo.foobar"), "ns.foo.foobar",
        )


class TestGetDisplayStatus(unittest.TestCase):

    def test_validate_ruling_exploitable(self):
        self.assertEqual(get_display_status({"ruling": {"status": "exploitable"}}), "Exploitable")

    def test_validate_ruling_confirmed(self):
        self.assertEqual(get_display_status({"ruling": {"status": "confirmed"}}), "Confirmed")

    def test_validate_ruling_ruled_out(self):
        self.assertEqual(get_display_status({"ruling": {"status": "ruled_out"}}), "Ruled Out")

    def test_validate_ruling_constrained(self):
        self.assertEqual(get_display_status({"ruling": {"status": "confirmed_constrained"}}), "Confirmed (Constrained)")

    def test_agentic_exploitable(self):
        self.assertEqual(get_display_status({"is_true_positive": True, "is_exploitable": True}), "Exploitable")

    def test_agentic_false_positive(self):
        self.assertEqual(get_display_status({"is_true_positive": False}), "False Positive")

    def test_agentic_confirmed(self):
        self.assertEqual(get_display_status({"is_true_positive": True, "is_exploitable": False}), "Confirmed")

    def test_agentic_error(self):
        self.assertEqual(get_display_status({"error": "timeout", "error_type": "timeout"}), "Error (timeout)")

    def test_flat_status(self):
        self.assertEqual(get_display_status({"status": "exploitable"}), "Exploitable")

    def test_final_status(self):
        self.assertEqual(get_display_status({"final_status": "confirmed_blocked"}), "Confirmed (Blocked)")

    def test_empty(self):
        self.assertEqual(get_display_status({}), "Unknown")

    def test_validated_ruling(self):
        self.assertEqual(get_display_status({"ruling": {"status": "validated"}}), "Confirmed")

    def test_final_status_overrides_ruling(self):
        """final_status (post-feasibility) takes priority over ruling.status (Stage D)."""
        self.assertEqual(get_display_status({
            "ruling": {"status": "exploitable"},
            "final_status": "confirmed_constrained",
        }), "Confirmed (Constrained)")

    def test_final_status_overrides_ruling_blocked(self):
        self.assertEqual(get_display_status({
            "ruling": {"status": "confirmed"},
            "final_status": "confirmed_blocked",
        }), "Confirmed (Blocked)")

    def test_boolean_overrides_ruling_string(self):
        # Agentic: is_exploitable=True should win over ruling=test_code
        self.assertEqual(get_display_status(
            {"is_true_positive": True, "is_exploitable": True, "ruling": "test_code"}
        ), "Exploitable")

    def test_boolean_false_positive_overrides_ruling(self):
        self.assertEqual(get_display_status(
            {"is_true_positive": False, "ruling": "validated"}
        ), "False Positive")

    def test_boolean_confirmed_when_not_exploitable(self):
        self.assertEqual(get_display_status(
            {"is_true_positive": True, "is_exploitable": False, "ruling": "test_code"}
        ), "Confirmed")


class TestTitleCaseType(unittest.TestCase):

    def test_buffer_overflow(self):
        self.assertEqual(title_case_type("buffer_overflow"), "Buffer Overflow")

    def test_command_injection(self):
        self.assertEqual(title_case_type("command_injection"), "Command Injection")

    def test_empty(self):
        self.assertEqual(title_case_type(""), "—")

    def test_none(self):
        self.assertEqual(title_case_type(None), "—")

    def test_display_name_lookup(self):
        self.assertEqual(title_case_type("null_deref"), "Null Pointer Dereference")
        self.assertEqual(title_case_type("xss"), "Cross-Site Scripting")
        self.assertEqual(title_case_type("sql_injection"), "SQL Injection")

    def test_fallback_for_unlisted(self):
        self.assertEqual(title_case_type("race_condition"), "Race Condition")


class TestTruncatePath(unittest.TestCase):

    def test_short_path(self):
        self.assertEqual(truncate_path("src/foo.py"), "src/foo.py")

    def test_long_path(self):
        result = truncate_path("/very/long/path/to/some/deeply/nested/file.py")
        self.assertTrue(result.startswith("..."))
        self.assertEqual(len(result), 40)


class TestFormatElapsed(unittest.TestCase):

    def test_seconds(self):
        self.assertEqual(format_elapsed(45), "45s")

    def test_minutes(self):
        self.assertEqual(format_elapsed(125), "2m 5s")

    def test_hours(self):
        self.assertEqual(format_elapsed(3725), "1h 2m")


if __name__ == "__main__":
    unittest.main()
