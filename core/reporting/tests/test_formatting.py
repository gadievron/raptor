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

    def test_true_positive_with_ruled_out_ruling_renders_ruled_out(self):
        # A real bug whose Stage-D security ruling rules it out (D-4
        # no security impact, D-2 unreachable) must not render as
        # Confirmed — the ruling decides the display status.
        self.assertEqual(get_display_status({
            "is_true_positive": True,
            "ruling": {"status": "ruled_out", "disqualifier": "D-4",
                       "reason": "real bug, no security impact"},
        }), "Ruled Out")

    def test_true_positive_with_blocked_final_status(self):
        self.assertEqual(get_display_status({
            "is_true_positive": True,
            "is_exploitable": False,
            "final_status": "confirmed_blocked",
        }), "Confirmed (Blocked)")

    def test_true_positive_with_confirmed_ruling_stays_confirmed(self):
        self.assertEqual(get_display_status({
            "is_true_positive": True,
            "ruling": {"status": "confirmed"},
        }), "Confirmed")

    def test_true_positive_provenance_dict_ruling_keeps_boolean(self):
        # The agentic→validate bridge wraps string rulings into dicts;
        # a provenance status (test_code / dead_code / validated) is
        # not a security ruling and still defers to the boolean
        # verdict fields.
        self.assertEqual(get_display_status({
            "is_true_positive": True,
            "ruling": {"status": "test_code",
                       "agentic_ruling": "test_code"},
        }), "Confirmed")

    def test_false_positive_boolean_still_wins_over_ruling(self):
        self.assertEqual(get_display_status({
            "is_true_positive": False,
            "ruling": {"status": "confirmed"},
        }), "False Positive")

    def test_true_positive_with_top_level_disproven_renders_ruled_out(self):
        # IRIS Tier-1 refutation sets top-level status only (no ruling
        # object); an agentic-imported is_true_positive=True must not
        # override the refutation.
        self.assertEqual(get_display_status({
            "is_true_positive": True,
            "status": "disproven",
        }), "Ruled Out")

    def test_true_positive_with_disproven_dict_ruling_renders_ruled_out(self):
        self.assertEqual(get_display_status({
            "is_true_positive": True,
            "ruling": {"status": "disproven"},
        }), "Ruled Out")


class TestRuledOutUnverifiedDisplay(unittest.TestCase):
    """ruled_out_unverified is the quarantine tier for rule-outs that
    carry no mechanical refutation receipt. The title-case fallback
    would render it "Ruled Out Unverified", which the counting code's
    exact "Ruled Out" match misses — it needs the same explicit
    parenthesised treatment as confirmed_unverified."""

    def test_ruling_status_renders_parenthesised(self):
        self.assertEqual(get_display_status({
            "ruling": {"status": "ruled_out_unverified",
                       "disqualifier": "D-2"},
        }), "Ruled Out (Unverified)")

    def test_top_level_status_renders_parenthesised(self):
        self.assertEqual(get_display_status(
            {"status": "ruled_out_unverified"}), "Ruled Out (Unverified)")

    def test_final_status_renders_parenthesised(self):
        self.assertEqual(get_display_status(
            {"final_status": "ruled_out_unverified"}), "Ruled Out (Unverified)")

    def test_outranks_bare_true_positive_boolean(self):
        # Same doctrine as ruled_out: a security ruling (even the
        # unverified tier) decides display over the bare
        # is_true_positive stand-in.
        self.assertEqual(get_display_status({
            "is_true_positive": True,
            "ruling": {"status": "ruled_out_unverified"},
        }), "Ruled Out (Unverified)")


class TestDisplayVocabularyClosure(unittest.TestCase):
    """The title-case fallback for unknown statuses is an open channel
    into the counting vocabulary: "EXPLOITABLE" misses every exact
    status_map key, title-cases to "Exploitable", and counts as a full
    exploitable verdict without any pipeline stage having issued one.
    Unknown statuses may still render as prose, but never as (or
    prefixed by) verdict vocabulary."""

    def test_all_caps_status_never_renders_exploitable(self):
        self.assertEqual(get_display_status({"status": "EXPLOITABLE"}),
                         "Unknown")

    def test_all_caps_final_status_never_renders_exploitable(self):
        self.assertEqual(
            get_display_status({"final_status": "EXPLOITABLE"}), "Unknown")

    def test_title_case_ruling_never_renders_ruled_out(self):
        self.assertEqual(get_display_status(
            {"ruling": {"status": "Ruled Out"}}), "Unknown")

    def test_confirmed_prefix_never_counts(self):
        # build_findings_summary buckets startswith("Confirmed") into
        # confirmed_unrestricted — the fallback must not mint that
        # prefix from an unknown status.
        self.assertEqual(get_display_status({"status": "confirmed maybe"}),
                         "Unknown")

    def test_error_prefix_never_counts(self):
        self.assertEqual(get_display_status({"status": "error_ish"}),
                         "Unknown")

    def test_disproven_variant_never_renders(self):
        self.assertEqual(get_display_status({"status": "DISPROVEN"}),
                         "Unknown")

    def test_non_verdict_unknown_status_still_renders(self):
        # The open fallback stays open for genuinely new NON-verdict
        # statuses — producers aren't blocked on a table update.
        self.assertEqual(get_display_status({"status": "pending"}),
                         "Pending")
        self.assertEqual(get_display_status({"status": "needs_rebuild"}),
                         "Needs Rebuild")


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

    def test_zero_width_flood_bounded(self):
        # Combining marks report zero display width, so the
        # width-based walk alone kept a flooded path essentially
        # whole (thousands of code points into a 40-column slot).
        # The code-point ceiling must cut it.
        flooded = "src/" + "à" + "̀" * 5000 + ".c"
        result = truncate_path(flooded, max_len=40)
        self.assertLessEqual(len(result), 4 * 40 + 8 + 3)

    def test_non_ascii_within_budget_unchanged(self):
        # Keep-direction: ordinary non-ASCII paths under both the
        # display-width and code-point budgets pass through whole.
        path = "src/héllo/wörld.c"
        self.assertEqual(truncate_path(path, max_len=40), path)


class TestFormatElapsed(unittest.TestCase):

    def test_seconds(self):
        self.assertEqual(format_elapsed(45), "45s")

    def test_minutes(self):
        self.assertEqual(format_elapsed(125), "2m 5s")

    def test_hours(self):
        self.assertEqual(format_elapsed(3725), "1h 2m")


if __name__ == "__main__":
    unittest.main()
