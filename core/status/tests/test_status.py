"""Tests for core.status — status/verdict string normalisation."""
from __future__ import annotations

from core.status import normalize_findings, normalize_status


class TestNormalizeStatusAllCapsLegacy:
    """ALL_CAPS legacy values (pre-cleanup orchestrator, LLM skill output)."""

    def test_exploitable(self) -> None:
        assert normalize_status("EXPLOITABLE") == "exploitable"

    def test_confirmed(self) -> None:
        assert normalize_status("CONFIRMED") == "confirmed"

    def test_confirmed_constrained(self) -> None:
        assert normalize_status("CONFIRMED_CONSTRAINED") == "confirmed_constrained"

    def test_ruled_out(self) -> None:
        assert normalize_status("RULED_OUT") == "ruled_out"

    def test_not_exploitable_aliases_to_unlikely(self) -> None:
        # NOT_EXPLOITABLE is a legacy verdict that maps to "unlikely" —
        # consumers downstream should treat the two as equivalent.
        assert normalize_status("NOT_EXPLOITABLE") == "unlikely"


class TestNormalizeStatusTitleCaseLegacy:
    """Title-case legacy values (old feasibility verdicts, LLM output)."""

    def test_exploitable(self) -> None:
        assert normalize_status("Exploitable") == "exploitable"

    def test_ruled_out_with_space(self) -> None:
        assert normalize_status("Ruled Out") == "ruled_out"

    def test_likely_exploitable_with_space(self) -> None:
        assert normalize_status("Likely exploitable") == "likely_exploitable"

    def test_bare_likely_aliases_to_likely_exploitable(self) -> None:
        # "Likely" without "exploitable" suffix maps to the same canonical
        # form — old feasibility output emitted it as a short verdict.
        assert normalize_status("Likely") == "likely_exploitable"

    def test_not_disproven_with_space(self) -> None:
        assert normalize_status("Not disproven") == "not_disproven"


class TestNormalizeStatusPassthrough:
    """Already-canonical snake_case values pass through unchanged."""

    def test_exploitable(self) -> None:
        assert normalize_status("exploitable") == "exploitable"

    def test_confirmed_unverified(self) -> None:
        assert normalize_status("confirmed_unverified") == "confirmed_unverified"

    def test_unknown(self) -> None:
        assert normalize_status("unknown") == "unknown"


class TestNormalizeStatusFallback:
    """Unknown values fall through lowercase + space/hyphen → underscore."""

    def test_unknown_value_lowercased(self) -> None:
        assert normalize_status("CustomStatus") == "customstatus"

    def test_unknown_value_with_spaces(self) -> None:
        assert normalize_status("some new status") == "some_new_status"

    def test_unknown_value_with_hyphens(self) -> None:
        assert normalize_status("some-new-status") == "some_new_status"

    def test_unknown_value_with_mixed_separators(self) -> None:
        assert normalize_status("Some New-Status") == "some_new_status"


class TestNormalizeStatusEdgeCases:
    def test_none_returns_none(self) -> None:
        assert normalize_status(None) is None

    def test_empty_string_returns_empty(self) -> None:
        # Falsy values short-circuit before strip — preserves the empty
        # string so callers can distinguish "" from None if they care.
        assert normalize_status("") == ""

    def test_whitespace_only_returns_none(self) -> None:
        assert normalize_status("   ") is None

    def test_leading_trailing_whitespace_stripped(self) -> None:
        assert normalize_status("  EXPLOITABLE  ") == "exploitable"

    def test_non_string_coerced(self) -> None:
        # Non-string inputs are str()-coerced then normalised; the
        # contract exists so producers don't silently drop ints/enums.
        assert normalize_status(42) == "42"


class TestNormalizeFindings:
    def test_top_level_status(self) -> None:
        data = {"findings": [{"status": "EXPLOITABLE"}]}
        normalize_findings(data)
        assert data["findings"][0]["status"] == "exploitable"

    def test_top_level_final_status(self) -> None:
        data = {"findings": [{"final_status": "RULED_OUT"}]}
        normalize_findings(data)
        assert data["findings"][0]["final_status"] == "ruled_out"

    def test_nested_ruling_status(self) -> None:
        data = {"findings": [{"ruling": {"status": "CONFIRMED"}}]}
        normalize_findings(data)
        assert data["findings"][0]["ruling"]["status"] == "confirmed"

    def test_nested_feasibility_verdict(self) -> None:
        data = {"findings": [{"feasibility": {"verdict": "Likely exploitable"}}]}
        normalize_findings(data)
        assert data["findings"][0]["feasibility"]["verdict"] == "likely_exploitable"

    def test_nested_feasibility_status(self) -> None:
        data = {"findings": [{"feasibility": {"status": "Difficult"}}]}
        normalize_findings(data)
        assert data["findings"][0]["feasibility"]["status"] == "difficult"

    def test_all_fields_in_one_finding(self) -> None:
        data = {
            "findings": [
                {
                    "status": "EXPLOITABLE",
                    "final_status": "Confirmed",
                    "ruling": {"status": "CONFIRMED_CONSTRAINED"},
                    "feasibility": {
                        "verdict": "Likely",
                        "status": "Difficult",
                    },
                }
            ]
        }
        normalize_findings(data)
        f = data["findings"][0]
        assert f["status"] == "exploitable"
        assert f["final_status"] == "confirmed"
        assert f["ruling"]["status"] == "confirmed_constrained"
        assert f["feasibility"]["verdict"] == "likely_exploitable"
        assert f["feasibility"]["status"] == "difficult"

    def test_non_dict_findings_entry_skipped(self) -> None:
        # Defensive: malformed input where a finding is a string/None/etc.
        # should not raise — normalize_findings has to be safe to call on
        # whatever upstream producers emit.
        data = {"findings": ["not a dict", None, {"status": "EXPLOITABLE"}]}
        normalize_findings(data)
        assert data["findings"][2]["status"] == "exploitable"

    def test_missing_findings_key_noop(self) -> None:
        data: dict = {}
        normalize_findings(data)
        assert data == {}

    def test_empty_findings_list_noop(self) -> None:
        data: dict = {"findings": []}
        normalize_findings(data)
        assert data == {"findings": []}

    def test_finding_without_any_status_field_untouched(self) -> None:
        data = {"findings": [{"title": "foo", "cwe": "CWE-79"}]}
        normalize_findings(data)
        assert data["findings"][0] == {"title": "foo", "cwe": "CWE-79"}
