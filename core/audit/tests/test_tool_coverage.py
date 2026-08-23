"""Tests for core.audit.tool_coverage — vulnerability class coverage map."""

from __future__ import annotations

from typing import ClassVar

from core.audit.tool_coverage import _extract_cwes, is_class_covered


class TestExtractCwes:
    def test_explicit_cwe(self):
        assert _extract_cwes("CWE-79") == ["CWE-79"]

    def test_multiple_cwes(self):
        assert _extract_cwes("CWE-79, CWE-89") == ["CWE-79", "CWE-89"]

    def test_cwe_case_insensitive(self):
        assert _extract_cwes("cwe-78") == ["CWE-78"]

    def test_mechanism_keyword(self):
        cwes = _extract_cwes("", mechanism="buffer overflow")
        assert "CWE-120" in cwes

    def test_hypothesis_keyword(self):
        cwes = _extract_cwes("", hypothesis="sql injection via user input")
        assert "CWE-89" in cwes

    def test_combined_sources(self):
        cwes = _extract_cwes("CWE-78", mechanism="command injection")
        assert "CWE-78" in cwes
        assert len([c for c in cwes if c == "CWE-78"]) == 1  # deduped

    def test_no_match(self):
        assert _extract_cwes("", mechanism="logic error") == []

    def test_empty_inputs(self):
        assert _extract_cwes("") == []

    def test_mechanism_use_after_free_variants(self):
        assert "CWE-416" in _extract_cwes("", mechanism="use after free")
        assert "CWE-416" in _extract_cwes("", mechanism="use-after-free")

    def test_mechanism_codeql_injection(self):
        assert "CWE-94" in _extract_cwes("", mechanism="CodeQL injection via proposed_guard")

    def test_mechanism_race_condition_is_cwe_362(self):
        """Generic races are CWE-362 (lock races), not CWE-367 (TOCTOU).

        The prefilter's TOCTOU check only detects stat/access-then-open
        patterns; mapping generic races to CWE-367 marked every race
        hypothesis tool-covered via the always-on prefilter.
        """
        cwes = _extract_cwes("", mechanism="race condition on shared counter")
        assert "CWE-362" in cwes
        assert "CWE-367" not in cwes

    def test_mechanism_toctou_is_cwe_367(self):
        assert _extract_cwes("", mechanism="toctou between stat and open") == ["CWE-367"]


class TestNormalizeRanChannels:
    def test_chain_step_types_pass_through(self):
        from core.audit.tool_coverage import normalize_ran_channels
        assert normalize_ran_channels({"semgrep", "smt"}) == {"semgrep", "smt"}

    def test_sub_channels_alias_to_parent_tool(self):
        from core.audit.tool_coverage import normalize_ran_channels
        assert normalize_ran_channels(
            {"joern_guard", "joern_flow", "cross_function", "coccinelle_flow"},
        ) == {"joern", "coccinelle"}

    def test_namespaced_receipts_reduce_to_tool(self):
        from core.audit.tool_coverage import normalize_ran_channels
        assert normalize_ran_channels(
            {"semgrep:rule-123", "sarif_cache:semgrep"},
        ) == {"semgrep"}

    def test_empty_and_none(self):
        from core.audit.tool_coverage import normalize_ran_channels
        assert normalize_ran_channels(None) == set()
        assert normalize_ran_channels(set()) == set()


class TestIsClassCovered:
    """Covered means a mapped channel actually RAN for the function —
    an installed-but-never-dispatched tool is NOT coverage."""

    ALL_TOOLS: ClassVar[dict[str, bool]] = {
        "joern": True, "codeql": True, "semgrep": True,
        "coccinelle": True, "smt": True,
    }
    NO_TOOLS: ClassVar[dict[str, bool]] = {
        "joern": False, "codeql": False, "semgrep": False,
        "coccinelle": False, "smt": False,
    }

    def test_installed_but_never_ran_is_not_covered(self):
        """The load-bearing fix: all tools live, none dispatched → dark."""
        assert is_class_covered("CWE-78", "", "", self.ALL_TOOLS) is False

    def test_covered_when_mapped_tool_ran(self):
        assert is_class_covered(
            "CWE-78", "", "", self.ALL_TOOLS, ran_tools={"semgrep"},
        ) is True

    def test_not_covered_when_only_unmapped_tool_ran(self):
        """CWE-476 maps to codeql+coccinelle — an SMT run is not coverage."""
        assert is_class_covered(
            "CWE-476", "", "", self.ALL_TOOLS, ran_tools={"smt"},
        ) is False

    def test_prefilter_probe_alone_is_not_coverage(self):
        """The old code injected prefilter as always-live; only an
        explicit prefilter entry in the dispatch record counts."""
        assert is_class_covered("CWE-22", "", "", self.ALL_TOOLS) is False
        assert is_class_covered(
            "CWE-22", "", "", self.ALL_TOOLS, ran_tools={"prefilter"},
        ) is True

    def test_uncovered_unknown_cwe(self):
        """Unknown CWE → not in map → conservative dark."""
        assert is_class_covered(
            "CWE-99999", "", "", self.ALL_TOOLS, ran_tools={"semgrep"},
        ) is False

    def test_uncovered_no_cwe_extracted(self):
        """No CWE extractable → conservative dark."""
        assert is_class_covered(
            "", "logic error", "", self.ALL_TOOLS, ran_tools={"semgrep"},
        ) is False

    def test_covered_via_mechanism(self):
        assert is_class_covered(
            "", "sql injection", "", self.ALL_TOOLS, ran_tools={"semgrep"},
        ) is True

    def test_covered_via_hypothesis(self):
        assert is_class_covered(
            "", "", "path traversal via user input", self.ALL_TOOLS,
            ran_tools={"semgrep"},
        ) is True

    def test_unavailable_tool_discarded_from_ran_record(self):
        """A stale dispatch record can't claim coverage for a dead tool."""
        tools = {"joern": True, "codeql": False, "semgrep": True,
                 "coccinelle": False}
        assert is_class_covered(
            "CWE-476", "", "", tools, ran_tools={"codeql", "coccinelle"},
        ) is False

    def test_covered_partial_tools(self):
        """CWE-89 maps to prefilter+semgrep+codeql+joern; semgrep ran."""
        tools = {"joern": False, "codeql": False, "semgrep": True,
                 "coccinelle": False}
        assert is_class_covered(
            "CWE-89", "", "", tools, ran_tools={"semgrep"},
        ) is True

    def test_joern_sub_channel_counts_as_joern(self):
        assert is_class_covered(
            "CWE-89", "", "", self.ALL_TOOLS, ran_tools={"joern_flow"},
        ) is True

    def test_sarif_hit_counts_as_semgrep(self):
        assert is_class_covered(
            "CWE-89", "", "", self.ALL_TOOLS, ran_tools={"sarif_cache"},
        ) is True

    def test_race_mechanism_dark_when_coccinelle_never_ran(self):
        """Lock races (CWE-362) are coccinelle-only — dark unless it ran."""
        assert is_class_covered(
            "", "race condition on shared counter", "", self.NO_TOOLS,
        ) is False
        assert is_class_covered(
            "", "race condition on shared counter", "",
            {"coccinelle": True},
        ) is False

    def test_race_mechanism_covered_when_coccinelle_ran(self):
        assert is_class_covered(
            "", "race condition on shared counter", "",
            {"coccinelle": True}, ran_tools={"coccinelle"},
        ) is True

    def test_ssrf_needs_semgrep_or_codeql_run(self):
        tools = {"joern": True, "codeql": False, "semgrep": False,
                 "coccinelle": True}
        assert is_class_covered(
            "CWE-918", "", "", tools, ran_tools={"joern", "coccinelle"},
        ) is False


class TestGateResolutionIntegration:
    """Test the three-way resolution logic end to end."""

    def test_covered_class_resolves_clean(self):
        """SQL injection + semgrep ran silent + no corroboration → clean."""
        covered = is_class_covered(
            "CWE-89", "", "", {"semgrep": True}, ran_tools={"semgrep"},
        )
        assert covered is True  # → would resolve to clean

    def test_never_ran_resolves_dark(self):
        """SQL injection + semgrep installed but never dispatched → dark."""
        covered = is_class_covered("CWE-89", "", "", {"semgrep": True})
        assert covered is False  # → would resolve to dark

    def test_errored_channel_resolves_dark(self):
        """The caller subtracts errored channels from the ran record —
        a Joern timeout must not convert into a clean verdict."""
        ran = {"joern"} - {"joern"}  # dispatched, then errored
        covered = is_class_covered(
            "CWE-89", "", "", {"joern": True}, ran_tools=ran,
        )
        assert covered is False  # → would resolve to dark

    def test_uncovered_class_resolves_dark(self):
        """Logic error (no CWE mapping) + no corroboration → dark."""
        covered = is_class_covered(
            "", "logic error", "", {"semgrep": True}, ran_tools={"semgrep"},
        )
        assert covered is False  # → would resolve to dark

    def test_incomplete_map_conservative(self):
        """CWE not in map → False → dark. Fails safe."""
        covered = is_class_covered(
            "CWE-1234", "", "", {"semgrep": True}, ran_tools={"semgrep"},
        )
        assert covered is False
