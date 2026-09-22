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

    def test_php_semgrep_families_silence_stays_dark(self):
        """Every PHP web-audit family (dispatch entries in
        cwe_dispatch) is deliberately unmapped: each rule adjudicates
        a narrow sub-shape (socket writes but not header()/mail()
        response splitting; membership checks with invisible
        haystack/polarity; the attribute-encoding residual;
        name-anchored PRNG stores), so a silent rule must classify
        the class dark — never clean. Pinned on the explicit
        cwe_field path, which is mechanism-independent: a mapped row
        here would grant clean-when-silent to every hypothesis the
        review tags with the class, not just the shapes the rule can
        see."""
        for cwe in ("CWE-93", "CWE-470", "CWE-88", "CWE-116",
                    "CWE-327", "CWE-338"):
            covered = is_class_covered(
                cwe, "", "", self.ALL_TOOLS, ran_tools={"semgrep"},
            )
            # CWE-88/327 rows PRE-EXIST this series (see the
            # companion test below); the four rows this series could
            # have added stay out.
            if cwe in ("CWE-88", "CWE-327"):
                assert covered is True
            else:
                assert covered is False

    def test_preexisting_88_327_rows_now_systematically_armed(self):
        """DOCUMENTED consequence, not a change: CWE-88 and CWE-327
        carried semgrep rows before this series, but no PHP semgrep
        leg ever dispatched for them — the rows were dormant. The
        cwe_dispatch entries make semgrep receipts systematic on PHP
        targets, so silence in these two classes now resolves
        clean-when-silent through the pre-existing rows despite both
        rules having narrow-shape gaps (helper-indirection taint for
        CWE-88; neutral-name digests and non-digest weak-crypto
        hypotheses for CWE-327). Accepted for this series; the
        rule-granular receipt design (see _CWE_TOOL_MAP comment) is
        the path to closing it."""
        for cwe in ("CWE-88", "CWE-327"):
            assert is_class_covered(
                cwe, "", "", self.ALL_TOOLS, ran_tools={"semgrep"},
            ) is True
            assert is_class_covered(cwe, "", "", self.ALL_TOOLS) is False

    def test_php_family_mechanisms_name_but_never_cover(self):
        """Mechanism keywords for the unmapped families are
        naming-only (the CWE-480/481 pattern): the class appears in
        coverage records but never resolves clean-when-silent. No
        crlf/header-injection keyword at all — response splitting is
        canonically tagged CWE-93 and must not even be named as
        semgrep territory."""
        from core.audit.tool_coverage import _extract_cwes

        assert _extract_cwes(
            "", mechanism="crlf injection into the smtp stream",
        ) == []
        assert _extract_cwes(
            "", mechanism="header injection via Location value",
        ) == []
        for mech in ("unsafe reflection over request parameter",
                     "variable function call on user input"):
            assert "CWE-470" in _extract_cwes("", mechanism=mech)
            assert is_class_covered(
                "", mech, "", self.ALL_TOOLS, ran_tools={"semgrep"},
            ) is False

    def test_sarif_cache_alias_never_covers_unmapped_families(self):
        """Gate resolution adds "sarif_cache" to the ran set for any
        file with prior semgrep findings, and the alias normalizes it
        to "semgrep" — with a CWE-93/470 row that would have resolved
        a C-file suspicious clean off an unrelated prior finding.
        Unmapped families are immune to the alias by construction."""
        for cwe in ("CWE-93", "CWE-470", "CWE-116", "CWE-338"):
            assert is_class_covered(
                cwe, "", "", self.ALL_TOOLS, ran_tools={"sarif_cache"},
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

    def test_operator_confusion_classes_stay_dark(self):
        """CWE-480/481 have mechanism-map emissions but deliberately no
        _CWE_TOOL_MAP entry — no mechanical channel detects operator
        confusion, so silence must read dark, never clean."""
        from core.audit.tool_coverage import _CWE_TOOL_MAP, _extract_cwes
        cwes = _extract_cwes("", "assignment in conditional", "")
        assert "CWE-480" in cwes
        assert "CWE-480" not in _CWE_TOOL_MAP
        assert "CWE-481" not in _CWE_TOOL_MAP
        covered = is_class_covered(
            "", "assignment in conditional", "",
            {"semgrep": True, "codeql": True},
            ran_tools={"semgrep", "codeql"},
        )
        assert covered is False
