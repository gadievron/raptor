"""Tests for strategy-exemplar coverage.

The exemplar table was kernel-C-heavy: no ``integer`` key despite
STRATEGY_INTEGER existing, and no web/injection exemplars at all —
web-heavy targets reviewed with kernel-UAF reasoning traces. These
tests pin: every declared strategy has at least one exemplar, the
integer and web/injection families are covered, exemplars keep the
house format, and the cache-stable pattern library renders them
deterministically.
"""

from __future__ import annotations

from core.audit.context import (
    _STRATEGY_EXEMPLARS,
    _load_strategy_exemplars,
    render_pattern_library,
)
from core.audit.strategy import ALL_STRATEGIES


class TestExemplarCoverage:
    def test_every_strategy_has_exemplars(self):
        """No declared strategy may review without a worked exemplar."""
        missing = set(ALL_STRATEGIES) - set(_STRATEGY_EXEMPLARS)
        assert not missing, f"strategies without exemplars: {sorted(missing)}"

    def test_integer_strategy_covered(self):
        exemplars = _load_strategy_exemplars(frozenset({"integer"}))
        cves = {e["cve"] for e in exemplars}
        assert "CVE-2021-33909" in cves  # size_t→int truncation
        assert "CVE-2022-23772" in cves  # unchecked parsed-value arithmetic
        assert all(e["strategy"] == "integer" for e in exemplars)

    def test_web_injection_families_covered(self):
        """SQLi, XSS, SSRF, path traversal, and command injection all
        have an exemplar under the input_handling strategy."""
        cves = {e["cve"] for e in _STRATEGY_EXEMPLARS["input_handling"]}
        assert "CVE-2020-12271" in cves   # SQL injection
        assert "CVE-2020-11022" in cves   # XSS
        assert "CVE-2021-26855" in cves   # SSRF
        assert "CVE-2021-41773" in cves   # path traversal
        assert "CVE-2014-6271" in cves    # command injection

    def test_selection_dedupes_across_strategies(self):
        exemplars = _load_strategy_exemplars(
            frozenset({"integer", "input_handling", "general"}),
        )
        cves = [e["cve"] for e in exemplars]
        assert len(cves) == len(set(cves))


class TestExemplarHouseStyle:
    def test_format_keys_and_conciseness(self):
        for strategy, entries in _STRATEGY_EXEMPLARS.items():
            assert entries, f"empty exemplar list for {strategy}"
            for e in entries:
                assert set(e) == {"cve", "title", "reasoning"}, (
                    f"{strategy}/{e.get('cve')} breaks the exemplar shape"
                )
                assert e["cve"].strip() and e["title"].strip()
                # pattern-focused, not essays — protect the token budget
                assert 50 <= len(e["reasoning"]) <= 700, (
                    f"{strategy}/{e['cve']} reasoning length "
                    f"{len(e['reasoning'])} outside house style"
                )

    def test_reasoning_names_the_violated_assumption(self):
        """House style: exemplars teach which assumption fails."""
        for e in (_STRATEGY_EXEMPLARS["integer"]
                  + _STRATEGY_EXEMPLARS["input_handling"][1:]):
            assert "ssumption" in e["reasoning"] or "diverge" in e["reasoning"], (
                f"{e['cve']} reasoning must name the violated assumption"
            )


class TestPatternLibraryRendering:
    def test_new_exemplars_render(self):
        text = render_pattern_library()
        assert "CVE-2021-33909" in text
        assert "CVE-2021-41773" in text
        assert "(integer)" in text
        assert "(input_handling)" in text

    def test_rendering_is_deterministic(self):
        """The library lives in the cache-stable system prompt — the
        text must be byte-identical across calls."""
        assert render_pattern_library() == render_pattern_library()
