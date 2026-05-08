"""Tests for ``render_strategy`` / ``render_strategies``.

Pure-text rendering — no LLM dependency. Adversarial coverage
focuses on the truncation cascade (drop exemplars → drop questions
→ drop strategies) and on edge cases (empty fields, oversized
content, content that looks like markdown injection).
"""

from __future__ import annotations

import pytest

from core.llm.cwe_strategies import (
    DEFAULT_MAX_BYTES,
    Exemplar,
    Signals,
    Strategy,
    load_all,
    pick_strategies,
    render_strategies,
    render_strategy,
)


def _ex(cve, title="t", pattern="p", why_buggy="w"):
    return Exemplar(cve=cve, title=title, pattern=pattern, why_buggy=why_buggy)


def _strat(name, *, desc="d", questions=("q?",), addendum="a", exemplars=()):
    return Strategy(
        name=name,
        description=desc,
        signals=Signals(),
        key_questions=tuple(questions),
        prompt_addendum=addendum,
        exemplars=tuple(exemplars),
    )


# ---------------------------------------------------------------------------
# render_strategy — single strategy
# ---------------------------------------------------------------------------


class TestRenderStrategy:
    def test_full_render_includes_all_sections(self):
        s = _strat(
            "input_handling",
            desc="Parsers and protocol handlers",
            questions=("What does this trust?", "Are lengths checked?"),
            addendum="Treat every byte as adversary-controlled.",
            exemplars=[_ex("CVE-2023-0179", title="nftables")],
        )
        out = render_strategy(s)
        assert "## Strategy: input_handling" in out
        assert "Parsers and protocol handlers" in out
        assert "### Key questions" in out
        assert "- What does this trust?" in out
        assert "### Approach" in out
        assert "adversary-controlled" in out
        assert "### Worked examples" in out
        assert "CVE-2023-0179" in out

    def test_minimal_strategy_renders_header_and_desc_only(self):
        s = Strategy(name="x", description="just a description")
        out = render_strategy(s)
        assert "## Strategy: x" in out
        assert "just a description" in out
        # No empty section headers.
        assert "### Key questions" not in out
        assert "### Approach" not in out
        assert "### Worked examples" not in out

    def test_skip_exemplars_flag(self):
        s = _strat("x", exemplars=[_ex("CVE-1")])
        out = render_strategy(s, include_exemplars=False)
        assert "### Worked examples" not in out
        assert "CVE-1" not in out

    def test_skip_questions_flag(self):
        s = _strat("x", questions=("q1?", "q2?"))
        out = render_strategy(s, include_questions=False)
        assert "### Key questions" not in out
        assert "q1?" not in out

    def test_multiline_description_preserved(self):
        s = Strategy(
            name="x",
            description="line one\nline two\nline three",
        )
        out = render_strategy(s)
        assert "line one" in out
        assert "line two" in out
        assert "line three" in out

    def test_multiple_exemplars_each_appear(self):
        s = _strat("x", exemplars=[
            _ex("CVE-1", title="first"),
            _ex("CVE-2", title="second"),
        ])
        out = render_strategy(s)
        assert "CVE-1" in out
        assert "CVE-2" in out
        assert "first" in out
        assert "second" in out


# ---------------------------------------------------------------------------
# render_strategies — multiple strategies + truncation cascade
# ---------------------------------------------------------------------------


class TestRenderStrategiesBasic:
    def test_empty_returns_empty(self):
        assert render_strategies([]) == ""

    def test_single_strategy(self):
        out = render_strategies([_strat("x")])
        assert "## Strategy: x" in out

    def test_multiple_strategies_in_order(self):
        out = render_strategies([_strat("a"), _strat("b"), _strat("c")])
        a_pos = out.index("## Strategy: a")
        b_pos = out.index("## Strategy: b")
        c_pos = out.index("## Strategy: c")
        assert a_pos < b_pos < c_pos


class TestTruncationCascade:
    def _big_strat(self, name, exemplar_text_size=500):
        # Exemplars are the easiest signal to inflate.
        # exemplar_text_size=500 → exemplar ~2KB, strategy ~2.5KB,
        # strategy-without-exemplar ~0.5KB. Pick budgets in tests to
        # fall between these landmarks to exercise the cascade tiers.
        big = "x " * exemplar_text_size
        return _strat(
            name,
            questions=("q?",),
            addendum="addendum",
            exemplars=[_ex(f"CVE-{name}-1", title="t",
                           pattern=big, why_buggy=big)],
        )

    def test_no_cap_no_truncation(self):
        s = [self._big_strat("a"), self._big_strat("b")]
        out = render_strategies(s, max_bytes=None)
        assert "truncated" not in out
        assert "CVE-a-1" in out
        assert "CVE-b-1" in out

    def test_within_budget_no_truncation_marker(self):
        s = [_strat("a"), _strat("b")]  # tiny strategies
        out = render_strategies(s, max_bytes=DEFAULT_MAX_BYTES)
        assert "truncated" not in out

    def test_drops_later_strategy_exemplars_first(self):
        """Tier 1 of the cascade: keep early strategies' exemplars,
        drop late ones'.

        Sizes: each exemplar ~2KB, strategy with exemplar ~2.5KB,
        strategy without ~0.5KB. Budget 4000: full (5KB) fails,
        a-keeps-b-drops (~3KB) fits.
        """
        s = [self._big_strat("a"), self._big_strat("b")]
        out = render_strategies(s, max_bytes=4_000)
        assert "truncated" in out
        # a's exemplar should survive.
        assert "CVE-a-1" in out
        # b's exemplar dropped.
        assert "CVE-b-1" not in out
        # b's structure still present.
        assert "## Strategy: b" in out

    def test_drops_all_exemplars_when_too_tight(self):
        s = [self._big_strat("a"), self._big_strat("b")]
        # Budget 1500: even a-only-keeps-exemplar (~2.5KB) doesn't
        # fit; cascade drops both.
        out = render_strategies(s, max_bytes=1_500)
        assert "truncated" in out
        # Exemplars are gone.
        assert "CVE-a-1" not in out
        assert "CVE-b-1" not in out

    def test_drops_questions_after_exemplars(self):
        # All exemplars dropped; if still too big, drop questions.
        big_q = "q? " * 1000
        s = [
            _strat("a", questions=(big_q, big_q),
                   exemplars=[_ex("CVE-a-1", pattern="p", why_buggy="w")]),
            _strat("b", questions=(big_q, big_q),
                   exemplars=[_ex("CVE-b-1", pattern="p", why_buggy="w")]),
        ]
        out = render_strategies(s, max_bytes=2_500)
        # Exemplars gone, last strategy's questions also gone.
        assert "CVE-a-1" not in out
        assert "CVE-b-1" not in out
        assert "truncated" in out

    def test_drops_strategies_when_too_tight(self):
        """Tier 3: drop later strategies entirely when even
        without exemplars/questions the budget is exceeded."""
        big_addendum = "x " * 5_000
        s = [
            _strat("a", addendum=big_addendum),
            _strat("b", addendum=big_addendum),
            _strat("c", addendum=big_addendum),
        ]
        out = render_strategies(s, max_bytes=12_000)
        # 'a' should survive; later ones may be dropped.
        assert "## Strategy: a" in out
        assert "truncated" in out

    def test_extreme_tight_budget_returns_first_only(self):
        big_desc = "x " * 5_000
        s = [
            _strat("a", desc=big_desc, addendum=big_desc),
            _strat("b", desc=big_desc, addendum=big_desc),
        ]
        out = render_strategies(s, max_bytes=200)
        # Only 'a' header + truncated description fits.
        assert "## Strategy: a" in out
        assert "## Strategy: b" not in out
        assert "truncated" in out


# ---------------------------------------------------------------------------
# Adversarial — content that could confuse the rendered prompt
# ---------------------------------------------------------------------------


class TestAdversarialContent:
    def test_strategy_name_with_markdown(self):
        """Strategy name showing up in a `## Strategy: <name>`
        heading. If the name contains ``##`` or `\n`, it could
        forge fake sections. Pin the current behaviour: rendered
        verbatim. Caller responsibility — strategies are
        operator-curated."""
        s = _strat("evil\n## Forged: heading")
        out = render_strategy(s)
        # We don't escape — but the test pins what we DO produce
        # so a future hardening change is visible.
        assert "## Strategy: evil" in out

    def test_empty_strategy_doesnt_crash(self):
        s = Strategy(name="x", description="")
        out = render_strategy(s)
        # Just the heading, nothing else.
        assert "## Strategy: x" in out

    def test_unicode_content_preserved(self):
        s = _strat(
            "ünïcødé",
            desc="émüläted",
            exemplars=[_ex("CVE-1", title="日本語タイトル",
                           pattern="código", why_buggy="τι")],
        )
        out = render_strategy(s)
        assert "ünïcødé" in out
        assert "日本語タイトル" in out
        assert "código" in out

    def test_huge_single_strategy(self):
        """One strategy that on its own exceeds the budget. Renderer
        falls all the way through to the 'first only, no frills'
        last resort, no crash."""
        big = "x" * 50_000
        s = [_strat("a", desc=big, addendum=big,
                     exemplars=[_ex("CVE-1", pattern=big, why_buggy=big)])]
        out = render_strategies(s, max_bytes=1_000)
        assert "truncated" in out


# ---------------------------------------------------------------------------
# E2E with bundled strategies
# ---------------------------------------------------------------------------


class TestE2EBundledStrategies:
    def test_full_audit_driver_render(self):
        """Realistic /audit Phase A scenario: pick strategies for a
        function, render them. Verify the rendered prompt is
        well-formed and contains the expected strategy content."""
        picked = pick_strategies(
            file_path="net/foo/parser.c",
            function_name="parse_request",
            file_includes=["linux/skbuff.h", "linux/spinlock.h"],
            function_calls_made=["spin_lock", "skb_pull"],
            candidate_cwes=["CWE-119"],
            max_strategies=4,
        )
        assert len(picked) >= 3
        out = render_strategies(picked)

        # Every picked strategy's name appears as a section heading.
        for s in picked:
            assert f"## Strategy: {s.name}" in out

        # Exemplars from picked strategies appear (at least one
        # CVE per non-empty strategy).
        for s in picked:
            if s.exemplars:
                first_cve = s.exemplars[0].cve
                assert first_cve in out, f"missing exemplar {first_cve}"

        # No truncation marker — bundled strategies should fit
        # comfortably within the default budget.
        assert "truncated" not in out

        # Rendered output is sub-32KB (sanity check on signal
        # density). At 3-4 strategies × 1-2 exemplars × ~500 chars
        # we expect ~5-15KB.
        assert len(out.encode("utf-8")) < 32_000

    def test_three_strategies_under_default_budget(self):
        """All bundled strategies, picked at max=3, fit under the
        default 16KB budget."""
        all_strats = load_all()
        out = render_strategies(all_strats[:3])
        assert "truncated" not in out
        assert len(out.encode("utf-8")) <= DEFAULT_MAX_BYTES

    def test_all_seven_bundled_might_truncate(self):
        """All 7 strategies rendered together MAY exceed the default
        budget. Pin behaviour: either fits, or truncates cleanly."""
        all_strats = load_all()
        out = render_strategies(all_strats)
        # Either no truncation OR clean truncation marker.
        if len(out.encode("utf-8")) >= DEFAULT_MAX_BYTES:
            assert "truncated" in out
