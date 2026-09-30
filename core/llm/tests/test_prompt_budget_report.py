"""Tests for the structured fit report and priority-0 elision in
``core.llm.prompt_budget``.

``fit_to_budget`` stays a thin 2-tuple wrapper whose behaviour is
byte-identical to the pre-report implementation (never truncates
priority-0 content, same send-anyway warning); the elision behaviour
is opt-in via ``fit_to_budget_report(..., elide_priority0=True)``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
import sys

import pytest

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_RAPTOR_DIR))

from core.llm.prompt_budget import (
    _P0_ELISION_FLOOR_TOKENS,
    FitReport,
    PromptSection,
    estimate_tokens,
    fit_to_budget,
    fit_to_budget_report,
)

_LOGGER = "core.llm.prompt_budget"


def _sec(label: str, tokens: int, priority: int = 0) -> PromptSection:
    """A section whose token estimate is exactly *tokens*."""
    return PromptSection(label, "x" * (tokens * 4), priority)


class TestReportNoOvershoot:

    def test_passthrough_keeps_everything(self) -> None:
        sections = [_sec("source", 100), _sec("callers", 50, 1)]
        report = fit_to_budget_report(sections, 1_000)
        assert isinstance(report, FitReport)
        assert report.kept == sections
        assert report.shed == []
        assert report.overshoot_tokens == 0
        assert report.elisions == []

    def test_elide_flag_is_inert_when_fit(self) -> None:
        sections = [_sec("source", 100)]
        report = fit_to_budget_report(
            sections, 1_000, elide_priority0=True,
        )
        assert report.kept[0].text == sections[0].text
        assert report.elisions == []

    def test_wrapper_two_tuple_matches_report(self) -> None:
        sections = [_sec("source", 100), _sec("callers", 50, 1)]
        kept, shed = fit_to_budget(sections, 1_000)
        report = fit_to_budget_report(sections, 1_000)
        assert (kept, shed) == (report.kept, report.shed)
        # Byte-identical passthrough: exact same texts, untouched.
        assert [s.text for s in kept] == [s.text for s in sections]

    def test_no_warning_when_fit(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            fit_to_budget_report(
                [_sec("source", 100)], 1_000, elide_priority0=True,
            )
        assert caplog.records == []


class TestWrapperCompatOverBudget:

    def test_wrapper_never_truncates_priority0(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        sections = [_sec("source", 2_000), _sec("evidence", 2_000)]
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            kept, shed = fit_to_budget(sections, 100)
        assert shed == []
        assert [s.text for s in kept] == [s.text for s in sections]
        # The pre-report warning line, byte-identical.
        msgs = [r.getMessage() for r in caplog.records]
        assert msgs == [
            "prompt_budget: still 3900 tokens over budget after "
            "shedding all sheddable sections",
        ]

    def test_wrapper_shedding_unchanged(self) -> None:
        sections = [
            _sec("source", 100),
            _sec("callers", 100, 1),
            _sec("exemplars", 100, 5),
        ]
        kept, shed = fit_to_budget(sections, 200)
        assert [s.label for s in shed] == ["exemplars"]
        assert [s.label for s in kept] == ["source", "callers"]


class TestP0Elision:

    def test_elides_to_fit_with_marker(self) -> None:
        sections = [_sec("source", 4_000)]
        report = fit_to_budget_report(
            sections, 1_000, elide_priority0=True,
        )
        assert report.overshoot_tokens == 0
        assert len(report.elisions) == 1
        el = report.elisions[0]
        assert el.label == "source"
        assert el.tokens_elided == 3_000
        assert "tokens elided from source" in report.kept[0].text

    def test_marker_cost_counted_in_fit(self) -> None:
        # The composed section (truncated body + marker) must land
        # exactly on the target estimate — the marker never rides
        # free into a still-over-budget result.
        report = fit_to_budget_report(
            [_sec("source", 4_000)], 1_000, elide_priority0=True,
        )
        kept = report.kept[0]
        assert estimate_tokens(kept.text) == 1_000
        assert kept.text.endswith(" ...]")

    def test_marker_format(self) -> None:
        report = fit_to_budget_report(
            [_sec("source", 4_000)], 1_000, elide_priority0=True,
        )
        assert re.search(
            r"\n\[\.\.\. prompt budget: 3000 tokens elided "
            r"from source \.\.\.\]$",
            report.kept[0].text,
        )

    def test_largest_first(self) -> None:
        sections = [_sec("small", 1_000), _sec("big", 4_000)]
        report = fit_to_budget_report(
            sections, 4_600, elide_priority0=True,
        )
        assert report.overshoot_tokens == 0
        assert [e.label for e in report.elisions] == ["big"]
        # The smaller section is untouched.
        assert report.kept[0].text == sections[0].text

    def test_spills_to_next_largest(self) -> None:
        sections = [_sec("big", 2_000), _sec("small", 1_000)]
        report = fit_to_budget_report(
            sections, 1_200, elide_priority0=True,
        )
        assert report.overshoot_tokens == 0
        assert [e.label for e in report.elisions] == ["big", "small"]
        by_label = {s.label: s for s in report.kept}
        # The largest section is floored: its BODY (text before the
        # marker) never drops below the floor; the composed section
        # is body plus the counted marker overhead.
        big_body = by_label["big"].text.split("\n[... prompt budget:")[0]
        assert len(big_body) >= _P0_ELISION_FLOOR_TOKENS * 4
        total = sum(estimate_tokens(s.text) for s in report.kept)
        assert total == 1_200

    def test_original_order_preserved(self) -> None:
        sections = [_sec("small", 1_000), _sec("big", 4_000)]
        report = fit_to_budget_report(
            sections, 4_600, elide_priority0=True,
        )
        assert [s.label for s in report.kept] == ["small", "big"]

    def test_shed_before_elide(self) -> None:
        sections = [_sec("source", 2_000), _sec("exemplars", 1_000, 5)]
        report = fit_to_budget_report(
            sections, 1_500, elide_priority0=True,
        )
        assert [s.label for s in report.shed] == ["exemplars"]
        assert [e.label for e in report.elisions] == ["source"]
        assert report.elisions[0].tokens_elided == 500
        assert report.overshoot_tokens == 0


class TestElisionFloor:

    def test_floor_constant_pinned(self) -> None:
        # Regression pin: the two-direction rationale on the constant
        # (evidence destruction below / elision defeat above) was
        # written for this value.
        assert _P0_ELISION_FLOOR_TOKENS == 512

    def test_never_truncates_below_floor(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            report = fit_to_budget_report(
                [_sec("source", 600)], 100, elide_priority0=True,
            )
        kept = report.kept[0]
        # The floor applies to the BODY: the kept evidence text
        # (before the marker) never drops below the floor even though
        # the counted marker overhead pushes the composed size
        # slightly above it.
        body = kept.text.split("\n[... prompt budget:")[0]
        assert len(body) >= _P0_ELISION_FLOOR_TOKENS * 4
        # Truthful accounting: reclaimed == original - composed, the
        # residual is the overshoot minus exactly that, and reclaim
        # never reaches past the floor (600 - 512 = 88 max).
        reclaimed = report.elisions[0].tokens_elided
        assert reclaimed == 600 - estimate_tokens(kept.text)
        assert 0 < reclaimed <= 88
        assert report.overshoot_tokens == 500 - reclaimed
        # The send-anyway warning survives.
        msgs = [r.getMessage() for r in caplog.records]
        assert msgs == [
            f"prompt_budget: still {report.overshoot_tokens} tokens "
            "over budget after shedding all sheddable sections",
        ]

    def test_at_floor_section_untouched(
        self, caplog: pytest.LogCaptureFixture,
    ) -> None:
        sections = [_sec("source", _P0_ELISION_FLOOR_TOKENS)]
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            report = fit_to_budget_report(
                sections, 100, elide_priority0=True,
            )
        assert report.kept[0].text == sections[0].text
        assert report.elisions == []
        assert report.overshoot_tokens == 412
        assert len(caplog.records) == 1

    def test_all_floored_residual_truthful(self) -> None:
        sections = [
            _sec("source", _P0_ELISION_FLOOR_TOKENS),
            _sec("evidence", _P0_ELISION_FLOOR_TOKENS),
        ]
        report = fit_to_budget_report(
            sections, 512, elide_priority0=True,
        )
        assert report.elisions == []
        assert report.overshoot_tokens == 512
        assert [s.text for s in report.kept] == \
            [s.text for s in sections]


def _fenced_sec(label: str, lines: int) -> PromptSection:
    """A priority-0 section shaped like the audit source section: a
    3-backtick fenced body whose closing fence sits at the very end."""
    body = "  x += p[i]; /* pad */\n" * lines
    return PromptSection(label, f"```c\n{body}```", 0)


class TestStructuralClosers:
    """Tail elision must never sever structural closers.

    A structure-blind cut that removes a section's closing code fence
    leaves everything after it rendering INSIDE the fence — a later
    backtick run in target-derived text can flip fence parity and
    surface untrusted content as live prose.  A cut that removes an
    ``</untrusted-...>`` close tag leaves the untrusted region
    unterminated.  The elision re-appends the severed closer(s) and
    places the marker LAST, outside the fence/envelope.
    """

    def test_severed_fence_reclosed_marker_outside(self) -> None:
        sec = _fenced_sec("source", 900)  # ~5.2k tokens
        report = fit_to_budget_report(
            [sec], 1_000, elide_priority0=True,
        )
        composed = report.kept[0].text
        # The fence is re-closed and the marker lands AFTER the
        # closer — outside the fence, in trusted context.
        assert re.search(
            r"\n```\n\[\.\.\. prompt budget: \d+ tokens elided "
            r"from source \.\.\.\]$", composed)
        # Fence-delimiter lines balance: opener + closer, nothing else.
        fence_lines = [ln for ln in composed.split("\n")
                       if ln.startswith("```")]
        assert len(fence_lines) == 2

    def test_reclosed_fence_matches_opener_run_length(self) -> None:
        # CommonMark closes a fence only with a backtick run AT LEAST
        # as long as the opener, and assemblers pick openers longer
        # than any run in the body — so a bare ``` cannot close this
        # ```` fence.  The re-appended closer must replay the opener's
        # run length.
        body = "data\n```\nmore\n" * 600
        sec = PromptSection("source", f"````c\n{body}````", 0)
        report = fit_to_budget_report(
            [sec], 1_000, elide_priority0=True,
        )
        composed = report.kept[0].text
        m = re.search(r"\n(`+)\n\[\.\.\. prompt budget:", composed)
        assert m is not None
        assert m.group(1) == "````"

    def test_envelope_close_reappended_marker_outside(self) -> None:
        close = "</untrusted-abc123def4567890>"
        text = (
            '<untrusted-abc123def4567890 kind="mechanical-evidence"'
            ' origin="audit-evidence-index">\n'
            + "sink hit detail line\n" * 1_000 + close
        )
        report = fit_to_budget_report(
            [PromptSection("evidence", text, 0)], 1_000,
            elide_priority0=True,
        )
        composed = report.kept[0].text
        lines = composed.split("\n")
        opens = [ln for ln in lines if ln.startswith("<untrusted-")]
        closes = [ln for ln in lines if ln.startswith("</untrusted-")]
        assert len(opens) == 1
        assert closes == [close]
        # Marker after the close tag — outside the untrusted region.
        assert composed.endswith(
            close + "\n[... prompt budget: "
            f"{report.elisions[0].tokens_elided} tokens elided "
            "from evidence ...]")

    def test_envelope_closer_never_minted(self) -> None:
        # An open tag whose close tag is NOT in the original section
        # text never gets one invented for it: the per-call nonce
        # close tag is unforgeable and only the envelope layer may
        # write it.
        text = (
            '<untrusted-abc123def4567890 kind="mechanical-evidence"'
            ' origin="audit-evidence-index">\n'
            + "sink hit detail line\n" * 1_000
        )
        report = fit_to_budget_report(
            [PromptSection("evidence", text, 0)], 1_000,
            elide_priority0=True,
        )
        assert "</untrusted-" not in report.kept[0].text

    def test_envelope_tags_inside_fence_are_literal(self) -> None:
        # Fence bodies are literal text: an <untrusted-...> line
        # inside an open fence is data, not a real envelope boundary —
        # only the fence gets re-closed.
        text = (
            "```\n"
            '<untrusted-abc123def4567890 kind="x" origin="y">\n'
            + "pad line\n" * 1_500
            + "</untrusted-abc123def4567890>\n```"
        )
        report = fit_to_budget_report(
            [PromptSection("source", text, 0)], 1_000,
            elide_priority0=True,
        )
        composed = report.kept[0].text
        assert re.search(r"\n```\n\[\.\.\. prompt budget:", composed)
        assert "</untrusted-" not in composed

    def test_closer_cost_counted_in_fit(self) -> None:
        # The re-appended closer joins the marker in the fit
        # arithmetic: the composed section (body + closer + marker)
        # lands exactly on the target estimate — neither the closer
        # nor the marker rides free into an over-budget result.
        sec = _fenced_sec("source", 900)
        report = fit_to_budget_report(
            [sec], 1_000, elide_priority0=True,
        )
        assert report.overshoot_tokens == 0
        composed = report.kept[0].text
        assert "\n```\n[... prompt budget:" in composed
        assert estimate_tokens(composed) == 1_000
        assert report.elisions[0].tokens_elided == \
            sec.token_estimate - 1_000
