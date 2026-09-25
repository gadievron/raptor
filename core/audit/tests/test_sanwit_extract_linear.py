"""Linearity pins for the chain extractor's scanning regexes.

The extractor parses attacker-controlled PHP function source, so its
three census-flagged regexes must stay linear on adversarial shapes:
the function-header probe (``_body_depth``, anchored match), the
assignment splitter (``_ASSIGN_RE``, anchored match per statement)
and the post-boundary transform-feed scan (built inline in
``extract_chain``, unanchored search per later statement).  All three
are linear by construction — character-disjoint adjacent repeats for
the anchored pair, paren-delimited restart windows for the scan — and
the redos-idiom census pump oracle pins each at growth exponent 1.0.

Every pin here is two-direction and non-vacuous: it asserts the
verdict on the hostile shape as well as the CPU bound, and a
matching-direction case keeps the language itself pinned.  The bound
discriminates by orders of magnitude: the natural quadratic drift
mutants measured, at these same input sizes, >20s for the header
probe (``\\w*`` widened to ``[\\w\\s]*``, already at n=3000), 11.3s
for the assignment splitter (same widening), and 6.3s for the
transform-feed scan (``[^()]*`` window widened to ``.*``); the
shipped spellings measure single-digit milliseconds.
"""

from __future__ import annotations

import re
import time
from typing import Callable, TypeVar

from core.audit.sanwit._extract import (
    ALLOWED_STEP_CALLABLES,
    _ASSIGN_RE,
    _body_depth,
    ChainExtraction,
    ExtractionRefusal,
    extract_chain,
)

# CPU-time ceiling for one hostile scan (see module docstring for the
# measured mutant margins this discriminates against).
_CPU_BOUND_S = 2.0

_T = TypeVar("_T")


def _timed(fn: Callable[[], _T]) -> tuple[_T, float]:
    start = time.process_time()
    result = fn()
    return result, time.process_time() - start


class TestBodyDepthHeaderLinear:
    """``\\s*(?:[A-Za-z_]\\w*\\s+)*function\\b`` — the trailing-span
    shape: a pumped modifier-word list whose ``function`` continuation
    never arrives."""

    def test_word_space_pump_fails_fast(self):
        depth, took = _timed(
            lambda: _body_depth("a " * 50_000 + "\x01"))
        assert depth == 0  # headerless — bare-body reading
        assert took < _CPU_BOUND_S

    def test_prefix_word_pump_fails_fast(self):
        # Every word prefix-matches ``function`` for 7 chars.
        depth, took = _timed(lambda: _body_depth("functio " * 12_000))
        assert depth == 0
        assert took < _CPU_BOUND_S

    def test_long_single_word_pump_fails_fast(self):
        depth, took = _timed(
            lambda: _body_depth("a" * 100_000 + " \x01"))
        assert depth == 0
        assert took < _CPU_BOUND_S

    def test_header_still_recognised(self):
        # Matching direction: modifier words then ``function``.
        assert _body_depth("static function f($x) { return $x; }") == 1
        assert _body_depth("function f($x) { return $x; }") == 1
        assert _body_depth("$v = 1;") == 0


class TestAssignSplitterLinear:
    """``^\\$([A-Za-z_]\\w*)\\s*=(?![=>])`` — pumped name and
    whitespace runs whose ``=`` continuation fails, including via the
    ``(?![=>])`` lookahead."""

    def test_name_pump_fails_fast(self):
        m, took = _timed(lambda: _ASSIGN_RE.match("$" + "a" * 100_000))
        assert m is None
        assert took < _CPU_BOUND_S

    def test_space_pump_fails_fast(self):
        m, took = _timed(
            lambda: _ASSIGN_RE.match("$a" + " " * 100_000 + "\x01"))
        assert m is None
        assert took < _CPU_BOUND_S

    def test_lookahead_poison_pump_fails_fast(self):
        # ``=>`` fails the lookahead AFTER the whitespace run matched.
        m, took = _timed(
            lambda: _ASSIGN_RE.match("$a" + " " * 100_000 + "=>"))
        assert m is None
        assert took < _CPU_BOUND_S

    def test_assignment_still_recognised(self):
        m = _ASSIGN_RE.match("$v = htmlspecialchars($x)")
        assert m is not None
        assert m.group(1) == "v"
        # ``==`` / ``=>`` stay non-assignments (lookahead direction).
        assert _ASSIGN_RE.match("$v == $x") is None
        assert _ASSIGN_RE.match("$v => $x") is None


def _feed_re(var: str) -> re.Pattern[str]:
    # The transform-feed spelling as built in ``extract_chain``
    # (same construction; drift between the two is caught by the
    # census pin digest for ``transform_feed_re``, which keys the
    # production site's pattern text).
    return re.compile(
        r"\b(?:" + "|".join(sorted(ALLOWED_STEP_CALLABLES))
        + r")\s*\([^()]*\$" + re.escape(var) + r"\b",
        re.IGNORECASE,
    )


class TestTransformFeedScanLinear:
    """The scan-restart shape: unanchored search whose every restart
    position used to re-scan an unbounded window."""

    def test_open_window_pump_fails_fast(self):
        m, took = _timed(
            lambda: _feed_re("v").search("trim(" + "a" * 300_000))
        assert m is None
        assert took < _CPU_BOUND_S

    def test_restart_salt_fails_fast(self):
        # Maximum restart density: every fifth position opens a new
        # candidate window.
        m, took = _timed(
            lambda: _feed_re("v").search("trim(" * 60_000))
        assert m is None
        assert took < _CPU_BOUND_S

    def test_dollar_salt_fails_fast(self):
        # ``$`` lives inside ``[^()]`` — salt the window with near-miss
        # data slots (``$vx`` fails the trailing ``\\b``).
        m, took = _timed(
            lambda: _feed_re("v").search("trim(" + "$vx" * 100_000))
        assert m is None
        assert took < _CPU_BOUND_S

    def test_feed_still_recognised(self):
        assert _feed_re("v").search("$w = trim( $v );")
        assert _feed_re("v").search("STRTOUPPER($v)")  # IGNORECASE
        assert _feed_re("v").search("$cache[$v] = 1;") is None

    def test_end_to_end_hostile_tail_is_linear_and_terminates(self):
        # Through the public surface: a valid chain, a use boundary,
        # then a pumped hostile statement after the boundary.  The
        # junk feeds nothing, so the chain terminates cleanly — fast.
        src = (
            "function f($x) {\n"
            "    $v = htmlspecialchars($x, ENT_QUOTES);\n"
            "    echo $v;\n"
            "    junk(" + "a" * 200_000 + ");\n"
            "}"
        )
        result, took = _timed(
            lambda: extract_chain(src, ("htmlspecialchars",)))
        assert isinstance(result, ChainExtraction)
        assert took < _CPU_BOUND_S

    def test_end_to_end_restart_salt_is_linear(self):
        # Restart density through the PRODUCTION spelling (the
        # ``_feed_re`` pins above rebuild the pattern locally; this
        # one exercises the compiled regex inside ``extract_chain``):
        # a post-boundary statement salted with a candidate window
        # every fifth character.  The ``.*``-window drift mutant
        # measures 6.3s here; the shipped spelling, milliseconds.
        src = (
            "function f($x) {\n"
            "    $v = htmlspecialchars($x, ENT_QUOTES);\n"
            "    echo $v;\n"
            "    " + "trim(" * 60_000 + "\n"
            "}"
        )
        result, took = _timed(
            lambda: extract_chain(src, ("htmlspecialchars",)))
        assert isinstance(result, ChainExtraction)
        assert took < _CPU_BOUND_S

    def test_end_to_end_post_boundary_feed_still_refuses(self):
        # Refusal direction stays pinned: an actual transform feed
        # after the boundary refuses, pump or no pump.
        src = (
            "function f($x) {\n"
            "    $v = htmlspecialchars($x, ENT_QUOTES);\n"
            "    echo $v;\n"
            "    $w = trim(" + "a" * 200_000 + " . $v);\n"
            "}"
        )
        result, took = _timed(
            lambda: extract_chain(src, ("htmlspecialchars",)))
        assert isinstance(result, ExtractionRefusal)
        assert "transformed or reassigned" in result.reason
        assert took < _CPU_BOUND_S
