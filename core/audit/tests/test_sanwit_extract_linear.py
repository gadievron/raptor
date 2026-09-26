"""Linearity pins for the chain extractor's scanning regexes.

The extractor parses attacker-controlled PHP function source, so its
three census-flagged regexes must stay linear on adversarial shapes:
the function-header probe (``_body_depth``, anchored match), the
assignment splitter (``_ASSIGN_RE``, anchored match per statement)
and the post-boundary transform-feed scan (built inline in
``extract_chain``, unanchored search per later statement).  All three
are linear by construction — character-disjoint repeats left of each
failable atom for the anchored pair, paren-delimited restart windows
for the scan — and the redos-idiom census pump oracle pins each at
growth exponent 1.0.  The chain-ASSEMBLY loop itself is pinned linear
too (``TestAssemblyLoopLinear``): regex linearity alone did not make
the entry point linear.

Clock choice, adjudicated: every bound here is ``time.process_time``
(CPU, not wall) — the same clock the census pins moved to — so a
loaded host cannot flake a pin and a pin cannot hide behind idle
wall time.  The bounds discriminate by >5x against the nearest
measured mutant (11.3s) and >25x against the rest.

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


def _alias_pump(k: int) -> str:
    lines = ["function f($x) {",
             "    $v0 = htmlspecialchars($x, ENT_QUOTES);"]
    lines += [f"    $v{i + 1} = $v{i};" for i in range(k)]
    lines.append("}")
    return "\n".join(lines)


def _transform_pump(k: int) -> str:
    lines = ["function f($x) {",
             "    $v0 = htmlspecialchars($x, ENT_QUOTES);"]
    lines += [f"    $v{i + 1} = trim($v{i});" for i in range(k)]
    lines.append("}")
    return "\n".join(lines)


class TestAssemblyLoopLinear:
    """The chain-ASSEMBLY loop through the production entry point:
    the divergence check used to rescan every remaining statement
    per carrier move, so a pumped alias chain was QUADRATIC (53s at
    16k one-line aliases — and ACCEPTED). Two independent layers pin
    the fix: the precomputed mention index makes extraction linear,
    and the carrier-move / step ceilings refuse hostile shapes
    DURING extraction (refusal over mis-attribution), so even a
    future algorithmic regression degrades to a bounded refusal."""

    def test_alias_pump_refuses_bounded(self):
        # 16k carrier moves: refused at the carrier gate, in linear
        # time (the mention index is built either way).
        src = _alias_pump(16_000)
        result, took = _timed(
            lambda: extract_chain(src, ("htmlspecialchars",)))
        assert isinstance(result, ExtractionRefusal)
        assert "moves its carrier" in result.reason
        assert took < _CPU_BOUND_S

    def test_transform_pump_refuses_bounded(self):
        # The transform variant grows steps, so the in-extraction
        # step ceiling fires first — still a bounded refusal.
        src = _transform_pump(16_000)
        result, took = _timed(
            lambda: extract_chain(src, ("htmlspecialchars",)))
        assert isinstance(result, ExtractionRefusal)
        assert "step ceiling" in result.reason
        assert took < _CPU_BOUND_S

    def test_algorithm_is_linear_past_the_gate(self, monkeypatch):
        # The gate is defense-in-depth, NOT the fix: with the gate
        # lifted, the same 16k pump ACCEPTS within the CPU bound
        # (measured 0.095s; the pre-fix rescan measured 53.3s) and
        # follows every carrier move correctly.
        import core.audit.sanwit._extract as ex

        monkeypatch.setattr(ex, "_MAX_CARRIER_MOVES", 10**9)
        src = _alias_pump(16_000)
        result, took = _timed(
            lambda: extract_chain(src, ("htmlspecialchars",)))
        assert isinstance(result, ChainExtraction)
        assert result.final_var == "v16000"
        assert took < _CPU_BOUND_S

    def test_carrier_gate_two_directions(self):
        import core.audit.sanwit._extract as ex

        at_gate = extract_chain(
            _alias_pump(ex._MAX_CARRIER_MOVES), ("htmlspecialchars",))
        assert isinstance(at_gate, ChainExtraction)
        assert at_gate.final_var == f"v{ex._MAX_CARRIER_MOVES}"
        over = extract_chain(
            _alias_pump(ex._MAX_CARRIER_MOVES + 1),
            ("htmlspecialchars",))
        assert isinstance(over, ExtractionRefusal)
        assert "moves its carrier" in over.reason

    def test_step_ceiling_two_directions(self):
        from core.audit.sanwit._extract import MAX_CHAIN_STEPS

        def same_var(extra: int) -> str:
            lines = ["function f($x) {",
                     "    $v = htmlspecialchars($x, ENT_QUOTES);"]
            lines += ["    $v = trim($v);"] * extra
            lines.append("}")
            return "\n".join(lines)

        at = extract_chain(
            same_var(MAX_CHAIN_STEPS - 1), ("htmlspecialchars",))
        assert isinstance(at, ChainExtraction)
        assert len(at.steps) == MAX_CHAIN_STEPS
        over = extract_chain(
            same_var(MAX_CHAIN_STEPS), ("htmlspecialchars",))
        assert isinstance(over, ExtractionRefusal)
        assert "step ceiling" in over.reason

    def test_divergence_verdict_survives_the_index(self):
        # Non-vacuity: the O(log n) mention-index lookup preserves
        # the divergence refusal the per-move rescan used to make —
        # an abandoned carrier used later still refuses, near or far.
        filler = "".join(f"    $z{i} = 1;\n" for i in range(40))
        src = (
            "function f($x) {\n"
            "    $a = htmlspecialchars($x, ENT_QUOTES);\n"
            "    $b = $a;\n"
            + filler
            + "    echo $a;\n"
            "}"
        )
        result = extract_chain(src, ("htmlspecialchars",))
        assert isinstance(result, ExtractionRefusal)
        assert "copies can diverge" in result.reason
