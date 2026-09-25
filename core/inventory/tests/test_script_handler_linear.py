"""Linearity and window-bound pins for the script-handler regexes.

The classifier parses scanned-repo PHP — a hostile-input surface — so
its two scanning regexes must stay linear on adversarial shapes: the
wiring statement test (``_PHP_WIRING_STMT_RE``, anchored match per
statement) and the interpolation-hole scan (``_INTERP_VAR_RE``,
finditer over double-quoted string bodies).  Every timing pin below
is non-vacuous: it asserts the classification verdict on the hostile
shape as well as the CPU bound, so a rewrite that goes fast by going
wrong fails here too.  The window bounds get two-direction pins —
at-bound behaviour identical, over-bound behaviour in the documented
direction (always toward handler code / dynamic, never toward
wiring / literal).
"""

from __future__ import annotations

import time
from typing import Callable, TypeVar

from core.inventory.script_handler import (
    _INTERP_VAR_RE,
    _PHP_WIRING_STMT_RE,
    classify_include_argument,
    php_interstitial_is_handler,
)

# CPU-time ceiling for one hostile classification.  The quadratic
# spellings these pins guard against measured 5.5s (wiring NBSP pump)
# and 4-5s (interp opener pumps) at these input sizes; the linear
# spellings measure milliseconds — the bound discriminates by more
# than an order of magnitude in both directions.
_CPU_BOUND_S = 2.0

_T = TypeVar("_T")


def _timed(fn: Callable[[], _T]) -> tuple[_T, float]:
    start = time.process_time()
    result = fn()
    return result, time.process_time() - start


class TestWiringHostileShapesLinear:
    """The trailing-span attack shapes: a pumped run that both the
    identifier class and ``\\s`` can consume (\\xa0 = NBSP is a PHP
    identifier byte AND Unicode whitespace), or a pumped plain run,
    followed by a poison byte so the match must fail."""

    def test_nbsp_pump_fails_fast_and_classifies_handler(self):
        stmt = "<?php\nglobal $a" + "\xa0" * 30000 + "\x01;\n"
        verdict, took = _timed(lambda: php_interstitial_is_handler(stmt))
        assert verdict is True  # poisoned statement is never wiring
        assert took < _CPU_BOUND_S

    def test_identifier_pump_fails_fast_and_classifies_handler(self):
        stmt = "<?php\nglobal $a" + "0" * 30000 + "\x01;\n"
        verdict, took = _timed(lambda: php_interstitial_is_handler(stmt))
        assert verdict is True
        assert took < _CPU_BOUND_S

    def test_space_pump_fails_fast_and_classifies_handler(self):
        stmt = "<?php\nglobal $a" + " " * 30000 + "\x01;\n"
        verdict, took = _timed(lambda: php_interstitial_is_handler(stmt))
        assert verdict is True
        assert took < _CPU_BOUND_S

    def test_name_list_pump_fails_fast_and_classifies_handler(self):
        stmt = "<?php\nglobal " + ",$a" * 9000 + "\x01;\n"
        verdict, took = _timed(lambda: php_interstitial_is_handler(stmt))
        assert verdict is True
        assert took < _CPU_BOUND_S

    def test_legit_long_list_still_wiring(self):
        # Non-vacuity in the accepting direction: a large but plain
        # global list is still recognised as wiring, fast.
        stmt = ("<?php\nglobal "
                + ", ".join(f"$v{i}" for i in range(900)) + ";\n")
        verdict, took = _timed(lambda: php_interstitial_is_handler(stmt))
        assert verdict is False
        assert took < _CPU_BOUND_S

    def test_overlap_bytes_stay_in_the_language(self):
        # \xa0 / \x85 are identifier bytes (PHP allows 0x80-0xff):
        # inside a name, and as trailing whitespace, both keep
        # matching exactly as the previous spelling did.
        assert _PHP_WIRING_STMT_RE.match("global $a\xa0b")
        assert _PHP_WIRING_STMT_RE.match("global $a\xa0")
        assert _PHP_WIRING_STMT_RE.match("global $a \xa0\t")
        assert _PHP_WIRING_STMT_RE.match("global $a\x85, $b")
        assert _PHP_WIRING_STMT_RE.match("global $a\xa0 ,\xa0$b\xa0")
        # ...and the poison shapes stay OUT of it.
        assert not _PHP_WIRING_STMT_RE.match("global $a\xa0\x01")
        assert not _PHP_WIRING_STMT_RE.match("global $a \xa0b")


class TestWiringListBound:
    """Two directions of the 1000-name comma-list bound."""

    def test_at_bound_is_wiring(self):
        stmt = "global " + ",".join(f"$v{i}" for i in range(1001))
        assert _PHP_WIRING_STMT_RE.match(stmt)  # 1000 commas

    def test_over_bound_classifies_handler_code(self):
        # Toward inclusion: an absurd list costs a review slot, it
        # never writes a span off as wiring.
        stmt = "global " + ",".join(f"$v{i}" for i in range(1002))
        assert not _PHP_WIRING_STMT_RE.match(stmt)  # 1001 commas


class TestInterpHostileShapesLinear:
    """The scan-restart attack shapes: a body salted with hole
    openers whose closer never comes, so every opener position used
    to re-scan the remaining body."""

    def test_dollar_brace_salt_is_dynamic_and_fast(self):
        arg = '"' + "${." * 60000 + '"'
        result, took = _timed(lambda: classify_include_argument(arg))
        assert result.shape == "dynamic"  # never static string material
        assert took < _CPU_BOUND_S

    def test_curly_dollar_salt_is_dynamic_and_fast(self):
        arg = '"' + "{$." * 60000 + '"'
        result, took = _timed(lambda: classify_include_argument(arg))
        assert result.shape == "dynamic"
        assert took < _CPU_BOUND_S

    def test_subscript_salt_is_dynamic_and_fast(self):
        arg = '"' + "$a[ " * 60000 + '"'
        result, took = _timed(lambda: classify_include_argument(arg))
        assert result.shape == "dynamic"
        assert took < _CPU_BOUND_S


class TestInterpWindowBound:
    """Two directions of the 1000-char hole-interior bound.  Overflow
    always lands on the dynamic side: an oversized hole can never
    make its string read as pure literal."""

    def test_at_bound_hole_swallows_interior(self):
        body = "mod/${" + "x" * 1000 + "}.php"
        result = classify_include_argument('"' + body + '"')
        assert result.shape == "dynamic"
        assert result.literal_tail == ".php"  # closer consumed

    def test_over_bound_closed_hole_stays_dynamic(self):
        body = "mod/${" + "x" * 1500 + "}.php"
        result = classify_include_argument('"' + body + '"')
        assert result.shape == "dynamic"

    def test_over_bound_unclosed_hole_stays_dynamic(self):
        body = "mod/${" + "x" * 1500
        result = classify_include_argument('"' + body + '"')
        assert result.shape == "dynamic"

    def test_over_bound_subscript_stays_dynamic(self):
        body = "$arr[" + "k" * 1500 + "].php"
        result = classify_include_argument('"' + body + '"')
        assert result.shape == "dynamic"  # bare $arr hole still fires

    def test_short_unclosed_opener_stays_literal(self):
        # Below the overflow gate an unclosed ``${`` is not a hole —
        # unchanged behaviour.
        assert _INTERP_VAR_RE.search("${abc") is None
        result = classify_include_argument('"mod/${abc.php"')
        assert result.shape == "literal"

    def test_plain_literal_stays_literal(self):
        result = classify_include_argument('"mod/plain.php"')
        assert result.shape == "literal"
        assert result.literal_tail == "mod/plain.php"
