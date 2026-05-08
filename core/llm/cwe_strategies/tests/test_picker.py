"""Tests for ``pick_strategies``.

Synthetic strategies are used throughout so the tests don't depend
on which strategies are bundled — commit 3 adds the rest, and we
don't want this test file to need updates each time.
"""

from __future__ import annotations

import pytest

from core.llm.cwe_strategies import (
    Signals,
    Strategy,
    pick_strategies,
)


def _strat(name, *, paths=(), includes=(), keywords=()):
    return Strategy(
        name=name,
        description=f"{name} description",
        signals=Signals(
            paths=tuple(paths),
            includes=tuple(includes),
            function_keywords=tuple(keywords),
        ),
        key_questions=("q1?",),
        prompt_addendum=f"{name} addendum",
    )


GENERAL_STRAT = _strat("general")
INPUT_STRAT = _strat("input_handling",
                     paths=("net/", "drivers/input/"),
                     keywords=("parse", "decode"))
CONCURRENCY_STRAT = _strat("concurrency",
                            paths=("kernel/locking/", "mm/"),
                            includes=("linux/mutex.h",),
                            keywords=("lock", "unlock"))
CRYPTO_STRAT = _strat("cryptography",
                       paths=("crypto/",),
                       keywords=("hash", "encrypt"))


def _pool():
    return [GENERAL_STRAT, INPUT_STRAT, CONCURRENCY_STRAT, CRYPTO_STRAT]


# ---------------------------------------------------------------------------
# Default behaviour
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_general_always_first_when_no_match(self):
        out = pick_strategies(
            file_path="src/random.py",
            function_name="do_thing",
            strategies=_pool(),
        )
        assert len(out) == 1
        assert out[0].name == "general"

    def test_general_first_with_matches(self):
        out = pick_strategies(
            file_path="net/proto.c",
            function_name="parse_packet",
            strategies=_pool(),
        )
        # Should pick general + input_handling.
        assert out[0].name == "general"
        assert any(s.name == "input_handling" for s in out)

    def test_max_strategies_cap(self):
        out = pick_strategies(
            file_path="net/crypto/lock.c",  # matches 3 strategies
            function_name="parse_lock_hash",  # matches 3 keywords
            strategies=_pool(),
            max_strategies=2,
        )
        # General + best match = 2 entries.
        assert len(out) == 2
        assert out[0].name == "general"

    def test_max_strategies_zero_returns_empty(self):
        out = pick_strategies(
            file_path="net/proto.c",
            function_name="parse",
            strategies=_pool(),
            max_strategies=0,
        )
        assert out == []


# ---------------------------------------------------------------------------
# Signal scoring
# ---------------------------------------------------------------------------


class TestSignalScoring:
    def test_path_match(self):
        out = pick_strategies(
            file_path="net/skbuff.c",
            function_name="x",
            strategies=_pool(),
        )
        assert "input_handling" in {s.name for s in out}

    def test_keyword_match_in_function_name(self):
        out = pick_strategies(
            file_path="src/util.c",  # no path match
            function_name="encrypt_buffer",
            strategies=_pool(),
        )
        assert "cryptography" in {s.name for s in out}

    def test_include_match(self):
        out = pick_strategies(
            file_path="src/random.c",
            function_name="x",
            file_includes=("linux/mutex.h",),
            strategies=_pool(),
        )
        assert "concurrency" in {s.name for s in out}

    def test_higher_score_ranks_higher(self):
        # input_handling: 1 path match (net/) + 1 keyword (parse) = 2
        # concurrency: 1 path match (mm/) only = 1
        out = pick_strategies(
            file_path="net/foo.c",  # input_handling: paths
            function_name="parse_data",  # input_handling: keyword
            strategies=_pool(),
            max_strategies=3,
        )
        # general first, then input_handling (highest score).
        assert out[0].name == "general"
        # input_handling should appear before concurrency (no concurrency
        # signal in this case, so concurrency wouldn't show at all).
        assert out[1].name == "input_handling"

    def test_zero_score_excluded(self):
        out = pick_strategies(
            file_path="src/totally_unrelated.py",
            function_name="boring_helper",
            strategies=_pool(),
        )
        # Only general (always-included), no zero-score strategies.
        assert [s.name for s in out] == ["general"]

    def test_case_insensitive_path(self):
        out = pick_strategies(
            file_path="NET/Proto.C",
            function_name="x",
            strategies=_pool(),
        )
        assert "input_handling" in {s.name for s in out}

    def test_case_insensitive_keyword(self):
        out = pick_strategies(
            file_path="src/x.c",
            function_name="ENCRYPT_DATA",
            strategies=_pool(),
        )
        assert "cryptography" in {s.name for s in out}

    def test_alphabetical_tiebreaker(self):
        # Construct two strategies with same-length keywords so the
        # specificity-weighted scoring genuinely ties.
        a = _strat("aaa", keywords=("hash",))   # len 4
        b = _strat("bbb", keywords=("lock",))   # len 4
        out = pick_strategies(
            file_path="src/x.c",
            function_name="hash_lock",  # hits both, equal length
            strategies=[a, b, GENERAL_STRAT],
        )
        # Both score 4; alphabetical ordering: aaa < bbb.
        names = [s.name for s in out]
        assert names == ["general", "aaa", "bbb"]

    def test_specificity_outranks_breadth(self):
        """Length-weighted scoring: a narrow path signal outscores
        a broader one matching the same file."""
        narrow = _strat("narrow", paths=("fs/splice.c",))   # len 12
        broad = _strat("broad", paths=("fs/",))              # len 3
        out = pick_strategies(
            file_path="fs/splice.c",
            function_name="x",
            strategies=[narrow, broad],
            always_include_general=False,
        )
        # Narrow's specificity wins.
        assert out[0].name == "narrow"
        assert out[1].name == "broad"


# ---------------------------------------------------------------------------
# always_include_general
# ---------------------------------------------------------------------------


class TestAlwaysIncludeGeneral:
    def test_general_omitted_when_flag_off_and_other_matches(self):
        out = pick_strategies(
            file_path="net/x.c",
            function_name="parse_data",
            strategies=_pool(),
            always_include_general=False,
        )
        # General should not appear; input_handling is the match.
        assert "general" not in {s.name for s in out}
        assert "input_handling" in {s.name for s in out}

    def test_general_falls_through_when_flag_off_and_no_matches(self):
        # No matches at all — picker should still return general so
        # the caller never gets an empty list when general exists.
        out = pick_strategies(
            file_path="src/totally_unrelated.py",
            function_name="boring",
            strategies=_pool(),
            always_include_general=False,
        )
        assert [s.name for s in out] == ["general"]

    def test_no_general_in_pool_returns_only_matches(self):
        # Pool without general — pick should only return scored matches.
        pool = [INPUT_STRAT, CONCURRENCY_STRAT]
        out = pick_strategies(
            file_path="net/x.c",
            function_name="parse_data",
            strategies=pool,
        )
        assert "general" not in {s.name for s in out}
        assert "input_handling" in {s.name for s in out}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_strategy_pool_returns_empty(self):
        assert pick_strategies(
            file_path="x", function_name="y", strategies=[],
        ) == []

    def test_empty_file_path(self):
        # No path signals can match without a path.
        out = pick_strategies(
            file_path="",
            function_name="parse_data",
            strategies=_pool(),
        )
        # Keyword-based match still fires.
        assert "input_handling" in {s.name for s in out}

    def test_empty_function_name(self):
        out = pick_strategies(
            file_path="net/x.c",
            function_name="",
            strategies=_pool(),
        )
        # Path match fires.
        assert "input_handling" in {s.name for s in out}

    def test_empty_includes_list(self):
        out = pick_strategies(
            file_path="src/x.c",
            function_name="x",
            file_includes=(),
            strategies=_pool(),
        )
        # No matches; only general.
        assert [s.name for s in out] == ["general"]

    def test_default_pool_loads_bundled(self):
        """When ``strategies`` is None, picker loads from the bundled
        directory. Sanity check that this path works at all."""
        out = pick_strategies(
            file_path="net/x.c",
            function_name="parse",
        )
        # Bundled dir currently has only general — but that's fine,
        # picker just returns it.
        assert any(s.name == "general" for s in out)
