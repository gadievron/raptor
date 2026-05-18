"""Tests for Tier-1 picker improvements:

  * 1a — token-based keyword matching (no more `parse` matching
    `is_sparse_array`).
  * 1b — function_calls signal: strategies declare callees, picker
    accepts ``function_calls_made``.
  * 1c — cwes signal: strategies declare CWEs, picker accepts
    ``candidate_cwes``; CWE matches are heavy-weighted.
"""

from __future__ import annotations


from core.llm.cwe_strategies import (
    Signals,
    Strategy,
    pick_strategies,
)


def _strat(name, *, paths=(), includes=(), keywords=(),
           calls=(), cwes=()):
    return Strategy(
        name=name,
        description=f"{name} description",
        signals=Signals(
            paths=tuple(paths),
            includes=tuple(includes),
            function_keywords=tuple(keywords),
            function_calls=tuple(calls),
            cwes=tuple(cwes),
        ),
        key_questions=("q?",),
        prompt_addendum=f"{name} addendum",
    )


GENERAL_STRAT = _strat("general")


# ---------------------------------------------------------------------------
# Tier 1a — token-based keyword matching
# ---------------------------------------------------------------------------


class TestTokenKeywordMatching:
    def test_token_match_in_function_name(self):
        s = _strat("input", keywords=("parse",))
        out = pick_strategies(
            file_path="x", function_name="parse_packet",
            strategies=[GENERAL_STRAT, s],
        )
        assert "input" in {x.name for x in out}

    def test_no_substring_pollution(self):
        """``parse`` keyword should NOT match ``is_sparse_array`` —
        the previous substring-based picker did, leading to
        false-positive strategy picks on unrelated functions."""
        s = _strat("input", keywords=("parse",))
        out = pick_strategies(
            file_path="x", function_name="is_sparse_array",
            strategies=[GENERAL_STRAT, s],
        )
        # Only general; input is not picked.
        assert [x.name for x in out] == ["general"]

    def test_compare_does_not_match_parse(self):
        """``parse`` is NOT a substring of ``compare`` — included
        for the historical lesson that substring matching seems
        right but isn't, and to pin the fix."""
        s = _strat("input", keywords=("parse",))
        out = pick_strategies(
            file_path="x", function_name="compare_buffers",
            strategies=[GENERAL_STRAT, s],
        )
        assert [x.name for x in out] == ["general"]

    def test_token_with_dash_separator(self):
        s = _strat("input", keywords=("parse",))
        out = pick_strategies(
            file_path="x", function_name="parse-packet",
            strategies=[GENERAL_STRAT, s],
        )
        assert "input" in {x.name for x in out}

    def test_trailing_underscore_keyword_treated_as_token(self):
        """``get_`` is a common operator convention: 'matches as a
        prefix'. Token semantics + trailing-separator strip handles
        this — ``get_`` keyword matches ``get_user``, ``get_size``
        etc."""
        s = _strat("memory", keywords=("get_",))
        out = pick_strategies(
            file_path="x", function_name="get_user_creds",
            strategies=[GENERAL_STRAT, s],
        )
        assert "memory" in {x.name for x in out}

    def test_keyword_in_middle_token(self):
        s = _strat("memory", keywords=("kref",))
        out = pick_strategies(
            file_path="x", function_name="my_kref_helper",
            strategies=[GENERAL_STRAT, s],
        )
        assert "memory" in {x.name for x in out}

    def test_partial_token_no_match(self):
        """``ref`` keyword should NOT match ``referer`` (token
        ``referer`` doesn't equal ``ref``)."""
        s = _strat("memory", keywords=("ref",))
        out = pick_strategies(
            file_path="x", function_name="set_referer_header",
            strategies=[GENERAL_STRAT, s],
        )
        assert [x.name for x in out] == ["general"]


# ---------------------------------------------------------------------------
# Tier 1b — function_calls signal
# ---------------------------------------------------------------------------


class TestFunctionCallsSignal:
    def test_call_match_picks_strategy(self):
        s = _strat("concurrency", calls=("mutex_lock", "mutex_unlock"))
        out = pick_strategies(
            file_path="src/random.c",  # no path signal
            function_name="do_thing",   # no keyword signal
            function_calls_made=["mutex_lock", "kfree"],
            strategies=[GENERAL_STRAT, s],
        )
        assert "concurrency" in {x.name for x in out}

    def test_no_call_match_no_pick(self):
        s = _strat("concurrency", calls=("mutex_lock",))
        out = pick_strategies(
            file_path="x", function_name="y",
            function_calls_made=["printf", "memcpy"],
            strategies=[GENERAL_STRAT, s],
        )
        assert [x.name for x in out] == ["general"]

    def test_call_match_outscores_path_match(self):
        """A function calling `mutex_lock` is a stronger
        concurrency signal than living in ``net/``. Length-weighted
        scoring on the ``mutex_lock`` (10 chars) vs ``net/`` (4)
        should rank concurrency higher."""
        net_strat = _strat("input", paths=("net/",))
        conc_strat = _strat("concurrency", calls=("mutex_lock",))
        out = pick_strategies(
            file_path="net/x.c",
            function_name="x",
            function_calls_made=["mutex_lock"],
            strategies=[GENERAL_STRAT, net_strat, conc_strat],
        )
        # general first, then concurrency (10) before input (4).
        names = [s.name for s in out]
        assert names == ["general", "concurrency", "input"]

    def test_case_insensitive_call_match(self):
        s = _strat("concurrency", calls=("Mutex_Lock",))
        out = pick_strategies(
            file_path="x", function_name="y",
            function_calls_made=["mutex_lock"],
            strategies=[GENERAL_STRAT, s],
        )
        assert "concurrency" in {x.name for x in out}


# ---------------------------------------------------------------------------
# Tier 1c — cwes signal
# ---------------------------------------------------------------------------


class TestCweSignal:
    def test_cwe_match_picks_strategy(self):
        s = _strat("input", cwes=("CWE-78", "CWE-89"))
        out = pick_strategies(
            file_path="x", function_name="y",
            candidate_cwes=["CWE-78"],
            strategies=[GENERAL_STRAT, s],
        )
        assert "input" in {x.name for x in out}

    def test_cwe_match_outranks_other_signals(self):
        """A CWE pin is direct evidence — should outrank a
        fragmentary signal stack from other strategies."""
        a = _strat("a", cwes=("CWE-78",))
        b = _strat("b",
                   paths=("very/long/path/to/match/strongly/",),
                   keywords=("parse", "decode", "deserialize",
                             "unmarshal"))
        out = pick_strategies(
            file_path="very/long/path/to/match/strongly/x.c",
            function_name="parse_decode_deserialize_unmarshal",
            candidate_cwes=["CWE-78"],
            strategies=[GENERAL_STRAT, a, b],
        )
        # 'a' wins on CWE pin (50 pts) over 'b' even with
        # accumulated path + keyword length.
        names = [s.name for s in out]
        assert names[1] == "a"

    def test_no_cwes_no_match(self):
        s = _strat("input", cwes=("CWE-78",))
        out = pick_strategies(
            file_path="x", function_name="y",
            candidate_cwes=[],
            strategies=[GENERAL_STRAT, s],
        )
        assert [x.name for x in out] == ["general"]

    def test_case_insensitive_cwe_match(self):
        s = _strat("input", cwes=("cwe-78",))
        out = pick_strategies(
            file_path="x", function_name="y",
            candidate_cwes=["CWE-78"],
            strategies=[GENERAL_STRAT, s],
        )
        assert "input" in {x.name for x in out}

    def test_multiple_cwe_matches_compound(self):
        """Two CWEs both matching → 100 pts. Stronger evidence
        than one CWE."""
        a = _strat("a", cwes=("CWE-78",))
        b = _strat("b", cwes=("CWE-89", "CWE-90"))
        out = pick_strategies(
            file_path="x", function_name="y",
            candidate_cwes=["CWE-89", "CWE-90"],
            strategies=[GENERAL_STRAT, a, b],
        )
        # 'b' has 2 CWE matches (100 pts) vs 'a' with no match (0).
        assert "b" in {s.name for s in out}
        assert "a" not in {s.name for s in out}


# ---------------------------------------------------------------------------
# Combined — realistic /audit driver scenario
# ---------------------------------------------------------------------------


class TestRealistic:
    def test_audit_driver_with_full_context(self):
        """The likely shape of /audit Phase A's call: file path,
        function name, includes from inventory, callees from
        tree-sitter call graph, CWEs from /agentic finding (if any).

        With max=4, both CWE-pinned strategies and the call/include-
        matched ``concurrency`` get into the result set."""
        out = pick_strategies(
            file_path="net/foo/parser.c",
            function_name="parse_request",
            file_includes=["linux/skbuff.h", "linux/spinlock.h"],
            function_calls_made=["spin_lock", "skb_pull"],
            candidate_cwes=["CWE-119"],
            max_strategies=4,
        )
        names = [s.name for s in out]
        # general always first, then specialised.
        assert names[0] == "general"
        # input_handling fires on path + include + keyword + call +
        # the CWE-119 pin (it's classified there too).
        assert "input_handling" in names
        # memory_management also pinned on CWE-119.
        assert "memory_management" in names
        # concurrency fires on include + call (no CWE pin).
        assert "concurrency" in names

    def test_audit_driver_max3_prefers_cwe_pinned(self):
        """With max=3 and two CWE-pinned strategies, the picker
        prefers the CWE-pinned ones over a non-CWE-pinned third
        (concurrency loses despite having include + call signal).
        This is correct: a CWE pin is direct evidence; aggregated
        weak signals shouldn't outrank it."""
        out = pick_strategies(
            file_path="net/foo/parser.c",
            function_name="parse_request",
            file_includes=["linux/skbuff.h", "linux/spinlock.h"],
            function_calls_made=["spin_lock", "skb_pull"],
            candidate_cwes=["CWE-119"],
            max_strategies=3,
        )
        names = [s.name for s in out]
        assert names[0] == "general"
        assert "input_handling" in names
        assert "memory_management" in names
        assert "concurrency" not in names

    def test_tier1_doesnt_break_path_only_pick(self):
        """A purely path-based pick (no calls, no CWEs) still works."""
        out = pick_strategies(
            file_path="kernel/locking/rwsem.c",
            function_name="rwsem_acquire",
            max_strategies=3,
        )
        assert "concurrency" in {s.name for s in out}
