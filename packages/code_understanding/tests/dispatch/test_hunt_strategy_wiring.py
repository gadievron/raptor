"""Tests for the cwe_strategies wire-in into /understand --hunt's user
message.

When the operator-supplied hunt pattern carries a CWE id or recognisable
bug-class vocabulary, the matching cwe_strategies bug-class lenses get
appended to the user message after the ``</pattern>`` close, giving the
hunt model decision support for variant enumeration.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from packages.code_understanding.dispatch.hunt_dispatch import (
    _build_hunt_strategy_block,
    _format_user_message,
)


# ---------------------------------------------------------------------------
# CWE-id pin → strategy
# ---------------------------------------------------------------------------


class TestCweTriggersStrategy:
    def test_cwe_22_pins_input_handling(self):
        out = _format_user_message("CWE-22 in upload handler")
        assert "## Strategy: input_handling" in out
        # input_handling's CVE exemplar.
        assert "CVE-2023-0179" in out

    def test_cwe_416_pins_memory_management(self):
        out = _format_user_message("CWE-416 in cleanup paths")
        assert "## Strategy: memory_management" in out

    def test_cwe_362_pins_concurrency(self):
        out = _format_user_message("CWE-362 race in rwsem path")
        assert "## Strategy: concurrency" in out

    def test_cwe_id_case_insensitive(self):
        # ``cwe-22`` lower-case still triggers the pin.
        out = _format_user_message("cwe-22 in api/upload.py")
        assert "## Strategy: input_handling" in out

    def test_multiple_cwes_all_considered(self):
        # Use CWEs unique to one strategy each so the picker's tie-
        # breaking doesn't drop one — CWE-22 lives only in
        # input_handling; CWE-401 (memory leak) lives only in
        # memory_management.
        out = _format_user_message("CWE-22 with CWE-401 fallthrough")
        assert "## Strategy: input_handling" in out
        assert "## Strategy: memory_management" in out


# ---------------------------------------------------------------------------
# Keyword-only fall-through (no CWE in pattern)
# ---------------------------------------------------------------------------


class TestKeywordTriggersStrategy:
    def test_use_after_free_natural_language_pins_memory_management(self):
        out = _format_user_message("use after free in cleanup_buf")
        assert "## Strategy: memory_management" in out

    def test_parse_keyword_pins_input_handling(self):
        # The picker tokenises and exact-matches keywords, so the
        # natural-language pattern needs an actual ``parse`` /
        # ``decode`` / ``unmarshal`` / etc. token to trigger
        # input_handling without a CWE id.
        out = _format_user_message(
            "parse user input without validation in request handler",
        )
        assert "## Strategy: input_handling" in out

    def test_mutex_lock_keyword_pins_concurrency(self):
        out = _format_user_message("mutex_lock without matching unlock")
        assert "## Strategy: concurrency" in out


# ---------------------------------------------------------------------------
# Fall-through: no recognised signals → general only (still fires)
# ---------------------------------------------------------------------------


class TestNoSignalFallthrough:
    def test_pattern_with_no_signals_still_includes_general(self):
        # The picker's ``general`` strategy is always pinned, so even a
        # signal-less pattern produces a non-empty block.
        out = _format_user_message("xyz")
        assert "Bug-class lenses for this hunt" in out
        # General strategy is the always-on fallback.
        assert "## Strategy: general" in out


# ---------------------------------------------------------------------------
# Robustness: substrate failures must not break the hunt
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_substrate_import_failure_returns_base_message(self):
        """If core/llm/cwe_strategies isn't importable, the hunt
        dispatch must still produce a usable user message."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "core.llm.cwe_strategies":
                raise ImportError("substrate missing")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", fake_import):
            out = _format_user_message("CWE-22")
            # Base message intact, no strategy block.
            assert "<pattern>" in out
            assert "</pattern>" in out
            assert "Bug-class lenses" not in out

    def test_picker_exception_returns_base_message(self):
        def boom(**kwargs):
            raise RuntimeError("simulated picker failure")

        with patch("core.llm.cwe_strategies.pick_strategies", boom):
            out = _format_user_message("CWE-22")
            assert "<pattern>" in out
            assert "Bug-class lenses" not in out

    def test_render_exception_returns_base_message(self):
        def boom(*args, **kwargs):
            raise RuntimeError("simulated render failure")

        with patch("core.llm.cwe_strategies.render_strategies", boom):
            out = _format_user_message("CWE-22")
            assert "<pattern>" in out
            assert "Bug-class lenses" not in out

    def test_hostile_cwe_with_fake_heading_no_injection(self):
        """A pattern injecting a fake heading via newline must not echo
        a bare ``## INJECTED`` heading inside the strategy block. The
        pattern itself sits inside ``<pattern>`` delimiters (data zone);
        the strategy block above is separate operator-trusted content."""
        out = _format_user_message("CWE-22\n## INJECTED")
        # Pattern goes inside <pattern>...</pattern> as data; the
        # `<pattern>` block contains the user text verbatim — that's
        # the existing data-zone contract, not introduced here. Verify
        # the strategy block (which is OUTSIDE the pattern delimiters)
        # contains no fake heading copied from the pattern.
        bug_pos = out.index("Bug-class lenses for this hunt")
        block = out[bug_pos:]
        assert "## INJECTED" not in block

    def test_huge_cwe_id_doesnt_blow_up_message(self):
        # Five-digit cap on the CWE_RE caps the length even of hostile
        # ids; six-or-more-digit strings simply don't match. Pattern
        # echoes verbatim into the data zone (operator-supplied),
        # which is fine — the strategy block stays small.
        out = _format_user_message("CWE-" + "9" * 50_000)
        bug_pos = out.find("Bug-class lenses for this hunt")
        if bug_pos != -1:
            block = out[bug_pos:]
            assert len(block) < 16_000


# ---------------------------------------------------------------------------
# Strategy block placement (after </pattern>, not inside)
# ---------------------------------------------------------------------------


class TestStrategyBlockPlacement:
    def test_strategy_block_after_pattern_close(self):
        """The strategy block must sit AFTER ``</pattern>`` so the model
        treats the bug-class lenses as trusted operator instructions
        rather than continuation of the pattern data zone."""
        out = _format_user_message("CWE-22 in upload")
        pat_close = out.index("</pattern>")
        bug_pos = out.index("Bug-class lenses for this hunt")
        assert bug_pos > pat_close


# ---------------------------------------------------------------------------
# E2E — different patterns produce demonstrably different lenses
# ---------------------------------------------------------------------------


class TestE2EDistinctStrategies:
    def test_path_traversal_vs_uaf_produce_different_blocks(self):
        out_path = _format_user_message("CWE-22 in upload handler")
        out_uaf = _format_user_message("CWE-416 in cleanup_buf")

        # The two outputs are demonstrably distinct — the wire-in is
        # actually shaping the message, not adding a fixed boilerplate.
        assert out_path != out_uaf
        assert "input_handling" in out_path
        assert "memory_management" in out_uaf


# ---------------------------------------------------------------------------
# Size bounds
# ---------------------------------------------------------------------------


class TestSizeBounds:
    def test_full_signal_stack_stays_bounded(self):
        """Worst-case: pattern with multiple CWE ids + keywords spanning
        all three core bug classes. Picker caps at max_strategies=3
        plus ``general``, render output stays manageable."""
        pattern = (
            "CWE-22 path traversal, CWE-416 use after free, CWE-362 "
            "concurrent mutex_lock without unlock — looking for any "
            "shape combining sanitization + free + locking issues"
        )
        out = _format_user_message(pattern)
        # Even with multiple strategy matches + verbose pattern, total
        # bounded.
        assert len(out) < 24_000


# ---------------------------------------------------------------------------
# _build_hunt_strategy_block direct unit tests
# ---------------------------------------------------------------------------


class TestStrategyBlockDirect:
    def test_returns_empty_when_substrate_missing(self):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "core.llm.cwe_strategies":
                raise ImportError("substrate missing")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", fake_import):
            assert _build_hunt_strategy_block("CWE-89") == ""

    def test_returns_block_with_cwe_pin(self):
        block = _build_hunt_strategy_block("CWE-89 SQL injection")
        assert "## Strategy: input_handling" in block
        assert "Bug-class lenses for this hunt" in block

    def test_returns_block_with_keyword_only(self):
        # No CWE id at all, but ``mutex_lock`` keyword pins concurrency.
        block = _build_hunt_strategy_block("mutex_lock followed by sleep")
        assert "## Strategy: concurrency" in block

    def test_empty_pattern_returns_block_with_general_only(self):
        # Empty pattern → no signals → ``general`` always-on still
        # produces a block. Pin behaviour so a future change is
        # intentional.
        block = _build_hunt_strategy_block("")
        assert "## Strategy: general" in block
