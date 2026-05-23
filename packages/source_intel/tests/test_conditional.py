"""Tests for ``packages.source_intel.conditional``."""

from __future__ import annotations


import pytest

from packages.source_intel.conditional import (
    _index_file,
    clear_cache,
    enclosing_condition,
)


@pytest.fixture(autouse=True)
def _clear_cache_between_tests():
    """File-index cache is global; clear between tests so each test's
    file content is freshly parsed."""
    clear_cache()
    yield
    clear_cache()


# =====================================================================
# Skip / edge cases
# =====================================================================


def test_empty_file_path_returns_none():
    assert enclosing_condition("", 1) is None


def test_missing_file_returns_none(tmp_path):
    assert enclosing_condition(str(tmp_path / "no-such-file.c"), 1) is None


def test_zero_or_negative_line_returns_none(tmp_path):
    f = tmp_path / "x.c"
    f.write_text("int x;\n")
    assert enclosing_condition(str(f), 0) is None
    assert enclosing_condition(str(f), -5) is None


def test_unconditional_line_returns_none(tmp_path):
    """A line that's not inside any #if* block → None."""
    f = tmp_path / "plain.c"
    f.write_text("int x;\nint y;\nint z;\n")
    assert enclosing_condition(str(f), 2) is None


# =====================================================================
# Basic #if / #endif tracking
# =====================================================================


def test_simple_ifdef_block(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "int outside;\n"            # line 1
        "#ifdef CONFIG_FOO\n"       # line 2
        "int inside;\n"             # line 3
        "#endif\n"                  # line 4
        "int after;\n"              # line 5
    )
    assert enclosing_condition(str(f), 3) == "CONFIG_FOO"
    assert enclosing_condition(str(f), 1) is None
    assert enclosing_condition(str(f), 5) is None


def test_if_with_expression(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "#if defined(CONFIG_A) && !defined(CONFIG_B)\n"
        "int conditional;\n"
        "#endif\n"
    )
    assert (enclosing_condition(str(f), 2)
            == "defined(CONFIG_A) && !defined(CONFIG_B)")


def test_ifndef_block(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "#ifndef _GUARD_H\n"
        "int header_body;\n"
        "#endif\n"
    )
    assert enclosing_condition(str(f), 2) == "_GUARD_H"


# =====================================================================
# Nesting — innermost wins
# =====================================================================


def test_nested_blocks_innermost_returned(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "#ifdef OUTER\n"        # line 1
        "int outer_only;\n"     # line 2
        "#ifdef INNER\n"        # line 3
        "int both;\n"           # line 4
        "#endif\n"              # line 5
        "int outer_again;\n"    # line 6
        "#endif\n"              # line 7
    )
    assert enclosing_condition(str(f), 4) == "INNER"
    assert enclosing_condition(str(f), 2) == "OUTER"
    assert enclosing_condition(str(f), 6) == "OUTER"


def test_three_level_nesting(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "#ifdef A\n"        # 1
        "#ifdef B\n"        # 2
        "#ifdef C\n"        # 3
        "int deep;\n"       # 4
        "#endif\n"          # 5
        "#endif\n"          # 6
        "#endif\n"          # 7
    )
    assert enclosing_condition(str(f), 4) == "C"


# =====================================================================
# Adjacent blocks
# =====================================================================


def test_adjacent_blocks_independent(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "#ifdef A\n"        # 1
        "int a_block;\n"    # 2
        "#endif\n"          # 3
        "#ifdef B\n"        # 4
        "int b_block;\n"    # 5
        "#endif\n"          # 6
    )
    assert enclosing_condition(str(f), 2) == "A"
    assert enclosing_condition(str(f), 5) == "B"


# =====================================================================
# Malformed input
# =====================================================================


def test_unclosed_if_block_ignored(tmp_path):
    """Malformed source with #ifdef but no matching #endif — the
    block is not recorded; lookups return None within the unclosed
    region (rather than fabricating a synthetic block to EOF)."""
    f = tmp_path / "x.c"
    f.write_text(
        "#ifdef NEVER_CLOSED\n"
        "int inside;\n"
        # no #endif
    )
    # Implementation choice: drop unclosed blocks rather than synthesise
    # EOF. Test pins the contract.
    assert enclosing_condition(str(f), 2) is None


def test_stray_endif_ignored(tmp_path):
    """An #endif without a matching opener is silently ignored — same
    posture as malformed-source handling above."""
    f = tmp_path / "x.c"
    f.write_text(
        "int normal;\n"
        "#endif\n"
        "int after;\n"
    )
    assert enclosing_condition(str(f), 1) is None
    assert enclosing_condition(str(f), 3) is None


# =====================================================================
# #elif / #else continuation
# =====================================================================


def test_elif_inherits_outer_condition(tmp_path):
    """#elif is treated as continuation; the outer #if's condition is
    what's reported. v1 limitation — Stage D LLM consumer is aware."""
    f = tmp_path / "x.c"
    f.write_text(
        "#if defined(A)\n"      # 1
        "int a_branch;\n"        # 2
        "#elif defined(B)\n"     # 3
        "int b_branch;\n"        # 4
        "#endif\n"               # 5
    )
    # In v1, line 4 is reported as inside the #if A block. Reflects
    # the documented limitation; downstream may refine.
    assert enclosing_condition(str(f), 4) == "defined(A)"


# =====================================================================
# Indexing (cached parse)
# =====================================================================


def test_index_file_returns_blocks(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "#ifdef A\n"
        "int x;\n"
        "#endif\n"
    )
    blocks = _index_file(str(f))
    assert len(blocks) == 1
    assert blocks[0].start_line == 1
    assert blocks[0].end_line == 3
    assert blocks[0].condition == "A"
    assert blocks[0].directive == "ifdef"


def test_index_file_caches_across_calls(tmp_path):
    """Multiple lookups against the same file path hit the cache —
    we verify by mutating file contents and confirming the cached
    parse persists until ``clear_cache``."""
    f = tmp_path / "x.c"
    f.write_text("#ifdef A\nint x;\n#endif\n")
    first = _index_file(str(f))
    # Mutate file under the cache.
    f.write_text("#ifdef B\nint y;\n#endif\n")
    cached = _index_file(str(f))
    assert cached == first  # same tuple (cached)
    clear_cache()
    refreshed = _index_file(str(f))
    assert refreshed[0].condition == "B"
