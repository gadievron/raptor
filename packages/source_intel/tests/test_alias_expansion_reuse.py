"""Scalar alias-expansion controls; no target or preprocessor execution."""

import pytest

from packages.source_intel import discovery


def test_repeated_tokens_reuse_expansion_in_same_context(monkeypatch):
    actual = discovery._resolve_expansion
    calls = []

    def counted(expansion, macros, *, depth, visited=None):
        calls.append((expansion, depth, visited))
        return actual(expansion, macros, depth=depth, visited=visited)

    monkeypatch.setattr(discovery, "_resolve_expansion", counted)
    output = counted("A A A A", {"A": "B B", "B": "warn_unused_result"}, depth=0)
    assert output == " ".join(["warn_unused_result"] * 8)
    assert len(calls) == 3


@pytest.mark.parametrize("text,macros,depth,visited,expected", [
    ("A A", {"A": "A"}, 0, None, "A A"),
    ("A A", {"A": "B", "B": "A"}, 0, None, "A A"),
    ("A B", {"A": "B", "B": "A"}, 0, None, "A B"),
    ("A A", {"A": "B", "B": "nonnull"}, 3, None, "A A"),
    ("A A", {"A": "B", "B": "nonnull"}, 2, None, "B B"),
    ("A A", {"A": "B", "B": "nonnull"}, 0, {"A"}, "A A"),
    ("AA A A0", {"A": "nonnull"}, 0, None, "AA nonnull A0"),
    ("A + B + A", {"A": "", "B": "nonnull"}, 0, None, " + nonnull + "),
])
def test_expansion_preserves_depth_cycles_and_token_boundaries(
    text, macros, depth, visited, expected,
):
    assert discovery._resolve_expansion(text, macros, depth=depth, visited=visited) == expected


def test_expansion_memo_does_not_escape_call_or_mutate_visited():
    macros = {"A": "nonnull"}
    visited = {"unrelated"}
    assert discovery._resolve_expansion("A A", macros, depth=0, visited=visited) == "nonnull nonnull"
    macros["A"] = "warn_unused_result"
    assert discovery._resolve_expansion("A A", macros, depth=0, visited=visited) == "warn_unused_result warn_unused_result"
    assert visited == {"unrelated"}
