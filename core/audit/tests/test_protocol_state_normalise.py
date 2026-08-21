"""Field-chain normalisation tests for the protocol-state channel.

Hermetic (no tree-sitter, no z3): ``_bare_fields`` is pure string
work. The timing cases are regression tests for the superlinear
backtracking the old ``(?:ident(?:->|.))+name`` regex exhibited on
long access chains — guard-condition strings are not truncated
before substitution and the per-invariant budget is only checked
between sites, so one pathological condition stalled the harness.
"""

from __future__ import annotations

import time

from core.audit.protocol_state import _bare_fields


class TestBareFieldsSemantics:
    def test_arrow_chain_collapses(self):
        assert _bare_fields("st->largest_acked_pkt", {"largest_acked_pkt"}) \
            == "largest_acked_pkt"

    def test_dot_chain_collapses(self):
        assert _bare_fields("a.b.field", {"field"}) == "field"

    def test_bare_name_untouched(self):
        assert _bare_fields("field", {"field"}) == "field"

    def test_mixed_expression(self):
        assert _bare_fields(
            "x->y + s->len <= s->cap", {"len", "cap"},
        ) == "x->y + len <= cap"

    def test_whitespace_around_separator(self):
        assert _bare_fields("s -> len", {"len"}) == "len"

    def test_name_as_chain_component(self):
        assert _bare_fields("a.name.b.name", {"name"}) == "name"

    def test_partial_identifier_not_stripped(self):
        assert _bare_fields("foo.barname", {"name"}) == "foo.barname"

    def test_longest_name_wins(self):
        assert _bare_fields(
            "s->len_max <= s->len", {"len", "len_max"},
        ) == "len_max <= len"


class TestBareFieldsTiming:
    def test_long_chain_with_match_is_fast(self):
        text = "a." * 16000 + "name"  # ~32k chars
        t0 = time.monotonic()
        out = _bare_fields(text, {"name"})
        assert time.monotonic() - t0 < 1.0
        assert out == "name"

    def test_long_chain_without_match_is_fast(self):
        text = "a." * 16000 + "other"
        t0 = time.monotonic()
        out = _bare_fields(text, {"name"})
        assert time.monotonic() - t0 < 1.0
        assert out == text

    def test_repeated_name_chain_is_fast(self):
        text = "name." * 6000 + "name"
        t0 = time.monotonic()
        out = _bare_fields(text, {"name"})
        assert time.monotonic() - t0 < 1.0
        assert out == "name"
