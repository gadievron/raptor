"""Tests for the shared numeric-coercion helpers."""

from __future__ import annotations

import math

from core.llm.coerce import (
    extract_fenced_code,
    structured_result,
    to_float_safe,
    to_int_safe,
)


class TestToIntSafe:
    def test_int_passthrough(self):
        assert to_int_safe(42) == 42
        assert to_int_safe(0) == 0
        assert to_int_safe(-5) == -5

    def test_bool_coerces_via_int_subclass(self):
        # Python bool subclasses int so ``isinstance(True, int) is True``.
        # ``to_int_safe`` doesn't add a special-case; it treats bools as
        # ints. Callers that consider bool a caller error should route
        # through a stricter helper (``sanitize_cost`` does).
        assert to_int_safe(True) == 1
        assert to_int_safe(False) == 0

    def test_none_short_circuits_to_default(self):
        assert to_int_safe(None) == 0
        assert to_int_safe(None, default=42) == 42

    def test_empty_string_short_circuits_to_default(self):
        assert to_int_safe("") == 0
        assert to_int_safe("", default=99) == 99

    def test_whitespace_string_coerces_via_int(self):
        # ``int(" 42 ") == 42`` — Python's own strip inside int(str).
        assert to_int_safe(" 42 ") == 42

    def test_float_string_falls_to_default(self):
        # ``int("42.5")`` raises ValueError; treated as bad value.
        assert to_int_safe("42.5") == 0
        assert to_int_safe("42.5", default=-1) == -1

    def test_float_value_truncates(self):
        # ``int(42.9) == 42`` — matches Python's own semantics.
        assert to_int_safe(42.9) == 42

    def test_on_error_fires_only_for_bad_value_not_none_or_empty(self):
        # None/"" hit the short-circuit — callback should NOT fire.
        seen: list[object] = []
        assert to_int_safe(None, on_error=lambda v, d: seen.append(("none", v))) == 0
        assert to_int_safe("", on_error=lambda v, d: seen.append(("empty", v))) == 0
        assert seen == []

        # Bad value → callback fires with the raw value and default.
        assert to_int_safe("bogus", default=7, on_error=lambda v, d: seen.append((v, d))) == 7
        assert seen == [("bogus", 7)]

    def test_list_falls_to_default(self):
        assert to_int_safe([1, 2, 3]) == 0


class TestToFloatSafe:
    def test_float_passthrough(self):
        assert to_float_safe(1.5) == 1.5
        assert to_float_safe(0.0) == 0.0
        assert to_float_safe(-3.14) == -3.14

    def test_int_coerces_to_float(self):
        assert to_float_safe(42) == 42.0
        assert isinstance(to_float_safe(42), float)

    def test_none_short_circuits_to_default(self):
        assert to_float_safe(None) == 0.0
        assert to_float_safe(None, default=1.5) == 1.5

    def test_empty_string_short_circuits_to_default(self):
        assert to_float_safe("") == 0.0

    def test_numeric_string_coerces(self):
        assert to_float_safe("42.5") == 42.5
        assert to_float_safe(" 0.05 ") == 0.05

    def test_nan_string_produces_nan(self):
        # ``float("nan")`` returns NaN — ``to_float_safe`` does NOT
        # clamp. Callers that need finite-only values must layer
        # ``math.isfinite`` themselves (or use ``sanitize_cost``).
        result = to_float_safe("nan")
        assert math.isnan(result)

    def test_inf_string_produces_inf(self):
        assert to_float_safe("inf") == float("inf")

    def test_bogus_string_falls_to_default(self):
        assert to_float_safe("bogus", default=-1.0) == -1.0

    def test_on_error_fires_only_for_bad_value_not_none_or_empty(self):
        seen: list[object] = []
        assert to_float_safe(None, on_error=lambda v, d: seen.append(("none", v))) == 0.0
        assert to_float_safe("", on_error=lambda v, d: seen.append(("empty", v))) == 0.0
        assert seen == []

        assert to_float_safe("bogus", default=2.5, on_error=lambda v, d: seen.append((v, d))) == 2.5
        assert seen == [("bogus", 2.5)]

    def test_list_falls_to_default(self):
        assert to_float_safe([1.0, 2.0]) == 0.0


class TestStructuredResult:
    """The one spelling of the ``.result``-or-tuple unwrap idiom."""

    def test_structured_response_object(self):
        from core.llm.providers import StructuredResponse
        resp = StructuredResponse(result={"a": 1}, raw="raw")
        assert structured_result(resp) == {"a": 1}

    def test_bare_tuple_from_stub(self):
        assert structured_result(({"a": 1}, "raw")) == {"a": 1}

    def test_already_unwrapped_dict(self):
        assert structured_result({"a": 1}) == {"a": 1}

    def test_none_gives_default(self):
        assert structured_result(None) is None
        assert structured_result(None, default={}) == {}

    def test_unindexable_gives_default(self):
        assert structured_result(object(), default={}) == {}

    def test_empty_tuple_gives_default_not_raise(self):
        # The hand-rolled ``response[0]`` copies relied on an enclosing
        # broad try; the shared helper must not raise.
        assert structured_result((), default={}) == {}


class TestExtractFencedCode:
    """First-block extractor for freeform code replies (NOT JSON —
    that's strip_json_fences' last-block, injection-hardened job)."""

    def test_no_fence_passthrough_stripped(self):
        assert extract_fenced_code("  predicate x()  ") == "predicate x()"

    def test_multiline_block_drops_language_tag(self):
        text = "prose\n```ql\npredicate isBarrier() { any() }\n```\nmore"
        assert extract_fenced_code(text) == "predicate isBarrier() { any() }"

    def test_multiline_block_bare_fence(self):
        text = "```\n{\"kind\": \"other\"}\n```"
        assert extract_fenced_code(text) == '{"kind": "other"}'

    def test_single_line_block_strips_leading_tag(self):
        assert extract_fenced_code("```ql exists(x)```") == "exists(x)"

    def test_first_block_wins(self):
        text = "```\nfirst\n```\nmiddle\n```\nsecond\n```"
        assert extract_fenced_code(text) == "first"

    def test_trailing_backticks_stripped(self):
        # The tier1 copy's rstrip("`") — kept in the union behaviour.
        text = "```json\n{\"k\": 1}```"
        assert extract_fenced_code(text) == '{"k": 1}'

    def test_none_and_empty(self):
        assert extract_fenced_code("") == ""
        assert extract_fenced_code(None) == ""  # type: ignore[arg-type]


class TestAsPair:
    def test_as_pair_matches_iter_unpack(self):
        from core.llm.providers import StructuredResponse
        resp = StructuredResponse(result={"a": 1}, raw="text")
        r1, raw1 = resp  # legacy 2-tuple unpack
        assert resp.as_pair() == (r1, raw1) == ({"a": 1}, "text")
