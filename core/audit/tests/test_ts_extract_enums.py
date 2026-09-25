"""Tests for the enum-definition / enum-switch extractors (C/C++).

The string dispatch extractor deliberately collects string-literal
case labels only; these extractors cover the enum side — identifier
labels, definition censuses, the ``default:`` idiom flag, the
per-definition member cap, and the nested-switch exclusion the
dispatch extractor already pins.
"""

from __future__ import annotations

import pytest

try:
    import tree_sitter  # noqa: F401
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
pytestmark = pytest.mark.skipif(
    not _HAS_TS, reason="tree-sitter not installed",
)

from core.audit.ts_extract import (  # noqa: E402
    MAX_ENUM_MEMBERS,
    extract_enum_definitions,
    extract_enum_switches,
)
from core.testing.treesitter import requires_ts  # noqa: E402

_ENUM_C = """\
enum pkt_kind {
    PKT_DATA,
    PKT_ACK = 5,
    PKT_RESET,
};

typedef enum {
    MODE_A,
    MODE_B,
} run_mode_t;
"""

_SWITCH_C = """\
int handle(enum pkt_kind k) {
    switch (k) {
    case PKT_DATA:
        return 1;
    case PKT_ACK:
        return 2;
    case PKT_RESET:
        return 3;
    }
    return 0;
}

int handle_partial(enum pkt_kind k) {
    switch (k) {
    case PKT_DATA:
        return 1;
    case PKT_ACK:
        return 2;
    default:
        return -1;
    }
}
"""


class TestEnumDefinitions:
    @requires_ts("c")
    def test_named_and_anonymous_definitions(self):
        defs = extract_enum_definitions("pkt.c", _ENUM_C)
        assert defs is not None
        by_name = {d.name: d for d in defs}
        assert by_name["pkt_kind"].members == [
            "PKT_DATA", "PKT_ACK", "PKT_RESET",
        ]
        anon = next(d for d in defs if d.name.startswith("<anon>@"))
        assert anon.members == ["MODE_A", "MODE_B"]
        assert not anon.caps_hit

    @requires_ts("c")
    def test_bare_reference_is_not_a_definition(self):
        defs = extract_enum_definitions(
            "use.c", "enum pkt_kind global_kind;\n",
        )
        assert defs == []

    @requires_ts("c")
    def test_member_cap_marks_caps_hit(self):
        members = ",\n".join(
            f"    M_{i:04d}" for i in range(MAX_ENUM_MEMBERS + 10)
        )
        src = f"enum flood {{\n{members}\n}};\n"
        defs = extract_enum_definitions("flood.c", src)
        assert defs is not None and len(defs) == 1
        assert len(defs[0].members) == MAX_ENUM_MEMBERS
        assert defs[0].caps_hit

    def test_unsupported_extension_returns_none(self):
        assert extract_enum_definitions("a.zig", _ENUM_C) is None

    @requires_ts("python")
    def test_non_c_language_returns_none(self):
        assert extract_enum_definitions("a.py", "x = 1\n") is None


def _nested_switch_tower(depth: int) -> str:
    """A switch-per-level tower — the nesting shape that made
    per-case ancestor re-attribution cubic in depth."""
    out = ["void f(int a) {\n"]
    for d in range(depth):
        out.append(f"switch (a) {{ case C{d}: ")
    out.append("h();")
    for d in range(depth):
        out.append(" case D%d: break; }" % d)
    out.append("\n}\n")
    return "".join(out)


class TestDepthGrowth:
    @requires_ts("c")
    def test_extraction_stays_near_linear_in_nesting_depth(self):
        # Growth-ratio pin: doubling the nesting depth must not
        # blow up extraction (the cubic shape measured ~8x per
        # doubling and ~100s of CPU on a 49KB depth-800 file in an
        # unbudgeted prep phase). Single-pass nearest-switch (and
        # nearest-function) attribution is ~linear; parse noise gets
        # generous slack, cubic still fails by an order.
        import time

        from core.audit.ts_extract import _PARSE_CACHE

        def cost(depth: int) -> float:
            src = _nested_switch_tower(depth)
            _PARSE_CACHE.clear()
            t0 = time.process_time()
            got = extract_enum_switches(f"d{depth}.c", src)
            assert got is not None and len(got) == depth
            return time.process_time() - t0

        cost(50)  # warm-up (imports, grammar load)
        small = max(cost(300), 0.005)
        large = cost(600)
        assert large <= 4 * small + 0.05, (small, large)


class TestEnumSwitches:
    @requires_ts("c")
    def test_labels_and_default_flag(self):
        sw = extract_enum_switches("pkt.c", _SWITCH_C)
        assert sw is not None
        by_fn = {s.function: s for s in sw}
        full = by_fn["handle"]
        assert full.labels == ["PKT_DATA", "PKT_ACK", "PKT_RESET"]
        assert full.has_default is False
        partial = by_fn["handle_partial"]
        assert partial.labels == ["PKT_DATA", "PKT_ACK"]
        assert partial.has_default is True

    @requires_ts("c")
    def test_non_identifier_labels_contribute_nothing(self):
        src = (
            "int f(int k) {\n"
            "    switch (k) {\n"
            "    case 1: return 1;\n"
            "    case 2: return 2;\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
        assert extract_enum_switches("num.c", src) == []

    @requires_ts("c")
    def test_single_label_switch_not_enum_shaped(self):
        src = (
            "int f(int k) {\n"
            "    switch (k) {\n"
            "    case PKT_DATA: return 1;\n"
            "    default: return 0;\n"
            "    }\n"
            "}\n"
        )
        assert extract_enum_switches("one.c", src) == []

    @requires_ts("c")
    def test_nested_switch_labels_stay_with_their_switch(self):
        src = (
            "int f(int a, int b) {\n"
            "    switch (a) {\n"
            "    case OUTER_A:\n"
            "        switch (b) {\n"
            "        case INNER_A: return 1;\n"
            "        case INNER_B: return 2;\n"
            "        }\n"
            "        return 3;\n"
            "    case OUTER_B: return 4;\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        )
        sw = extract_enum_switches("nest.c", src)
        assert sw is not None
        label_sets = sorted(tuple(s.labels) for s in sw)
        assert label_sets == [
            ("INNER_A", "INNER_B"),
            ("OUTER_A", "OUTER_B"),
        ]
