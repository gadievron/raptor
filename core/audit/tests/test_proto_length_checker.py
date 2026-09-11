"""Tests for core.audit.proto_length_checker — hermetic, synthetic C.

The suppression direction is the dangerous one: only a comparison
that caps the length ABOVE may make an unbounded protocol length read
as bounded.
"""

from __future__ import annotations

from core.audit.proto_length_checker import (
    _var_has_upper_bound,
    check_proto_length,
)

# Classic recv → ntohs → malloc(len) → copy shape, with a slot for a
# guard between extraction and allocation.
_TEMPLATE = (
    "void handle(int fd, char *pkt) {\n"
    "    unsigned short len;\n"
    "    len = ntohs(*(unsigned short *)pkt);\n"
    "    %s\n"
    "    char *buf = malloc(len);\n"
    "    memcpy(buf, pkt + 2, len);\n"
    "}\n"
)


class TestUpperBoundDirection:
    def test_unbounded_length_detected(self):
        findings = check_proto_length("handle", _TEMPLATE % "")
        assert len(findings) == 1

    def test_copy_loop_bound_on_i_does_not_suppress(self):
        # `while (i < len)` bounds i, not len — symmetric acceptance
        # read it as an upper bound ON len and hid the bug behind its
        # own copy loop.
        guarded = _TEMPLATE % "int i = 0;\n    while (i < len) { i++; }"
        findings = check_proto_length("handle", guarded)
        assert len(findings) == 1

    def test_real_upper_bound_suppresses(self):
        guarded = _TEMPLATE % "if (len < 512) {"
        assert check_proto_length("handle", guarded) == []

    def test_reversed_operand_upper_bound_suppresses(self):
        guarded = _TEMPLATE % "if (512 >= len) {"
        assert check_proto_length("handle", guarded) == []

    def test_bail_check_suppresses(self):
        guarded = _TEMPLATE % "if (len > 512) { return; }"
        assert check_proto_length("handle", guarded) == []

    def test_lower_bound_does_not_suppress(self):
        guarded = _TEMPLATE % "if (len > 2) {"
        findings = check_proto_length("handle", guarded)
        assert len(findings) == 1

    def test_var_has_upper_bound_direction(self):
        src = "while (i < len) { }"
        assert _var_has_upper_bound(src, "len", len(src)) is None
        assert _var_has_upper_bound(src, "i", len(src)) == "len"
        src2 = "if (len <= 64) { }"
        assert _var_has_upper_bound(src2, "len", len(src2)) == "64"
