"""Tests for core.audit.heap_copy_checker — hermetic, synthetic C.

The suppression direction is the dangerous one: a comparison that
does not actually bound the copy length must never make an unchecked
copy read as checked.
"""

from __future__ import annotations

from core.audit.heap_copy_checker import (
    check_cross_function,
    check_decompiled_function,
    _is_bounds_checked,
)


def _findings(source: str):
    return check_decompiled_function("f", source, file="t.c")


class TestBoundsCheckOperators:
    _COPY = (
        "void f(char *src, int count) {\n"
        "    char *buf = malloc(64);\n"
        "    %s\n"
        "    memcpy(buf, src, count);\n"
        "}\n"
    )

    def test_inequality_zero_does_not_suppress(self):
        # `if (count != 0)` bounds nothing — it used to read as a
        # bounds check and suppress the unchecked memcpy.
        src = self._COPY % "if (count != 0) {"
        assert len(_findings(src)) == 1

    def test_equality_does_not_suppress(self):
        src = self._COPY % "if (count == 4) {"
        assert len(_findings(src)) == 1

    def test_lower_bound_does_not_suppress(self):
        # `count > 0` caps nothing above.
        src = self._COPY % "if (count > 0) {"
        assert len(_findings(src)) == 1

    def test_upper_bound_constant_suppresses(self):
        src = self._COPY % "if (count < 32) {"
        assert _findings(src) == []

    def test_upper_bound_reversed_operands_suppresses(self):
        src = self._COPY % "if (32 > count) {"
        assert _findings(src) == []

    def test_exact_limit_either_direction_suppresses(self):
        # Compared against the limit expression itself: `count < 64`
        # guards the copy, `count > 64` guards a bail — both are a
        # check against the right quantity.
        for guard in ("if (count < 64) {", "if (count > 64) return;"):
            src = self._COPY % guard
            assert _findings(src) == [], guard

    def test_oversized_constant_bound_does_not_suppress(self):
        src = self._COPY % "if (count < 4096) {"
        assert len(_findings(src)) == 1

    def test_is_bounds_checked_direct(self):
        src = "if (n != 0) { memcpy(dst, s, n); }"
        assert not _is_bounds_checked(src, "n", "64", src.index("memcpy"))
        src2 = "if (n < 64) { memcpy(dst, s, n); }"
        assert _is_bounds_checked(src2, "n", "64", src2.index("memcpy"))


class TestConstantMismatch:
    def test_constant_overflow_detected(self):
        src = (
            "void f(char *src) {\n"
            "    char *buf = malloc(16);\n"
            "    memcpy(buf, src, 64);\n"
            "}\n"
        )
        f = _findings(src)
        assert len(f) == 1
        assert f[0].confidence == "high"

    def test_constant_fit_clean(self):
        src = (
            "void f(char *src) {\n"
            "    char *buf = malloc(64);\n"
            "    memcpy(buf, src, 16);\n"
            "}\n"
        )
        assert _findings(src) == []


class TestCrossFunction:
    def _funcs(self, callee_body: str):
        return [
            {
                "name": "caller",
                "decompilation": (
                    "void caller(char *src) {\n"
                    "    char *buf = malloc(64);\n"
                    "    fill(buf, src);\n"
                    "}\n"
                ),
            },
            {
                "name": "fill",
                "decompilation": (
                    "void fill(char *param_1, char *param_2) {\n"
                    f"    {callee_body}\n"
                    "}\n"
                ),
            },
        ]

    def test_callee_copy_into_param_detected(self):
        # The headline scenario: caller allocates, callee copies into
        # the parameter.  The old filter only accepted callee-local
        # allocation findings, so this matched nothing (dead code).
        findings = check_cross_function(
            self._funcs("memcpy(param_1, param_2, 128);"),
        )
        assert len(findings) == 1
        assert findings[0].is_cross_function
        assert "caller" in findings[0].evidence
        assert findings[0].confidence == "high"

    def test_callee_unchecked_variable_length_detected(self):
        findings = check_cross_function(
            self._funcs("memcpy(param_1, param_2, n);"),
        )
        assert len(findings) == 1
        assert findings[0].confidence == "medium"

    def test_callee_fitting_copy_clean(self):
        findings = check_cross_function(
            self._funcs("memcpy(param_1, param_2, 32);"),
        )
        assert findings == []

    def test_callee_strcpy_into_param_detected(self):
        findings = check_cross_function(
            self._funcs("strcpy(param_1, param_2);"),
        )
        assert len(findings) == 1
        assert findings[0].copy_call == "strcpy"

    def test_unknown_alloc_size_is_inconclusive(self):
        funcs = self._funcs("memcpy(param_1, param_2, 128);")
        funcs[0]["decompilation"] = (
            "void caller(char *src, int n) {\n"
            "    char *buf = malloc(n);\n"
            "    fill(buf, src);\n"
            "}\n"
        )
        assert check_cross_function(funcs) == []
