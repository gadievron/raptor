"""The preprocessor fast path is a necessary-prefix check, never a verdict."""

import pytest

from core.audit.source_view import _blank_if0_regions, sanitized_view_with_status
from core.testing.wallclock import cpu_budget


@pytest.mark.parametrize("condition", [
    "0", "00", "(0)", "(( 0 ))", "0x0", "0X000uL", "000ULL",
    "\t(((\t00Lu )))\t",
])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_zero_spellings_still_blank_the_region(condition, newline):
    source = f"# \tif {condition}\nint hidden;\n#endif\nint visible;\n"
    source = source.replace("\n", newline)
    status = sanitized_view_with_status(source, "a.c")
    assert "hidden" not in status.text
    assert "int visible;" in status.text
    assert len(status.text) == len(source)
    assert [i for i, ch in enumerate(status.text) if ch == "\n"] == [
        i for i, ch in enumerate(source) if ch == "\n"
    ]
    assert not status.ambiguous


@pytest.mark.parametrize("condition", [
    "FEATURE", "defined(FEATURE)", "1", "0 || FEATURE", "0u || FEATURE",
    "(0) + FEATURE", "0x10", "1 && 0",
])
def test_nonzero_and_build_dependent_conditions_stay_visible(condition):
    source = f"#if {condition}\nint visible;\n#endif\n"
    assert _blank_if0_regions(source) == source


def test_nested_conditionals_and_elif_keep_the_existing_depth_rules():
    source = (
        "#ifndef GUARD\n#define GUARD\n#if 0\nint hidden;\n"
        "#if OTHER\nint nested_hidden;\n#endif\n"
        "#elif ALT\nint visible;\n#endif\n#endif\n"
    )
    status = sanitized_view_with_status(source, "a.cpp")
    assert "hidden" not in status.text
    assert "int visible;" in status.text
    assert len(status.text) == len(source)
    assert not status.ambiguous


def test_string_subclasses_keep_split_behavior():
    class CustomView(str):
        def split(self, *args, **kwargs):
            return ["#if 0", "hidden", "#endif"]

    assert _blank_if0_regions(CustomView("plain")) == "     \n      \n      "


def test_guarded_header_without_zero_conditions_stays_within_cpu_budget():
    source = "#ifndef GUARD\n#define GUARD\n" + "".join(
        f"extern int value_{i};\n" for i in range(100000)
    ) + "#endif\n"
    with cpu_budget(0.2, what="guarded-header preprocessor scanning"):
        for _ in range(5):
            status = sanitized_view_with_status(source, "generated.h")
    assert status.text == source
    assert not status.ambiguous
