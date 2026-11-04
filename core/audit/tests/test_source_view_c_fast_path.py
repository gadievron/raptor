"""Fast C paths retain lexer transitions, diagnostics and preprocessing."""

import pytest

from core.audit.source_view import sanitized_view, sanitized_view_with_status
from core.testing.wallclock import cpu_budget


@pytest.mark.parametrize("path", ["a.c", "a.cpp", "a.inc"])
@pytest.mark.parametrize("keep_strings", [False, True])
def test_plain_c_code_is_preserved(path, keep_strings):
    source = "int café(int value) {\n    return value + 1;\n}\n"
    status = sanitized_view_with_status(source, path, keep_strings=keep_strings)
    assert status.text == source
    assert not status.ambiguous
    assert status.reasons == ()


@pytest.mark.parametrize("path", ["a.c", "a.cpp", "a.inc"])
def test_c_identity_still_processes_dead_preprocessor_regions(path):
    source = "#if 0\nint hidden;\n#else\nint visible;\n#endif\n"
    status = sanitized_view_with_status(source, path)
    assert "hidden" not in status.text
    assert "int visible;" in status.text
    assert len(status.text) == len(source)
    assert [i for i, c in enumerate(status.text) if c == "\n"] == [
        i for i, c in enumerate(source) if c == "\n"
    ]
    assert not status.ambiguous
    assert sanitized_view(source, path, keep_strings=True) == source


@pytest.mark.parametrize("path, source", [
    ("a.js", "const x = `hidden`; run();\n"),
    ("a.go", "var x = `hidden`; run();\n"),
    ("a.php", "<?php # hidden\nrun();\n"),
])
def test_other_grammars_keep_their_non_c_openers(path, source):
    view = sanitized_view(source, path)
    assert "hidden" not in view
    assert "run();" in view


def test_string_subclasses_keep_iteration_behavior():
    class CustomText(str):
        def __iter__(self):
            return iter("int y;")

    assert sanitized_view(CustomText("int x;"), "a.c") == "int y;"


@pytest.mark.parametrize("path", ["a.c", "a.cpp"])
@pytest.mark.parametrize("keep_strings", [False, True])
def test_ordinary_runs_preserve_comment_string_and_division_transitions(
    path, keep_strings,
):
    source = (
        "int value = numerator / denominator;\n"
        "// comment_hidden \\\ncontinued_hidden\n"
        'const char *text = "string_hidden /* data */";\n'
        "char separator = '/'; /* block_hidden */\n"
        'const char *raw = u8R"tag(raw_hidden // data)tag";\n'
        "int visible;\n"
    )
    status = sanitized_view_with_status(source, path, keep_strings=keep_strings)
    assert "numerator / denominator" in status.text
    assert "int visible;" in status.text
    for name in ["comment_hidden", "continued_hidden", "block_hidden"]:
        assert name not in status.text
    for name in ["string_hidden", "raw_hidden"]:
        assert (name in status.text) is keep_strings
    assert len(status.text) == len(source)
    assert not status.ambiguous


@pytest.mark.parametrize("path", ["a.c", "a.cpp"])
def test_skipping_plain_prefix_retains_unterminated_raw_string_diagnostics(path):
    status = sanitized_view_with_status('auto text = R"tag(unfinished', path)
    assert status.ambiguous
    assert "unterminated-raw-string" in status.reasons


def test_large_c_ordinary_runs_complete_within_cpu_budget():
    source = "/* license */\n" + "".join(
        f"extern int value_{i};\n" for i in range(100000)
    )
    with cpu_budget(0.5, what="C ordinary-text scanning"):
        status = sanitized_view_with_status(source, "generated.h")
    assert "license" not in status.text
    assert "extern int value_0;" in status.text
    assert "extern int value_99999;" in status.text
    assert len(status.text) == len(source)
    assert not status.ambiguous
