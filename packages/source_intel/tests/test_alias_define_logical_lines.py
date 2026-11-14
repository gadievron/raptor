"""Macro discovery keeps definitions within joined logical lines."""

import pytest

from packages.source_intel.discovery import _DEFINE_RE, _join_continuations


def test_empty_definition_does_not_capture_next_declaration():
    text = "#define EMPTY\n__attribute__((warn_unused_result)) int owned(void);\n"
    assert [(m.group(1), m.group(2).strip()) for m in _DEFINE_RE.finditer(text)] == [("EMPTY", "")]


@pytest.mark.parametrize(
    "text, expected",
    [
        ("#define OWNED()__attribute__((warn_unused_result))", ("OWNED", "__attribute__((warn_unused_result))")),
        ("#define OWNED(x) __attribute__((nonnull(x)))", ("OWNED", "__attribute__((nonnull(x)))")),
        ("#define OWNED (x) warn_unused_result", ("OWNED", "(x) warn_unused_result")),
        ("#define OWNED", ("OWNED", "")),
        ("#define OWNED()", ("OWNED", "")),
        (" \t# \tdefine\tX\tvalue", ("X", "value")),
        ("#define OWNED \\\n __attribute__((warn_unused_result))", ("OWNED", "__attribute__((warn_unused_result))")),
    ],
    ids=["adjacent-function", "function-space", "object-parentheses", "empty-object", "empty-function", "horizontal-space", "joined-continuation"],
)
def test_definition_forms(text, expected):
    matches = list(_DEFINE_RE.finditer(_join_continuations(text)))
    assert [(m.group(1), m.group(2).strip()) for m in matches] == [expected]


@pytest.mark.parametrize("text", ["#\ndefine X warn_unused_result", "#define\nX warn_unused_result", "#define X(\narg) warn_unused_result", "#define X) warn_unused_result"],
                         ids=["directive-newline", "name-newline", "parameter-newline", "missing-separator"])
def test_unjoined_or_malformed_definition_is_not_invented(text):
    assert list(_DEFINE_RE.finditer(text)) == []
