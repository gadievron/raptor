"""Printable-string shortcut matches the legacy character-by-character escape."""

import pytest

from core.security.log_sanitisation import _escape_char, escape_nonprintable


def legacy_escape(text, preserve):
    return "".join(c if c.isprintable() or (preserve and c in ("\n", "\t"))
                   else _escape_char(c) for c in text)


@pytest.mark.parametrize("preserve", [False, True])
def test_all_unicode_blocks_match_legacy(preserve):
    # Cover all codepoints (including surrogates/unassigned characters)
    # in bounded mixed strings, across every Unicode category boundary.
    for start in range(0, 0x110000, 256):
        text = "".join(map(chr, range(start, start + 256)))
        assert escape_nonprintable(text, preserve_newlines=preserve) == legacy_escape(text, preserve)


@pytest.mark.parametrize("text", [
    "", "ordinary title / src/module.c:123", "éλληνικά 中文 🙂", "a\n\tb",
    "prefix" * 100 + "\x1b[31m\u202e\x00", "\ud800\u00a0\u200d\u2028",
])
@pytest.mark.parametrize("preserve", [False, True])
def test_report_and_control_strings_match(text, preserve):
    assert escape_nonprintable(text, preserve_newlines=preserve) == legacy_escape(text, preserve)


def test_string_subclass_keeps_iteration_semantics():
    class Special(str):
        def __iter__(self):
            return iter("\x1b")

        def isprintable(self):
            raise AssertionError("whole-string shortcut must not inspect subclasses")

    assert escape_nonprintable(Special("plain")) == "\\x1b"


def test_non_boolean_flag_keeps_truthiness_semantics():
    class Flag:
        def __bool__(self):
            raise RuntimeError("legacy flag validation")

    with pytest.raises(RuntimeError, match="legacy flag validation"):
        escape_nonprintable("plain", preserve_newlines=Flag())
