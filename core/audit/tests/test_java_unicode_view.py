"""Java translation ambiguity preserves raw view coordinates and hits."""
import pytest

from core.audit.source_view import sanitized_view_with_status
from core.source.java_unicode import java_unicode_unverified

PREFIX = chr(92) + "u000a"
REASON = "java_unicode_translation_unverified"
SOURCE = "class T { void handle() {\n // " + PREFIX + " marker = 1;\n value.matches(\"[a-z]+\");\n} }\n"


@pytest.mark.parametrize("language,file_path", [("java", ""), (None, "App.JAVA")])
@pytest.mark.parametrize("keep_strings", [False, True])
def test_view_reports_translation_without_rewriting_source(language, file_path, keep_strings):
    view = sanitized_view_with_status(SOURCE, file_path, language=language, keep_strings=keep_strings)
    assert view.ambiguous
    assert REASON in view.reasons
    assert len(view.text) == len(SOURCE)
    assert [i for i, char in enumerate(view.text) if char == "\n"] == [
        i for i, char in enumerate(SOURCE) if char == "\n"]
    assert "value.matches" in view.text


def test_prefilter_guard_cannot_vouch_for_ambiguous_java_source():
    from core.audit.prefilter import PrefilterResult, _GuardViews

    result = PrefilterResult(file="App.java", function="handle", language="java")
    views = _GuardViews(result, SOURCE)
    assert "value.matches" in views.code
    assert views.vouch is False
    assert views.sees(r"value\.matches") is False


def test_other_languages_do_not_inherit_java_translation_rules():
    assert not java_unicode_unverified("# " + PREFIX, language="python", file_path="App.java")
    assert not java_unicode_unverified("// " + PREFIX, language="javascript")
    assert not java_unicode_unverified('String note = "π";', language="java")
