"""Contract tests for the shared ``apply_version_edit`` driver."""

from __future__ import annotations

import re

from packages.sca.rewriters import RewriteEdit, apply_version_edit


def _attr_pattern(locator: str) -> re.Pattern:
    return re.compile(
        rf'{re.escape(locator)}="(?P<version>[^"]+)"',
    )


def _child_pattern(locator: str) -> re.Pattern:
    return re.compile(
        rf"<{re.escape(locator)}>(?P<version>[^<]+)</{re.escape(locator)}>",
    )


BUILDERS = (_attr_pattern, _child_pattern)


def test_first_matching_pattern_wins():
    text = 'pkg="1.0"\n<pkg>1.0</pkg>\n'
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert result.applied is True
    # Only the attribute occurrence (first builder) is rewritten.
    assert new_text == 'pkg="2.0"\n<pkg>1.0</pkg>\n'


def test_fallback_to_later_builder():
    text = "<pkg>1.0</pkg>\n"
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert result.applied is True
    assert new_text == "<pkg>2.0</pkg>\n"


def test_value_mismatch_leaves_text_untouched():
    text = 'pkg="1.5"\n'
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert new_text == text
    assert result.applied is False
    assert result.reason.startswith("value_mismatch")
    assert "'1.5'" in result.reason and "'1.0'" in result.reason


def test_mismatch_on_first_match_does_not_fall_through():
    # The first builder that MATCHES decides; a later builder with the
    # expected old value must not rescue the edit.
    text = 'pkg="1.5"\n<pkg>1.0</pkg>\n'
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert new_text == text
    assert result.applied is False
    assert result.reason.startswith("value_mismatch")


def test_not_found_when_no_pattern_matches():
    text = 'other="1.0"\n'
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert new_text == text
    assert result.applied is False
    assert result.reason == "not_found"


def test_result_carries_the_edit():
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    _, result = apply_version_edit("", edit, BUILDERS)
    assert result.edit is edit
