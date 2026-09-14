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


def test_all_matching_occurrences_rewritten():
    """A per-TFM conditional duplicate (same locator twice at the old
    value) must have EVERY occurrence bumped — a first-match
    substitution bumped one and left its twin on the vulnerable
    version while reporting applied."""
    text = 'pkg="1.0"\nother="9.9"\npkg="1.0"\n'
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert result.applied is True
    assert new_text.count('pkg="2.0"') == 2
    assert 'pkg="1.0"' not in new_text
    assert result.reason == ""            # full apply, no strays


def test_later_occurrence_at_old_value_still_bumped():
    """First occurrence already bumped, second still vulnerable: the
    verdict must span all matches (old code value_mismatched on the
    first and touched nothing)."""
    text = 'pkg="2.0"\npkg="1.0"\n'
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert result.applied is True
    assert new_text.count('pkg="2.0"') == 2


def test_mixed_stray_value_reports_partial():
    text = 'pkg="1.0"\npkg="7.7"\n'
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert result.applied is True
    assert 'pkg="2.0"' in new_text and 'pkg="7.7"' in new_text
    assert result.reason.startswith("partial:")
    assert "7.7" in result.reason


def test_all_at_new_value_is_no_change():
    text = 'pkg="2.0"\npkg="2.0"\n'
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert result.applied is False
    assert result.reason == "no_change"
    assert new_text == text


def test_no_old_value_and_stray_is_value_mismatch():
    text = 'pkg="7.7"\n'
    edit = RewriteEdit(locator="pkg", old_value="1.0", new_value="2.0")
    new_text, result = apply_version_edit(text, edit, BUILDERS)
    assert result.applied is False
    assert "value_mismatch" in result.reason
    assert new_text == text
