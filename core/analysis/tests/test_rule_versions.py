"""Per-rule requirements never disable otherwise compatible rules."""

from unittest.mock import Mock

import pytest

from core.analysis.rule_versions import rule_version_refusal, version_tuple


@pytest.mark.parametrize("actual", ["1.3", "1.3.0", "1.4 compiled with OCaml", "v2.0.0"])
def test_compatible_release(actual):
    assert rule_version_refusal("// raptor-min-version: 1.3.0\n@r@", lambda: actual) is None


@pytest.mark.parametrize("actual", [None, "unknown", "1.3.0-rc1", "1.2.99"])
def test_incompatible_or_unknown_release(actual):
    reason = rule_version_refusal("// raptor-min-version: 1.3.0\n@r@", lambda: actual)
    assert reason and "rule skipped" in reason and "1.3.0" in reason


def test_undeclared_rule_does_not_probe():
    probe = Mock(side_effect=AssertionError("unneeded probe"))
    assert rule_version_refusal("// plain rule\n@r@\n@@\nfoo()", probe) is None
    probe.assert_not_called()


@pytest.mark.parametrize("header", [
    "// raptor-min-version: newest", "// raptor-min-version: 1.3",
    "// raptor-min-version: 1.3.0\n// raptor-min-version: 1.3.0",
    "// raptor-min-version: 1.3.0\u202e",
])
def test_invalid_declaration_is_not_ignored(header):
    assert rule_version_refusal(header + "\n@r@", lambda: "9.0.0")


def test_metadata_is_only_read_from_leading_comments():
    assert rule_version_refusal('select "// raptor-min-version: 99.0.0"', Mock()) is None


def test_version_parser_is_bounded():
    assert version_tuple("1" * 2000) is None


def test_bom_does_not_hide_a_requirement():
    assert rule_version_refusal("\ufeff// raptor-min-version: 2.0.0\nselect 1", lambda: "1.0.0")
