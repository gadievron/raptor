"""Parent metadata retains textual identity instead of coercing values."""

import pytest

from core.dataflow.cvefix_loader import _single_parent


@pytest.mark.parametrize("parent", [1234567, True, None, [], {}, "", "   "])
def test_nontext_or_blank_parent_is_declined(parent):
    assert _single_parent(repr([parent])) is None


@pytest.mark.parametrize("parent", ["a" * 40, "abc1234", "abc"])
@pytest.mark.parametrize("container", [list, tuple])
def test_single_text_parent_retains_exact_identity(parent, container):
    assert _single_parent(repr(container([parent]))) == parent


@pytest.mark.parametrize("parents", ["[]", "['a', 'b']", "invalid", None])
def test_existing_root_merge_and_parse_refusals_remain(parents):
    assert _single_parent(parents) is None
