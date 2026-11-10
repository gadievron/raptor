"""Context anchors cannot silently fall back to primary-only admission."""

import re

import pytest

from core.audit.source_anchor import (
    context_source_anchor_version,
    make_context_source_anchor,
    make_source_anchor,
    parse_context_source_anchor,
    parse_source_anchor,
)


PRIMARY = "a" * 64
SPAN = "b" * 12
DEPENDENCY = "c" * 64


def test_context_anchor_exposes_all_inputs_and_preserves_primary_parser_api():
    value = make_context_source_anchor(PRIMARY, SPAN, DEPENDENCY)

    assert value == f"src:ctx1:{PRIMARY}:{SPAN}:{DEPENDENCY}"
    assert parse_context_source_anchor(value) == (PRIMARY, SPAN, DEPENDENCY)
    assert parse_source_anchor(value) == (PRIMARY, SPAN)


def test_predecessor_exact_parser_refuses_context_anchor():
    # The predecessor's exact grammar is deliberately retained here. A new
    # context-dependent record must not become primary-only coverage on downgrade.
    predecessor = re.compile(r"src:([0-9a-f]{64}):([0-9a-f]{12})")

    assert predecessor.fullmatch(make_source_anchor(PRIMARY, SPAN))
    assert predecessor.fullmatch(make_context_source_anchor(PRIMARY, SPAN, DEPENDENCY)) is None
    assert predecessor.fullmatch(make_context_source_anchor(PRIMARY, SPAN, None)) is None


def test_unknown_dependency_is_distinct_from_legacy_anchor():
    value = make_context_source_anchor(PRIMARY, SPAN, None)

    assert value.endswith(":unknown")
    assert parse_context_source_anchor(value) == (PRIMARY, SPAN, None)
    assert parse_source_anchor(value) == (PRIMARY, SPAN)
    assert parse_context_source_anchor(make_source_anchor(PRIMARY, SPAN)) is None


@pytest.mark.parametrize("value", [
    None, 1, {}, "", f"src:ctx3:{PRIMARY}:{SPAN}:{DEPENDENCY}",
    f"src:ctx1:{PRIMARY.upper()}:{SPAN}:{DEPENDENCY}",
    f"src:ctx1:{PRIMARY}:{SPAN.upper()}:{DEPENDENCY}",
    f"src:ctx1:{PRIMARY}:{SPAN}:{DEPENDENCY.upper()}",
    f"src:ctx1:{PRIMARY[:-1]}:{SPAN}:{DEPENDENCY}",
    f"src:ctx1:{PRIMARY}:{SPAN[:-1]}:{DEPENDENCY}",
    f"src:ctx1:{PRIMARY}:{SPAN}:{DEPENDENCY[:-1]}",
    f"src:ctx1:{PRIMARY}:{SPAN}:UNKNOWN",
    f"src:ctx1:{PRIMARY}:{SPAN}:{DEPENDENCY}\n",
    f"src:ctx1:{PRIMARY}:{SPAN}:{DEPENDENCY}:extra",
])
def test_malformed_context_anchor_has_no_primary_fallback(value):
    assert parse_context_source_anchor(value) is None
    assert context_source_anchor_version(value) is None
    assert parse_source_anchor(value) is None


@pytest.mark.parametrize("primary,span,dependency", [
    (PRIMARY[:-1], SPAN, DEPENDENCY),
    (PRIMARY, SPAN[:-1], DEPENDENCY),
    (PRIMARY, SPAN, DEPENDENCY[:-1]),
    (PRIMARY, SPAN, "UNKNOWN"),
])
def test_context_anchor_maker_refuses_malformed_inputs(primary, span, dependency):
    with pytest.raises(ValueError):
        make_context_source_anchor(primary, span, dependency)


def test_legacy_maker_cannot_be_used_to_construct_context_form():
    with pytest.raises(ValueError):
        make_source_anchor(f"ctx1:{PRIMARY}", f"{SPAN}:{DEPENDENCY}")


def test_legacy_roundtrip_stays_exact():
    value = make_source_anchor(PRIMARY, SPAN)

    assert value == f"src:{PRIMARY}:{SPAN}"
    assert parse_source_anchor(value) == (PRIMARY, SPAN)
    assert parse_context_source_anchor(value) is None


@pytest.mark.parametrize("dependency", [DEPENDENCY, None], ids=["known", "unknown"])
def test_rooted_context_anchor_preserves_primary_and_dependency_tuple(dependency):
    value = make_context_source_anchor(PRIMARY, SPAN, dependency, context_version=2)

    assert value == f"src:ctx2:{PRIMARY}:{SPAN}:{dependency or 'unknown'}"
    assert parse_context_source_anchor(value) == (PRIMARY, SPAN, dependency)
    assert parse_source_anchor(value) == (PRIMARY, SPAN)
    assert context_source_anchor_version(value) == 2


def test_ctx1_predecessor_refuses_rooted_context_contract():
    predecessor = re.compile(r"src:ctx1:([0-9a-f]{64}):([0-9a-f]{12}):([0-9a-f]{64}|unknown)")

    assert predecessor.fullmatch(make_context_source_anchor(PRIMARY, SPAN, DEPENDENCY))
    assert predecessor.fullmatch(make_context_source_anchor(PRIMARY, SPAN, DEPENDENCY, context_version=2)) is None
    assert predecessor.fullmatch(make_context_source_anchor(PRIMARY, SPAN, None, context_version=2)) is None


def test_context_version_is_explicit_and_legacy_has_none():
    assert context_source_anchor_version(make_source_anchor(PRIMARY, SPAN)) is None
    assert context_source_anchor_version(make_context_source_anchor(PRIMARY, SPAN, DEPENDENCY)) == 1
    assert context_source_anchor_version(make_context_source_anchor(PRIMARY, SPAN, None)) == 1


@pytest.mark.parametrize("version", [None, True, False, 0, 3, "2", 2.0])
def test_context_anchor_maker_refuses_unknown_or_coerced_versions(version):
    with pytest.raises(ValueError):
        make_context_source_anchor(PRIMARY, SPAN, DEPENDENCY, context_version=version)


@pytest.mark.parametrize("value", [
    f"src:ctx2:{PRIMARY.upper()}:{SPAN}:{DEPENDENCY}",
    f"src:ctx2:{PRIMARY}:{SPAN.upper()}:{DEPENDENCY}",
    f"src:ctx2:{PRIMARY}:{SPAN}:{DEPENDENCY.upper()}",
    f"src:ctx2:{PRIMARY[:-1]}:{SPAN}:{DEPENDENCY}",
    f"src:ctx2:{PRIMARY}:{SPAN[:-1]}:{DEPENDENCY}",
    f"src:ctx2:{PRIMARY}:{SPAN}:{DEPENDENCY[:-1]}",
    f"src:ctx2:{PRIMARY}:{SPAN}:UNKNOWN",
    f"src:ctx2:{PRIMARY}:{SPAN}:{DEPENDENCY}\n",
    f"src:ctx2:{PRIMARY}:{SPAN}:{DEPENDENCY}:extra",
])
def test_malformed_rooted_anchor_has_no_primary_or_version_fallback(value):
    assert parse_context_source_anchor(value) is None
    assert context_source_anchor_version(value) is None
    assert parse_source_anchor(value) is None
