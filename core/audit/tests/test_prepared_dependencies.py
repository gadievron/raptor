"""Declared depfile grammar controls; no compiler or capture authority."""

import pytest

from core.audit.prepared_dependencies import DependencyOutputUnavailable, parse_dependency_output


def parse(raw, *, cap=4096, count=16):
    return parse_dependency_output(raw, expected_target="capture_unit", max_bytes=cap,
                                   max_dependencies=count)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_owned_target_compiler_continuations_preserve_order_and_deduplicate(ending):
    raw = b"capture_unit: unit.c " + bytes((92,)) + ending + b" include/owned.h unit.c" + ending
    assert parse(raw) == ("unit.c", "include/owned.h")


def test_escaped_path_characters_and_dollars_are_declarations_only():
    assert parse(br"capture_unit: dir\ space/a.c hash\#name.h colon\:name.h back\\name.h cost$$.h") == (
        "dir space/a.c", "hash#name.h", "colon:name.h", "back\\name.h", "cost$.h")


def test_paths_are_not_normalised_confined_or_claimed_complete():
    assert parse(b"capture_unit: ../unproven.h /outside/not-read.h src/./unit.c") == (
        "../unproven.h", "/outside/not-read.h", "src/./unit.c")


def test_comments_and_blank_lines_do_not_add_dependencies():
    assert parse(b"# preface\ncapture_unit: unit.c # metadata\n\n# end\n") == ("unit.c",)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_continued_comment_cannot_supply_an_apparent_dependency_rule(ending):
    raw = b"# continued comment " + bytes((92,)) + ending + b"capture_unit: unit.c" + ending
    with pytest.raises(DependencyOutputUnavailable, match="dependency_comment_continuation"):
        parse(raw)


@pytest.mark.parametrize("raw", [
    b"", b"unit.c", b"capture_unit:", b"other: unit.c",
    b"capture_unit second: unit.c", b"capture_unit:: unit.c", b"capture_unit\n: unit.c",
    b"capture_unit: unit.c\nheader.h:\n", b"capture_unit: unit.c\nnext: more.h",
    b"capture_unit: unit.c\\", b"capture_unit: unit.c\r",
    b"capture_unit: bad\x00.h", b"capture_unit: bad\x7f.h", b"capture_unit: \xff.h",
    br"capture_unit: path\q.h", b"capture_unit: $(FORGED)", b"capture_unit: $x",
    b"capture_unit: end$", b"capture_unit: first.h | order.h", b"capture_unit: x;command",
    b"capture_unit: *.h", b"capture_unit: name=metadata", b"capture_unit: windows:header.h",
])
def test_malformed_or_unsupported_rule_refuses_whole_result(raw):
    with pytest.raises(DependencyOutputUnavailable):
        parse(raw)


def test_exact_byte_budget_is_allowed_but_no_prefix_result_is_returned():
    raw = b"capture_unit: unit.c"
    assert parse(raw, cap=len(raw)) == ("unit.c",)
    with pytest.raises(DependencyOutputUnavailable, match="dependency_byte_budget"):
        parse(raw, cap=len(raw) - 1)


def test_count_budget_counts_repeated_declarations_before_deduplication():
    assert parse(b"capture_unit: unit.c unit.c", count=2) == ("unit.c",)
    with pytest.raises(DependencyOutputUnavailable, match="dependency_count_budget"):
        parse(b"capture_unit: unit.c unit.c", count=1)


@pytest.mark.parametrize("budget", [True, None, 0, -1, 1.5])
def test_budgets_are_explicit_positive_integers(budget):
    with pytest.raises(DependencyOutputUnavailable, match="invalid_dependency_budget"):
        parse(b"capture_unit: unit.c", cap=budget)
    with pytest.raises(DependencyOutputUnavailable, match="invalid_dependency_budget"):
        parse(b"capture_unit: unit.c", count=budget)


@pytest.mark.parametrize("target", ["", "../target", "two targets", "$(TARGET)", "a:b"])
def test_capture_owned_target_has_no_make_grammar(target):
    with pytest.raises(DependencyOutputUnavailable, match="invalid_expected_target"):
        parse_dependency_output(b"capture_unit: unit.c", expected_target=target,
                                max_bytes=4096, max_dependencies=16)
