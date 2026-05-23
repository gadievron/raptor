"""Tests for ``packages.source_intel.analyze``.

Covers skip-silent paths, parse logic, alias-scan augmentation, and
a real-spatch E2E test that exercises the shipped
``attr_warn_unused_result.cocci`` rule against a tiny C fixture.
"""

from __future__ import annotations

import shutil
from unittest.mock import MagicMock, patch

import pytest

from packages.source_intel.analyze import (
    SCHEMA_VERSION,
    SourceIntelResult,
    WurEvidence,
    _parse_match_to_wur,
    _scan_alias_in_file,
    analyze,
)


# =====================================================================
# Data shape invariants
# =====================================================================


def test_default_result_is_safe_default():
    r = SourceIntelResult()
    assert r.schema_version == SCHEMA_VERSION
    assert r.target == ""
    assert r.rules_executed == ()
    assert r.rules_failed == ()
    assert r.wur_functions == ()
    assert r.skipped_reason is None
    assert r.is_skipped is False


def test_skipped_marks_is_skipped():
    r = SourceIntelResult(skipped_reason="spatch_not_available")
    assert r.is_skipped is True


def test_function_has_wur_returns_observation():
    ev = WurEvidence(
        function_name="foo",
        location=("a.c", 10),
        match_source="literal",
        raw_match="__attribute__((warn_unused_result))",
    )
    r = SourceIntelResult(attributes=(ev,))
    assert r.function_has_wur("foo") is ev
    assert r.function_has_wur("bar") is None


# =====================================================================
# Skip paths
# =====================================================================


def test_analyze_skips_when_spatch_missing(tmp_path):
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    with patch(
        "packages.coccinelle.runner.is_available",
        return_value=False,
    ):
        r = analyze(tmp_path)
    assert r.skipped_reason == "spatch_not_available"


def test_analyze_skips_for_pure_python_target(tmp_path):
    (tmp_path / "app.py").write_text("# python only\n")
    with patch(
        "packages.coccinelle.runner.is_available",
        return_value=True,
    ):
        r = analyze(tmp_path)
    assert r.skipped_reason == "no_c_cpp_source"


def test_analyze_skips_when_rules_dir_missing(tmp_path):
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    with patch(
        "packages.coccinelle.runner.is_available",
        return_value=True,
    ), patch(
        "packages.source_intel.analyze._shipped_rules_root",
        return_value=None,
    ):
        r = analyze(tmp_path)
    assert r.skipped_reason == "rules_dir_missing"


def test_analyze_accepts_single_c_file_target(tmp_path):
    """Single-file target — common when scanning a fixture sample."""
    src = tmp_path / "single.c"
    src.write_text("int main(void){return 0;}\n")
    with patch(
        "packages.coccinelle.runner.is_available",
        return_value=False,  # short-circuit before spatch call
    ):
        r = analyze(src)
    # The reason is spatch_not_available — meaning we DID get past
    # the C-source check on the single-file path.
    assert r.skipped_reason == "spatch_not_available"


# =====================================================================
# Match parsing
# =====================================================================


def _make_match(file_path: str, line: int, message: str):
    m = MagicMock()
    m.file = file_path
    m.line = line
    m.message = message
    return m


def test_parse_match_extracts_wur_from_message():
    m = _make_match("src/a.c", 42, "wur:my_func")
    evs = _parse_match_to_wur(m)
    assert len(evs) == 1
    assert evs[0].function_name == "my_func"
    assert evs[0].location == ("src/a.c", 42)
    assert evs[0].match_source == "literal"


def test_parse_match_ignores_non_wur_messages():
    m = _make_match("src/a.c", 1, "alloc:other_data")
    assert _parse_match_to_wur(m) == []


def test_parse_match_ignores_empty_wur_payload():
    m = _make_match("src/a.c", 1, "wur:")
    assert _parse_match_to_wur(m) == []


# =====================================================================
# Alias scanning
# =====================================================================


def test_alias_scan_finds_kernel_must_check(tmp_path):
    f = tmp_path / "kernel_style.c"
    f.write_text(
        "#include <linux/types.h>\n"
        "static __must_check int validate(int x) { return x > 0; }\n"
    )
    observations = _scan_alias_in_file(f)
    assert len(observations) == 1
    assert observations[0].match_source == "known_alias"
    assert observations[0].raw_match == "__must_check"
    # Phase B post-E2E: function-name extractor (post-fix #2) binds
    # the alias to the nearest non-decoration, non-uppercase
    # `<name>(` token. Was empty in the original ship; now extracts
    # `validate` from `static __must_check int validate(int x)`.
    assert observations[0].function_name == "validate"


def test_alias_scan_finds_cpp_nodiscard(tmp_path):
    f = tmp_path / "cpp_style.cpp"
    f.write_text(
        "[[nodiscard]] int compute(int x) { return x; }\n"
    )
    observations = _scan_alias_in_file(f)
    assert len(observations) == 1
    assert observations[0].raw_match == "[[nodiscard]]"


def test_alias_scan_emits_one_observation_per_distinct_spelling(tmp_path):
    """Two different alias spellings → two observations (because each
    may apply to a different function)."""
    f = tmp_path / "mixed.c"
    f.write_text(
        "static __must_check int a(void) { return 0; }\n"
        "static __wur int b(void) { return 0; }\n"
    )
    observations = _scan_alias_in_file(f)
    spellings = {o.raw_match for o in observations}
    assert spellings == {"__must_check", "__wur"}


def test_alias_scan_skips_non_c_files(tmp_path):
    """Best-effort scan only walks C/H files."""
    py = tmp_path / "ignore.py"
    py.write_text("# __must_check this should be ignored\n")
    from packages.source_intel.analyze import _scan_alias_observations
    observations = _scan_alias_observations(tmp_path)
    assert observations == []


# =====================================================================
# Real-spatch E2E
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_detects_literal_wur(tmp_path):
    """End-to-end: real spatch runs the shipped attr_warn_unused_result
    rule against a small C file with a literal GCC attribute. Pin
    against rule-corpus drift."""
    src = tmp_path / "literal.c"
    src.write_text(
        "#include <stddef.h>\n"
        "__attribute__((warn_unused_result))\n"
        "int alloc_thing(size_t sz);\n"
    )

    r = analyze(tmp_path)
    assert not r.is_skipped, (
        f"expected real spatch to produce facts; got skipped_reason="
        f"{r.skipped_reason!r}"
    )
    # The cocci rule should emit ``wur:alloc_thing`` for the function.
    function_names = {
        ev.function_name for ev in r.wur_functions
        if ev.match_source == "literal"
    }
    assert "alloc_thing" in function_names, (
        f"attr_warn_unused_result rule didn't fire on literal "
        f"GCC syntax; got: {list(r.wur_functions)!r}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_detects_literal_nonnull(tmp_path):
    """End-to-end: real spatch runs the shipped attr_nonnull rule
    against a small C file with nonnull declarations in three forms
    (bare, paramised, internal-alias). Pin against rule-corpus drift
    and the multi-variant disjunction in the cocci rule."""
    src = tmp_path / "nonnull_fixture.c"
    src.write_text(
        "__attribute__((nonnull)) int bare(int *p);\n"
        "__attribute__((nonnull(1))) int paramised(int *p, int q);\n"
        "__attribute__((__nonnull__(1, 2))) int internal(int *a, int *b);\n"
    )

    r = analyze(tmp_path)
    assert not r.is_skipped
    from packages.source_intel.analyze import KIND_NONNULL
    nn_obs = r.attrs_of_kind(KIND_NONNULL)
    names = {ev.function_name for ev in nn_obs if ev.match_source == "literal"}
    assert names == {"bare", "paramised", "internal"}, (
        f"attr_nonnull rule didn't fire on all three forms; "
        f"got: {names!r}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_detects_literal_alloc_size(tmp_path):
    """Both pointer-return and value-return alloc_size variants
    detected, including the __alloc_size__ internal alias."""
    src = tmp_path / "alloc_size_fixture.c"
    src.write_text(
        "__attribute__((alloc_size(1))) void *my_malloc(int sz);\n"
        "__attribute__((alloc_size(1, 2))) void *my_calloc(int n, int sz);\n"
        "__attribute__((__alloc_size__(1))) char *gimme(unsigned long n);\n"
    )

    r = analyze(tmp_path)
    from packages.source_intel.analyze import KIND_ALLOC_SIZE
    names = {ev.function_name for ev in r.attrs_of_kind(KIND_ALLOC_SIZE)
             if ev.match_source == "literal"}
    assert names == {"my_malloc", "my_calloc", "gimme"}, (
        f"attr_alloc_size rule didn't fire on all three variants; "
        f"got: {names!r}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_detects_literal_returns_nonnull(tmp_path):
    """Both literal and __returns_nonnull__ internal alias detected."""
    src = tmp_path / "rn_fixture.c"
    src.write_text(
        "__attribute__((returns_nonnull)) void *must_succeed(void);\n"
        "__attribute__((__returns_nonnull__)) char *strdup_or_die(const char *s);\n"
    )

    r = analyze(tmp_path)
    from packages.source_intel.analyze import KIND_RETURNS_NONNULL
    names = {ev.function_name for ev in r.attrs_of_kind(KIND_RETURNS_NONNULL)
             if ev.match_source == "literal"}
    assert names == {"must_succeed", "strdup_or_die"}, (
        f"attr_returns_nonnull rule didn't fire on all forms; "
        f"got: {names!r}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_detects_axis1_completion_kinds(tmp_path):
    """End-to-end across the 4 axis-1-completion attribute rules
    (noreturn, malloc, no_stack_protector, access). Pins the
    multi-rule axis-dispatch loop + ALL_KINDS membership for the
    expanded attribute set."""
    src = tmp_path / "all_attrs.c"
    src.write_text(
        "__attribute__((noreturn)) void panic_fn(const char *m);\n"
        "__attribute__((__noreturn__)) void exit_fn(int code);\n"
        "__attribute__((malloc)) void *my_alloc(int sz);\n"
        "__attribute__((__malloc__)) void *my_zalloc(int sz);\n"
        "__attribute__((no_stack_protector)) void critical_fn(void);\n"
        "__attribute__((__no_stack_protector__)) void other_crit(void);\n"
        "__attribute__((access(read_only, 1))) int ro_fn(const int *p);\n"
        "__attribute__((access(write_only, 1, 2))) int wo_fn(int *buf, int n);\n"
    )

    r = analyze(tmp_path)
    from packages.source_intel.analyze import (
        KIND_ACCESS, KIND_MALLOC, KIND_NO_STACK_PROTECTOR, KIND_NORETURN,
    )

    by_kind = {kind: set() for kind in (
        KIND_NORETURN, KIND_MALLOC, KIND_NO_STACK_PROTECTOR, KIND_ACCESS,
    )}
    for ev in r.attributes:
        if ev.match_source != "literal":
            continue
        if ev.kind in by_kind:
            by_kind[ev.kind].add(ev.function_name)

    assert by_kind[KIND_NORETURN] == {"panic_fn", "exit_fn"}
    assert by_kind[KIND_MALLOC] == {"my_alloc", "my_zalloc"}
    assert by_kind[KIND_NO_STACK_PROTECTOR] == {"critical_fn", "other_crit"}
    assert by_kind[KIND_ACCESS] == {"ro_fn", "wo_fn"}


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_captures_conditional_on_for_ifdef_wrapped_attr(tmp_path):
    """A WUR-annotated function under #ifdef must surface ``conditional_on``.

    Stage D consumer uses this to downweight matches behind unknown
    config — without it, the LLM might infer hardening when the
    actual build excluded the attribute."""
    src = tmp_path / "wrapped.c"
    src.write_text(
        "#ifdef CONFIG_HARDENING\n"
        "__attribute__((warn_unused_result))\n"
        "int alloc_thing(int sz);\n"
        "#endif\n"
    )

    r = analyze(tmp_path)
    from packages.source_intel.conditional import clear_cache
    clear_cache()
    wur = [ev for ev in r.attributes
           if ev.kind == "wur" and ev.match_source == "literal"]
    assert wur, "expected a literal WUR observation"
    assert wur[0].conditional_on == "CONFIG_HARDENING", (
        f"expected conditional_on='CONFIG_HARDENING'; got "
        f"{wur[0].conditional_on!r}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_discovers_project_alias_and_emits_project_alias_evidence(tmp_path):
    """Target with a project-defined __must_check alias — discovery
    finds the macro, alias-scan emits ``match_source='project_alias'``
    evidence for source files where the macro is used."""
    (tmp_path / "compiler.h").write_text(
        "#define MY_MUST_CHECK __attribute__((__warn_unused_result__))\n"
    )
    (tmp_path / "lib.c").write_text(
        "MY_MUST_CHECK int validate(int x);\n"
    )

    r = analyze(tmp_path)
    # Discovery should surface in result.
    discovered = dict(r.discovered_aliases)
    assert "MY_MUST_CHECK" in discovered.get("wur", ())

    # Project-alias evidence should be emitted for the source file.
    project_aliases = [ev for ev in r.attributes
                       if ev.match_source == "project_alias"]
    assert any(ev.raw_match == "MY_MUST_CHECK" for ev in project_aliases), (
        f"expected MY_MUST_CHECK project-alias observation; "
        f"got: {project_aliases!r}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_axis_dispatch_runs_multiple_rules(tmp_path):
    """When the target has both WUR and nonnull annotations, BOTH
    rules in the attrs/ axis fire — confirms the axis-dir iteration
    correctly drives all rules per axis."""
    src = tmp_path / "mixed.c"
    src.write_text(
        "__attribute__((warn_unused_result)) int alloc(int sz);\n"
        "__attribute__((nonnull)) int validate(int *p);\n"
    )

    r = analyze(tmp_path)
    from packages.source_intel.analyze import KIND_NONNULL, KIND_WUR
    wur_names = {
        ev.function_name for ev in r.attrs_of_kind(KIND_WUR)
        if ev.match_source == "literal"
    }
    nn_names = {
        ev.function_name for ev in r.attrs_of_kind(KIND_NONNULL)
        if ev.match_source == "literal"
    }
    assert "alloc" in wur_names
    assert "validate" in nn_names
