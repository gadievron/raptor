"""Tests for axis-3 unchecked-allocation evidence (Phase 6a)."""

from __future__ import annotations

import shutil
from unittest.mock import patch

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.adapter import (
    SourceIntelValidator,
    _unchecked_alloc_supports_finding,
)
from packages.source_intel.analyze import (
    AllocationEvidence,
    SourceIntelResult,
    analyze,
)


def _finding(file_path: str, rule_id: str,
             source_line: int = 5) -> Finding:
    return Finding(
        finding_id="test",
        producer="codeql",
        rule_id=rule_id,
        message="test",
        source=Step(file_path=file_path, line=source_line, column=1,
                    snippet="x", label="source"),
        sink=Step(file_path=file_path, line=source_line + 1, column=1,
                  snippet="x", label="sink"),
        intermediate_steps=(),
        raw={},
    )


# =====================================================================
# Real-spatch E2E — fires on field-assignment shape
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_unchecked_alloc_field_fires(tmp_path):
    """The unchecked_alloc.cocci rule emits an AllocationEvidence
    record on `struct_p->field = alloc(...)` with no subsequent
    NULL check."""
    src = tmp_path / "unchecked.c"
    src.write_text(
        "extern char *kstrdup(const char *s, int gfp);\n"
        "struct prop { char *name; };\n"
        "\n"
        "int unchecked(const char *name, int gfp) {\n"
        "    struct prop *p;\n"
        "    p->name = kstrdup(name, gfp);\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert r.allocations, "expected at least one AllocationEvidence"
    ae = r.allocations[0]
    assert ae.allocator == "kstrdup"
    assert ae.target_field == "name"
    assert ae.shape == "field"


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_unchecked_alloc_local_fires_on_kstrdup(tmp_path):
    """Axis-3b (Phase 6b): local-variable assignment of an allocator
    return value with no NULL check — covers CVE-2019-12382 shape:
    `local = kstrdup(...)` followed by use without check."""
    src = tmp_path / "unchecked_local.c"
    # Note: declaration-with-initializer (`char *p = alloc(...);`) is
    # NOT matched by the current cocci pattern — spatch handles bare
    # `expression = ...` assignments only, not declarators. CVE-2019-12382
    # uses the bare-assignment shape, which is what we test here.
    src.write_text(
        "extern char *kstrdup(const char *s, int gfp);\n"
        "extern int strsep(char **, const char *);\n"
        "\n"
        "int unchecked_local(const char *name, int gfp) {\n"
        "    char *fwstr;\n"
        "    fwstr = kstrdup(name, gfp);\n"
        "    strsep(&fwstr, \",\");\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    locals_ = [a for a in r.allocations if a.shape == "local"]
    assert locals_, (
        f"expected at least one local-shape AllocationEvidence; got "
        f"{[(a.allocator, a.shape) for a in r.allocations]!r}"
    )
    assert locals_[0].allocator == "kstrdup"


def test_e2e_unchecked_alloc_skips_checked_case(tmp_path):
    """When the field IS NULL-checked after the alloc, the rule
    must NOT fire — `when !=` clauses correctly exclude checked
    paths."""
    src = tmp_path / "checked.c"
    src.write_text(
        "extern char *kstrdup(const char *s, int gfp);\n"
        "struct prop { char *name; };\n"
        "\n"
        "int checked(const char *name, int gfp) {\n"
        "    struct prop *p;\n"
        "    p->name = kstrdup(name, gfp);\n"
        "    if (!p->name) return -1;\n"
        "    return 0;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert not r.allocations, (
        f"expected zero AllocationEvidence on checked case; got "
        f"{r.allocations!r}"
    )


# =====================================================================
# Verdict policy
# =====================================================================


def test_unchecked_alloc_at_source_line_emits_exploitable(tmp_path):
    """A null-deref finding whose source line coincides with an
    unchecked-alloc site should verdict EXPLOITABLE."""
    src = tmp_path / "test.c"
    src.write_text("int f(void){return 0;}\n")
    finding = _finding(str(src), "cpp/null-dereference",
                       source_line=10)
    result = SourceIntelResult(allocations=(AllocationEvidence(
        allocator="kstrdup",
        location=(str(src), 10),
        shape="field",
        target_field="name",
        enclosing_function="f",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.EXPLOITABLE


def test_unchecked_alloc_far_from_source_does_not_fire(tmp_path):
    """Alloc 50 lines from the finding's source — within tolerance?
    Phase 6a uses ±3 lines so this should NOT fire."""
    src = tmp_path / "test.c"
    src.write_text("int f(void){return 0;}\n")
    finding = _finding(str(src), "cpp/null-dereference",
                       source_line=10)
    result = SourceIntelResult(allocations=(AllocationEvidence(
        allocator="kstrdup",
        location=(str(src), 50),
        shape="field",
        target_field="name",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_unchecked_alloc_irrelevant_for_uaf(tmp_path):
    """Axis-3 evidence only supports null-deref findings (CWE-476).
    A UAF finding (CWE-416) at the same line stays UNCERTAIN."""
    src = tmp_path / "test.c"
    src.write_text("int f(void){return 0;}\n")
    finding = _finding(str(src), "cpp/use-after-free",
                       source_line=10)
    result = SourceIntelResult(allocations=(AllocationEvidence(
        allocator="kstrdup",
        location=(str(src), 10),
        shape="field",
        target_field="name",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_unchecked_alloc_pure_helper():
    """Direct test of _unchecked_alloc_supports_finding."""
    finding = Finding(
        finding_id="t",
        producer="codeql",
        rule_id="cpp/null-dereference",
        message="t",
        source=Step(file_path="/tmp/foo.c", line=10, column=1,
                    snippet="x", label="source"),
        sink=Step(file_path="/tmp/foo.c", line=11, column=1,
                  snippet="x", label="sink"),
        intermediate_steps=(),
        raw={},
    )
    matching = SourceIntelResult(allocations=(AllocationEvidence(
        allocator="kstrdup",
        location=("/tmp/foo.c", 10),
        shape="field",
        target_field="name",
    ),))
    assert _unchecked_alloc_supports_finding(finding, matching) is True

    wrong_file = SourceIntelResult(allocations=(AllocationEvidence(
        allocator="kstrdup",
        location=("/tmp/other.c", 10),
        shape="field",
        target_field="name",
    ),))
    assert _unchecked_alloc_supports_finding(finding, wrong_file) is False
