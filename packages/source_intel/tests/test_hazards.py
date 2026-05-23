"""Tests for axis-7 hazardous-code-pattern evidence."""

from __future__ import annotations

import shutil
from unittest.mock import patch

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.adapter import (
    SourceIntelValidator,
    _hazard_supports_finding,
)
from packages.source_intel.analyze import (
    HazardEvidence,
    SourceIntelResult,
    analyze,
)


def _finding(file_path: str, rule_id: str, sink_line: int = 5) -> Finding:
    return Finding(
        finding_id="t", producer="codeql",
        rule_id=rule_id, message="t",
        source=Step(file_path=file_path, line=1, column=1,
                    snippet="x", label="source"),
        sink=Step(file_path=file_path, line=sink_line, column=1,
                  snippet="x", label="sink"),
        intermediate_steps=(), raw={},
    )


# =====================================================================
# Real-spatch E2E — deprecated_functions rule
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_deprecated_functions_fires(tmp_path):
    src = tmp_path / "dep.c"
    src.write_text(
        "extern int strcpy(char *, const char *);\n"
        "extern int sprintf(char *, const char *, ...);\n"
        "\n"
        "void use(const char *s) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, s);\n"
        "    sprintf(buf, \"%s\", s);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    kinds = {(h.kind, h.detail) for h in r.hazards}
    assert ("deprecated_func", "strcpy") in kinds
    assert ("deprecated_func", "sprintf") in kinds


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_deprecated_skipped_for_strncpy(tmp_path):
    """strncpy carries its bounds argument; not in deprecated list."""
    src = tmp_path / "safe.c"
    src.write_text(
        "extern char *strncpy(char *, const char *, unsigned long);\n"
        "void op(const char *s) {\n"
        "    char buf[16];\n"
        "    strncpy(buf, s, 16);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert not any(
        h.detail == "strncpy" for h in r.hazards
        if h.kind == "deprecated_func"
    )


# =====================================================================
# Real-spatch E2E — signed_alloc rule
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_signed_alloc_fires(tmp_path):
    src = tmp_path / "signed.c"
    src.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "extern int recv_count(void);\n"
        "void *op(void) {\n"
        "    int n = recv_count();\n"
        "    return kmalloc(n * sizeof(int), 0);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    hits = [h for h in r.hazards if h.kind == "signed_alloc"]
    assert hits, f"expected signed_alloc evidence, got {r.hazards!r}"
    assert "kmalloc" in hits[0].detail


# =====================================================================
# Verdict policy — deprecated_func on cpp/unbounded-write
# =====================================================================


def test_deprecated_func_supports_unbounded_write_verdict(tmp_path):
    src = tmp_path / "f.c"
    src.write_text("void op(void){}\n")
    finding = _finding(str(src), "cpp/unbounded-write", sink_line=10)
    result = SourceIntelResult(hazards=(HazardEvidence(
        kind="deprecated_func", detail="strcpy",
        location=(str(src), 10), enclosing_function="op",
    ),))
    with patch("packages.source_intel.adapter.analyze",
               return_value=result):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.EXPLOITABLE


def test_deprecated_func_irrelevant_for_uaf(tmp_path):
    """UAF (CWE-416) findings — deprecated_func evidence is
    informational, not verdict-driving."""
    src = tmp_path / "f.c"
    src.write_text("void op(void){}\n")
    finding = _finding(str(src), "cpp/use-after-free", sink_line=10)
    result = SourceIntelResult(hazards=(HazardEvidence(
        kind="deprecated_func", detail="strcpy",
        location=(str(src), 10),
    ),))
    with patch("packages.source_intel.adapter.analyze",
               return_value=result):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_hazard_in_different_file_does_not_fire(tmp_path):
    src = tmp_path / "f.c"
    src.write_text("void op(void){}\n")
    finding = _finding(str(src), "cpp/unbounded-write", sink_line=10)
    result = SourceIntelResult(hazards=(HazardEvidence(
        kind="deprecated_func", detail="strcpy",
        location=("/other.c", 10),
    ),))
    with patch("packages.source_intel.adapter.analyze",
               return_value=result):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_hazard_far_from_sink_does_not_fire(tmp_path):
    """±3 line tolerance — hazard >3 lines away doesn't support."""
    src = tmp_path / "f.c"
    src.write_text("void op(void){}\n")
    finding = _finding(str(src), "cpp/unbounded-write", sink_line=10)
    result = SourceIntelResult(hazards=(HazardEvidence(
        kind="deprecated_func", detail="strcpy",
        location=(str(src), 20),  # 10 lines away
    ),))
    with patch("packages.source_intel.adapter.analyze",
               return_value=result):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_signed_alloc_supports_uncontrolled_alloc_verdict(tmp_path):
    src = tmp_path / "f.c"
    src.write_text("void op(void){}\n")
    finding = _finding(
        str(src), "cpp/uncontrolled-allocation-size", sink_line=10,
    )
    result = SourceIntelResult(hazards=(HazardEvidence(
        kind="signed_alloc", detail="kmalloc:n",
        location=(str(src), 10),
    ),))
    with patch("packages.source_intel.adapter.analyze",
               return_value=result):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.EXPLOITABLE


def test_hazard_helper_direct():
    """Direct test of _hazard_supports_finding logic."""
    finding = Finding(
        finding_id="t", producer="codeql",
        rule_id="cpp/unbounded-write", message="t",
        source=Step(file_path="/x.c", line=5, column=1,
                    snippet="x", label="source"),
        sink=Step(file_path="/x.c", line=5, column=1,
                  snippet="x", label="sink"),
        intermediate_steps=(), raw={},
    )
    match = SourceIntelResult(hazards=(HazardEvidence(
        kind="deprecated_func", detail="strcpy",
        location=("/x.c", 5),
    ),))
    assert _hazard_supports_finding(finding, match) is True

    wrong_file = SourceIntelResult(hazards=(HazardEvidence(
        kind="deprecated_func", detail="strcpy",
        location=("/other.c", 5),
    ),))
    assert _hazard_supports_finding(finding, wrong_file) is False
