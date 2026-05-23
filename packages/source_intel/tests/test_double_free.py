"""Tests for axis-3 double-free detection."""

from __future__ import annotations

import shutil
from unittest.mock import patch

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.adapter import (
    SourceIntelValidator,
    _double_free_supports_finding,
)
from packages.source_intel.analyze import (
    DoubleFreeEvidence,
    SourceIntelResult,
    analyze,
)


def _finding(file_path: str, sink_line: int,
             rule_id: str = "cpp/double-free") -> Finding:
    return Finding(
        finding_id="t", producer="codeql", rule_id=rule_id, message="t",
        source=Step(file_path=file_path, line=sink_line, column=1,
                    snippet="kfree(p);", label="source"),
        sink=Step(file_path=file_path, line=sink_line, column=1,
                  snippet="kfree(p);", label="sink"),
        intermediate_steps=(), raw={},
    )


# =====================================================================
# Real-spatch E2E
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_double_free_fires_on_classic_pattern(tmp_path):
    src = tmp_path / "df.c"
    src.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "extern void kfree(void *);\n"
        "void op(void) {\n"
        "    void *p = kmalloc(16, 0);\n"
        "    if (!p) return;\n"
        "    kfree(p);\n"
        "    kfree(p);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert len(r.double_frees) >= 2, f"got {r.double_frees!r}"
    roles = {df.role for df in r.double_frees}
    assert "first" in roles
    assert "second" in roles


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_double_free_skipped_on_reassign(tmp_path):
    """If pointer is reassigned between frees, NOT a double-free."""
    src = tmp_path / "ok.c"
    src.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "extern void kfree(void *);\n"
        "void op(void) {\n"
        "    void *p = kmalloc(16, 0);\n"
        "    if (!p) return;\n"
        "    kfree(p);\n"
        "    p = kmalloc(16, 0);\n"
        "    if (!p) return;\n"
        "    kfree(p);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert not r.double_frees, f"got {r.double_frees!r}"


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_e2e_double_free_skipped_on_single_free(tmp_path):
    src = tmp_path / "single.c"
    src.write_text(
        "extern void *kmalloc(unsigned long, int);\n"
        "extern void kfree(void *);\n"
        "void op(void) {\n"
        "    void *p = kmalloc(16, 0);\n"
        "    if (!p) return;\n"
        "    kfree(p);\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert not r.double_frees


# =====================================================================
# Verdict policy
# =====================================================================


def test_double_free_supports_verdict_at_first_free(tmp_path):
    src = tmp_path / "f.c"
    src.write_text("void op(void){}\n")
    finding = _finding(str(src), sink_line=10)
    result = SourceIntelResult(double_frees=(DoubleFreeEvidence(
        role="first", free_fn="kfree", location=(str(src), 10),
        enclosing_function="op",
    ), DoubleFreeEvidence(
        role="second", free_fn="kfree", location=(str(src), 12),
        enclosing_function="op",
    )))
    with patch("packages.source_intel.adapter.analyze",
               return_value=result):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.EXPLOITABLE


def test_double_free_supports_verdict_at_second_free(tmp_path):
    src = tmp_path / "f.c"
    src.write_text("void op(void){}\n")
    finding = _finding(str(src), sink_line=12)
    result = SourceIntelResult(double_frees=(DoubleFreeEvidence(
        role="first", free_fn="kfree", location=(str(src), 10),
    ), DoubleFreeEvidence(
        role="second", free_fn="kfree", location=(str(src), 12),
    )))
    with patch("packages.source_intel.adapter.analyze",
               return_value=result):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.EXPLOITABLE


def test_double_free_irrelevant_for_other_cwe(tmp_path):
    """cpp/null-dereference finding doesn't get verdict from
    double-free evidence — wrong CWE class."""
    src = tmp_path / "f.c"
    src.write_text("void op(void){}\n")
    finding = _finding(str(src), sink_line=10,
                       rule_id="cpp/null-dereference")
    result = SourceIntelResult(double_frees=(DoubleFreeEvidence(
        role="first", free_fn="kfree", location=(str(src), 10),
    ),))
    with patch("packages.source_intel.adapter.analyze",
               return_value=result):
        SourceIntelValidator(repo_root=tmp_path)
        # Verdict shouldn't be EXPLOITABLE from axis-3 double-free —
        # but axis-7 hazard / axis-1 etc. might still fire. Just
        # assert that axis-3 helper says no.
        assert _double_free_supports_finding(finding, result) is False


def test_double_free_far_from_sink_does_not_fire(tmp_path):
    """±3 line tolerance — double-free 20 lines away doesn't fire."""
    src = tmp_path / "f.c"
    src.write_text("void op(void){}\n")
    finding = _finding(str(src), sink_line=10)
    result = SourceIntelResult(double_frees=(DoubleFreeEvidence(
        role="first", free_fn="kfree", location=(str(src), 30),
    ),))
    with patch("packages.source_intel.adapter.analyze",
               return_value=result):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN
