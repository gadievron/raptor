"""Scalar declaration controls; no source parser or native rules."""

import pytest

from core.dataflow.finding import Finding, Step
from packages.source_intel import adapter
from packages.source_intel.analyze import AllocationEvidence, SourceIntelResult


@pytest.mark.parametrize("snippet,expected", [
    ("p = alloc();", "p"),
    ("char *p = alloc();", "p"),
    ("char* p = alloc();", "p"),
    ("const char **p = alloc();", "p"),
    ("*p = alloc();", None),
    ("p->field = alloc();", None),
    ("obj.field = alloc();", None),
    ("T" * 300 + " *p = alloc();", None),
])
def test_local_assignment_shapes(snippet, expected):
    assert adapter._extract_local_var_from_snippet(snippet) == expected


@pytest.mark.parametrize("guarded", [True, False])
def test_pointer_declaration_reaches_existing_guard(tmp_path, monkeypatch, guarded):
    path = str(tmp_path / "owned.c")
    snippet = "char *p = kstrdup(s, 0);"
    lines = [snippet, "if (validate(p)) return;" if guarded else "work();", "use(p);"]
    monkeypatch.setattr(adapter, "_sanitized_lines", lambda *args: lines)
    finding = Finding(
        finding_id="owned", producer="codeql", rule_id="cpp/null-dereference", message="owned",
        source=Step(file_path=path, line=1, column=1, snippet=snippet, label="source"),
        sink=Step(file_path=path, line=3, column=1, snippet="use(p);", label="sink"),
        intermediate_steps=(), raw={},
    )
    result = SourceIntelResult(allocations=(AllocationEvidence(
        allocator="kstrdup", location=(path, 1), shape="local",
    ),))
    assert adapter._unchecked_alloc_supports_finding(finding, result, repo_root=tmp_path) is (not guarded)
