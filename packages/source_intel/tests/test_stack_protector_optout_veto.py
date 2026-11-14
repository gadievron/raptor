"""Opt-out identity controls with owned source-view and inventory callbacks."""

import importlib

import pytest

from core.build.build_flags import BuildFlagsContext
from core.dataflow.finding import Finding, Step
from packages.source_intel import adapter
from packages.source_intel.analyze import AttributeEvidence, SourceIntelResult

analyze_module = importlib.import_module("packages.source_intel.analyze")


@pytest.mark.parametrize("optout_path", ["/owned/unit.c", "/owned/header.h"])
@pytest.mark.parametrize("sink_function,optout_function,expected", [
    ("owned", "owned", False),
    ("owned", "unrelated", True),
    (None, "unrelated", False),
    ("owned", None, False),
    (None, None, False),
])
def test_optout_requires_proven_disjoint_function(
    monkeypatch, sink_function, optout_function, expected, optout_path,
):
    step = Step("/owned/unit.c", 3, 1, "copy(buf, input);")
    finding = Finding("owned", "codeql", "cpp/unbounded-write", "owned", step, step)
    optout = AttributeEvidence(
        kind="no_stack_protector", function_name="untrusted_label",
        location=(optout_path, 7), match_source="literal",
        raw_match="no_stack_protector",
    )
    result = SourceIntelResult(
        attributes=(optout,),
        build_flags=BuildFlagsContext(
            extraction_confidence="best_effort", stack_protector_level="strong",
        ),
    )
    monkeypatch.setattr(adapter, "_sanitized_lines", lambda _: [
        "int owned() {", "char buf[64];", "copy(buf, input);", "}",
    ])
    monkeypatch.setattr(adapter, "_build_flags_trusted", lambda _: True)
    calls = []

    def identity(path, line):
        assert path == ("/owned/unit.c" if line == 3 else optout_path)
        calls.append(line)
        return sink_function if line == 3 else optout_function

    monkeypatch.setattr(analyze_module, "_enclosing_function_via_inventory", identity)
    monkeypatch.setattr(analyze_module, "_enclosing_function", lambda *_: pytest.fail(
        "regex fallback must not establish opt-out disjointness",
    ))
    assert adapter._stack_protector_suppresses_finding(finding, result) is expected
    if expected:
        assert calls == [3, 7]


@pytest.mark.parametrize("path,line,kind,expected", [
    ("/owned/other.c", 7, "no_stack_protector", False),
    ("", 7, "no_stack_protector", False),
    ("/owned/unit.c", 0, "no_stack_protector", False),
    ("/owned/unit.c", 7, "nonnull", True),
    ("/owned/../owned/unit.c", 7, "no_stack_protector", False),
])
def test_optout_file_and_kind_admission(monkeypatch, path, line, kind, expected):
    step = Step("/owned/unit.c", 3, 1, "copy(buf, input);")
    finding = Finding("owned", "codeql", "cpp/unbounded-write", "owned", step, step)
    optout = AttributeEvidence(
        kind=kind, function_name="untrusted_label", location=(path, line),
        match_source="literal", raw_match=kind, conditional_on="CONFIG_UNKNOWN",
    )
    result = SourceIntelResult(
        attributes=(optout,),
        build_flags=BuildFlagsContext(
            extraction_confidence="best_effort", stack_protector_level="strong",
        ),
    )
    monkeypatch.setattr(adapter, "_sanitized_lines", lambda _: [
        "int owned() {", "char buf[64];", "copy(buf, input);", "}",
    ])
    monkeypatch.setattr(adapter, "_build_flags_trusted", lambda _: True)
    monkeypatch.setattr(analyze_module, "_enclosing_function_via_inventory", lambda *_: None)
    monkeypatch.setattr(analyze_module, "_enclosing_function", lambda *_: pytest.fail(
        "regex fallback must not establish opt-out disjointness",
    ))
    assert adapter._stack_protector_suppresses_finding(finding, result) is expected
