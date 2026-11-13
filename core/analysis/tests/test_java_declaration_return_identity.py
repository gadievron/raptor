"""Later Java declaration initializers may overwrite an earlier return."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import _get_parser, build_java_intraproc_cfg  # noqa: E402
from core.analysis.sanitizer_cut import evaluate_finding  # noqa: E402


def evaluate(statement):
    source = ('import org.owasp.encoder.Encode;\n'
              'class T { void m(String raw) {\n' + statement + '\n'
              'System.out.println(tmp);\n} }')
    assert not _get_parser().parse(source.encode()).root_node.has_error
    cfg = build_java_intraproc_cfg(source, "m")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "System.out.println" in node.calls)
    assignment = next(node for node in cfg.nodes() if "org.owasp.encoder.Encode.forHtml" in node.calls)
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-79", language="java",
                              source_symbols={"raw"}, sink_arg="tmp")
    return assignment, result


def test_later_initializer_overwrite_cannot_borrow_sanitizer_identity():
    assignment, result = evaluate('String tmp=Encode.forHtml(raw), other=(tmp=raw);')
    assert {"tmp", "other"} <= assignment.defs
    assert result.all_matched_bindings
    assert result.suppress is False
    site = next(cs for cs in assignment.call_sites if cs.name == "org.owasp.encoder.Encode.forHtml")
    assert not site.assigned_names


@pytest.mark.parametrize("statement", [
    'String tmp=Encode.forHtml(raw), other=identity(tmp=raw);',
    'String tmp=Encode.forHtml(raw), other=flag() ? (tmp=raw) : raw;',
])
def test_nested_initializer_writes_remove_return_credit(statement):
    _assignment, result = evaluate(statement)
    assert not result.value_bound_bindings
    assert result.suppress is False


def test_distinct_later_initializer_preserves_return_identity():
    assignment, result = evaluate('String tmp=Encode.forHtml(raw), other=raw;')
    assert result.suppress is True
    site = next(cs for cs in assignment.call_sites if cs.name == "org.owasp.encoder.Encode.forHtml")
    assert site.assigned_names == frozenset({"tmp"})


def test_later_sanitizer_declarator_keeps_its_own_identity():
    _assignment, result = evaluate('String other=raw, tmp=Encode.forHtml(raw);')
    assert result.suppress is True
