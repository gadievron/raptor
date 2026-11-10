"""Unmapped Java translation cannot supply a structural proof graph."""
import pytest

from core.analysis.cfg_builder_java import _get_parser, build_java_intraproc_cfg
from core.analysis.sanitizer_cut import evaluate_finding

pytest.importorskip("tree_sitter_java")
PREFIX = chr(92) + "u000a"
REASON = "java_unicode_translation_unverified"


def _source():
    return "class T { void handle() {\n int marker = 0;\n // " + PREFIX + " marker = 1;\n consume(marker);\n} }\n"


def test_java_unicode_prefix_refuses_raw_cfg():
    assert build_java_intraproc_cfg(_source(), "handle") is None


def test_cached_tree_cannot_bypass_raw_source_profile():
    source = _source()
    tree = _get_parser().parse(source.encode())
    assert build_java_intraproc_cfg(source, "handle", _ts_tree=tree) is None


def test_direct_structural_entry_cannot_bypass_raw_source_profile():
    graph = build_java_intraproc_cfg(_source().replace(PREFIX, ""), "handle")
    assert graph is not None
    sink = next(node for node in graph.nodes() if "consume" in node.label)
    result = evaluate_finding(graph, [graph.entry_node], sink,
                              cwe="CWE-79", language="java", java_source_text=_source())
    assert not result.suppress
    assert REASON in result.reason


def test_direct_unicode_characters_do_not_require_escape_translation():
    source = 'class T { void handle() { String note = "π"; consume(note); } }'
    assert build_java_intraproc_cfg(source, "handle") is not None


def test_escaped_spelling_also_declines_until_eligibility_is_verified():
    source = 'class T { void handle() { String note = "' + chr(92) * 2 + 'u0041"; consume(note); } }'
    assert build_java_intraproc_cfg(source, "handle") is None
