"""Finding CFGs retain the exact span-selected function identity."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.finding_resolver import ResolvedFinding, resolve_finding
from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, evaluate_finding


SOURCES = [
    'import html\nclass First:\n    def handle(self, ignored):\n        return ignored\nclass Second:\n    def handle(self, raw):\n        clean=html.escape(raw)\n        render(clean)\n',
    'import html\ndef handle(ignored):\n    return ignored\ndef handle(raw):\n    clean=html.escape(raw)\n    render(clean)\n',
    'import html\ndef outer():\n    def handle(ignored):\n        return ignored\n    def handle(raw):\n        clean=html.escape(raw)\n        render(clean)\n',
]


@pytest.mark.parametrize('source', SOURCES, ids=['methods', 'top-level', 'nested'])
def test_resolver_uses_later_span_selected_function(tmp_path, source):
    path = tmp_path / 'app.py'
    path.write_text(source)
    matches = [node for node in ast.walk(ast.parse(source))
               if isinstance(node, ast.FunctionDef) and node.name == 'handle']
    selected = max(matches, key=lambda node: node.lineno)
    finding = {'cwe': 'CWE-79', 'file_path': str(path), 'source_line': selected.lineno,
               'sink_line': selected.end_lineno, 'language': 'python'}
    resolved = resolve_finding(finding, target_root=tmp_path)
    assert isinstance(resolved, ResolvedFinding)
    assert 'raw' in resolved.cfg.params
    assert 'ignored' not in resolved.cfg.params
    assert resolved.sink_node.lineno == selected.end_lineno
    assert 'clean' == resolved.sink_arg
    result = evaluate_finding(resolved.cfg, [resolved.source_node], resolved.sink_node,
                              cwe=resolved.cwe, language=resolved.language,
                              source_symbols=resolved.source_symbols, sink_arg=resolved.sink_arg)
    assert result.suppress is False
    assert result.verdict == VERDICT_CANDIDATE_ONLY
    assert any(binding.unverified_source_contracts for binding in result.all_matched_bindings)


def test_node_pin_must_belong_to_same_module_tree_and_match_name():
    source = SOURCES[1]
    tree = ast.parse(source)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    selected = functions[-1]
    cfg = build_python_cfg(source, 'handle', _module_tree=tree, _function_node=selected)
    assert cfg is not None and cfg.params == ('raw',)
    foreign = ast.parse(source).body[-1]
    assert build_python_cfg(source, 'handle', _module_tree=tree, _function_node=foreign) is None
    assert build_python_cfg(source, 'missing', _module_tree=tree, _function_node=selected) is None
    default = build_python_cfg(source, 'handle', _module_tree=tree)
    assert default is not None and default.params == ('ignored',)


def test_selected_unsafe_function_does_not_borrow_earlier_sanitizer(tmp_path):
    source = 'import html\ndef handle(ignored):\n    clean=html.escape(ignored)\n    render(clean)\ndef handle(raw):\n    render(raw)\n'
    path = tmp_path / 'app.py'
    path.write_text(source)
    resolved = resolve_finding({'cwe': 'CWE-79', 'file_path': str(path),
                               'source_line': 5, 'sink_line': 6, 'language': 'python'}, target_root=tmp_path)
    assert isinstance(resolved, ResolvedFinding)
    result = evaluate_finding(resolved.cfg, [resolved.source_node], resolved.sink_node,
                              cwe=resolved.cwe, language=resolved.language,
                              source_symbols=resolved.source_symbols, sink_arg=resolved.sink_arg)
    assert result.suppress is False


def test_unique_name_cfg_keeps_existing_parameters():
    cfg = build_python_cfg('def unique(raw):\n    render(raw)\n', 'unique')
    assert cfg is not None and cfg.params == ('raw',)
