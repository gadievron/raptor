"""Module call classification preserves the union of closed function intervals."""

import ast

import pytest

from core.analysis import python_module_callgraph as graph


def _records(ranges):
    return [graph._FunctionRecord(str(i), start, end, (), False, None, ast.Pass())
            for i, (start, end) in enumerate(ranges)]


def _legacy_calls(tree, records):
    ranges = [(record.lineno, record.end_lineno) for record in records]
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if any(start <= node.lineno <= end for start, end in ranges):
            continue
        chain = graph._attribute_chain(node.func)
        if chain is not None:
            calls.append((node, chain))
    return calls


@pytest.mark.parametrize('ranges', [
    [], [(4, 4)], [(4, 8)], [(8, 4)], [(-3, -1)], [(20, 30)],
    [(2, 16), (5, 7)], [(5, 7), (2, 16)], [(3, 9), (7, 13)],
    [(4, 8), (4, 16), (4, 8)], [(9, 3), (2, 6), (15, 11)],
    [(7, 9), (2, 4), (12, 15)], [(0, 0), (1, 1), (18, 18)],
])
def test_interval_union_matches_original_predicate_and_call_identity(ranges):
    tree = ast.parse(''.join('callee()\n' for _ in range(18)) + 'factory()()\n')
    records = _records(ranges)
    expected = _legacy_calls(tree, records)
    actual = graph._module_level_calls(tree, records)
    assert actual == expected
    assert all(a is b for (a, _), (b, _) in zip(actual, expected, strict=True))


@pytest.mark.parametrize('ranges', [[(1, 9), (None, 4)], [(None, 4)], [(2.5, 4.5)], [(True, 3)]])
def test_non_integer_ranges_retain_original_short_circuit_or_failure(ranges):
    tree = ast.parse('callee()\n')
    records = _records(ranges)
    try:
        expected = _legacy_calls(tree, records)
    except TypeError:
        with pytest.raises(TypeError):
            graph._module_level_calls(tree, records)
    else:
        assert graph._module_level_calls(tree, records) == expected


def test_non_integer_call_line_retains_original_comparison_semantics():
    tree = ast.parse('callee()\n')
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    for line in (1.5, float('nan'), True):
        call.lineno = line
        records = _records([(1, 2)])
        assert graph._module_level_calls(tree, records) == _legacy_calls(tree, records)


def test_real_graph_preserves_header_nested_lambda_and_redefinition_semantics(monkeypatch):
    source = """def callee(): pass
@callee()
def outer(value=callee()):
    def inner(arg=callee()):
        callee()
    return inner()
if flag:
    def repeated(): callee()
else:
    def repeated(): callee()
bound = lambda value=callee(): callee()
class Holder:
    callee()
    def method(self, value=callee()): callee()
callee()
"""
    def signature(value):
        assert value is not None
        return sorted((node.name, node.lineno,
                       sorted((child.name, child.lineno) for child in value.successors(node)))
                      for node in value.nodes())
    actual = signature(graph.build_python_module_callgraph(source))
    original = graph._module_level_calls
    with monkeypatch.context() as scope:
        scope.setattr(graph, '_module_level_calls', _legacy_calls)
        expected = signature(graph.build_python_module_callgraph(source))
    assert graph._module_level_calls is original
    assert actual == expected
