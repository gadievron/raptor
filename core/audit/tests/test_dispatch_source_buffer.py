"""Dispatch expansion preserves source freshness, evidence and traversal refusals."""

from types import SimpleNamespace

import pytest

from core.audit.cross_entry import dispatch
from core.audit.cross_entry.model import AccessIndex, Call, Function, Limits


class ChangingSource(str):
    encodes = 0
    def encode(self, *args, **kwargs):
        self.encodes += 1
        replacement = b'aaaaaa' if self.encodes == 1 else b'bbbbbb'
        return super().encode(*args, **kwargs).replace(b'helper', replacement)


def fixture(source=None, *, large=False):
    text = source if source is not None else 'void f(int value) {\n /*雪*/ helper(value);\n}\n'
    if large:
        text = text.replace('{\n', '{\n /*' + ' padding' * 700 + '*/\n', 1)
    raw = str.encode(text)
    index = AccessIndex()
    index.functions['f'] = Function('f', 'a.c', 'f', 10, 12, 100, 100+len(raw), '', text, params=['value'])
    for i, (name, param) in enumerate([('g', 'first'), ('h', 'second')]):
        body = f'void {name}(int {param}) {{}}'
        index.functions[name] = Function(name, 'a.c', name, 20+i, 20+i, 500+i*100,
                                         500+i*100+len(body), '', body, params=[param])
    offset = raw.index(b'helper(value)')
    begin = 100+offset
    line = 10+raw[:offset].count(b'\n')
    index.calls = [Call('f', 'helper', ['value'], line, targets=['g', 'h'],
                        start_byte=begin, end_byte=begin+len(b'helper(value)'))]
    index.declarations['binding'] = {'file': 'a.c', 'line': 1, 'source': 'ops.run = f;'}
    roots = [{'caller': 'install', 'target': 'f', 'evidence_id': 'binding', 'installer': 'install'}]
    evidence = f'callback-helper-call:a.c:{begin}'
    return index, roots, evidence


def limits(**kwargs):
    return Limits(graph_seconds=1000, **kwargs)


@pytest.mark.parametrize("large", [False, True], ids=["small", "buffered"])
def test_unicode_source_and_target_bindings_remain_independent(large):
    index, roots, evidence = fixture(large=large)
    rows, deferred = dispatch.expand_dispatch_paths(index, roots, limits())
    assert [row['target'] for row in rows] == ['f', 'g', 'h']
    assert deferred == []
    assert index.declarations[evidence] == {'file': 'a.c', 'line': index.calls[0].line, 'source': 'helper(value)'}
    g = rows[1]['dispatch_path'][-1]['parameter_bindings']
    h = rows[2]['dispatch_path'][-1]['parameter_bindings']
    assert g == {'first': 'value'} and h == {'second': 'value'}
    g['first'] = 'consumer edit'
    assert h == {'second': 'value'}


def test_custom_source_keeps_per_step_encode_hooks():
    source = ChangingSource('void f(int value) { /*' + ' padding' * 700 + '*/ helper(value); }')
    index, roots, evidence = fixture(source)
    dispatch.expand_dispatch_paths(index, roots, limits())
    assert source.encodes == 2
    assert index.declarations[evidence]['source'] == 'bbbbbb(value)'


def test_native_source_replacement_refreshes_buffer_within_row():
    index, roots, evidence = fixture(large=True)
    fn = index.functions['f']
    fn.source = fn.source.replace('}\n', ' external();\n}\n')
    fn.end_byte = fn.start_byte + len(fn.source.encode())
    offset = len(fn.source[:fn.source.index('external()')].encode())
    index.calls.append(Call('f', 'external', [], 12, start_byte=fn.start_byte+offset,
                            end_byte=fn.start_byte+offset+len('external()')))
    class Targets(list):
        def __iter__(self):
            yield 'g'
            index.functions['f'].source = index.functions['f'].source.replace('helper', 'second')
            yield 'h'
    index.calls[0].targets = Targets(['g', 'h'])
    dispatch.expand_dispatch_paths(index, roots, limits())
    assert index.declarations[evidence]['source'] == 'second(value)'


def test_site_cap_keeps_declined_edge_evidence():
    index, roots, evidence = fixture()
    rows, deferred = dispatch.expand_dispatch_paths(index, roots, limits(max_sites=1))
    assert [row['target'] for row in rows] == ['f']
    assert [row['target'] for row in deferred] == ['g', 'h']
    assert all(row['reason'] == 'dispatch_path_budget' for row in deferred)
    assert index.declarations[evidence]['source'] == 'helper(value)'


def test_depth_refusal_does_not_encode_source():
    source = ChangingSource('void f(int value) { /*' + ' padding' * 700 + '*/ helper(value); }')
    index, roots, evidence = fixture(source)
    rows, deferred = dispatch.expand_dispatch_paths(index, roots, limits(graph_depth=0))
    assert len(rows) == 1
    assert deferred == [{'reason': 'dispatch_path_depth', 'target': 'f', 'root': 'f'}]
    assert source.encodes == 0
    assert evidence not in index.declarations


def test_deadline_keeps_root_and_queue_refusal_order(monkeypatch):
    index, roots, evidence = fixture()
    roots.append({**roots[0], 'evidence_id': 'other-binding'})
    ticks = iter([0, 2])
    monkeypatch.setattr(dispatch, 'time', SimpleNamespace(monotonic=lambda: next(ticks)))
    rows, deferred = dispatch.expand_dispatch_paths(index, roots, Limits(graph_seconds=1))
    assert len(rows) == 2
    assert deferred == [{'reason': 'dispatch_path_budget', 'target': 'f', 'root': 'f'}] * 2
    assert evidence not in index.declarations


def test_conditional_only_paths_do_not_encode_caller():
    source = ChangingSource('void f(int value) { /*' + ' padding' * 700 + '*/ helper(value); }')
    index, roots, evidence = fixture(source)
    index.calls[0].targets = []
    index.calls[0].dispatch_bindings = [{'target': 'g', 'caller': 'f', 'evidence_id': 'binding',
                                      'invocation_evidence': 'invoke', 'parameter_bindings': {'first': 'value'}}]
    rows, deferred = dispatch.expand_dispatch_paths(index, roots, limits())
    assert [row['target'] for row in rows] == ['f', 'g']
    assert rows[1]['dispatch_path'][-1]['kind'] == 'dispatch_candidate'
    assert deferred == []
    assert source.encodes == 0 and evidence not in index.declarations


def test_native_encoding_errors_still_propagate():
    index, roots, evidence = fixture()
    index.functions['f'].source += ' padding' * 700 + '\ud800'
    index.functions['f'].end_byte += 5600
    with pytest.raises(UnicodeEncodeError):
        dispatch.expand_dispatch_paths(index, roots, limits())
    assert evidence not in index.declarations
