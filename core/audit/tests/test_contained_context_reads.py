"""Audit prompt reads carry the target root to the contained opener."""

import pytest

from core.audit import caller_context, caller_contract, context
from core.source import windows


def test_function_source_uses_contained_window(tmp_path, monkeypatch):
    path = tmp_path / 'source.c'
    path.write_text('void f(void) {\n  return;\n}\n')
    actual = windows._open_contained
    calls = []

    def rooted(root, candidate, mode):
        calls.append((root, candidate, mode))
        return actual(root, candidate, mode)

    def unexpected(*args, **kwargs):
        pytest.fail('prompt source used the by-name opener')

    monkeypatch.setattr(windows, '_open_contained', rooted)
    monkeypatch.setattr(windows, 'open_regular', unexpected)
    assert 'return;' in context._read_source(tmp_path, path.name, 1, 3)
    assert calls == [(tmp_path, path, 'rb')]


def _read_consumer(kind, root):
    """Exercise actual producers with an admitted three-line fixture span."""
    if kind == 'function':
        return context._read_source(root, 'source.c', 1, 3)
    if kind == 'malformed-span':
        return context._read_source(root, 'source.c', 1, -1)
    if kind == 'callee':
        callees = [{'file': 'source.c', 'name': 'f', 'line_start': 1}]
        context._enrich_callees_with_source(callees, root, None)
        return callees[0].get('source_snippet', '')
    if kind == 'flow':
        return context._read_flow_node_source(
            root, {'file': 'source.c', 'name': 'f', 'line': 1}, None,
        )
    if kind in ('caller-known', 'caller-unknown'):
        callers = [{'file': 'source.c', 'name': 'f'}]
        if kind == 'caller-known':
            callers[0]['line_start'] = 1
        context._enrich_callers_with_call_sites(callers, root, 'handle')
        return callers[0].get('call_site', '')
    if kind == 'entry':
        callers = [{'file': 'source.c', 'name': 'f', 'line_start': 1}]
        inventory = {'files': [{'path': 'source.c', 'items': [
            {'name': 'f', 'line_start': 1, 'line_end': 3},
        ]}]}
        caller_context.enrich_caller_entries(callers, root, inventory)
        return callers[0].get('caller_entry', '')
    if kind == 'contract-span':
        end = caller_contract._infer_def_end(root, 'source.c', 1)
        return 'handle' if end == 3 else ''
    if kind == 'contract-site':
        return caller_contract._site_excerpt(root, 'source.c', 2, {})
    raise AssertionError(kind)


@pytest.mark.parametrize('kind', [
    'function', 'malformed-span', 'callee', 'flow', 'caller-known',
    'caller-unknown', 'entry', 'contract-span', 'contract-site',
])
@pytest.mark.parametrize('admitted', [True, False], ids=['admitted', 'refused'])
def test_producers_honor_rooted_open_result(tmp_path, monkeypatch, kind, admitted):
    from core.source import contained

    path = tmp_path / 'source.c'
    path.write_text('void f(void) {\n  handle();\n}\n')
    actual = contained._open_contained
    calls = []

    def rooted(root, candidate, mode, **kwargs):
        calls.append((root, candidate))
        if not admitted:
            return None
        return actual(root, candidate, mode, **kwargs)

    def unexpected(*args, **kwargs):
        pytest.fail('refused rooted read fell back to a by-name opener')

    monkeypatch.setattr(windows, '_open_contained', rooted)
    monkeypatch.setattr(contained, '_open_contained', rooted)
    monkeypatch.setattr(windows, 'open_regular', unexpected)
    result = _read_consumer(kind, tmp_path)
    assert calls == [(tmp_path, path)]
    if admitted:
        assert 'handle' in result
    else:
        assert result in ('', '(read error)')
