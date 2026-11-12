"""Evaluating an assignment target does not give its walruses the RHS value."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import evaluate_finding


def evaluate(statement, sink_name='tmp'):
    source = (
        'import werkzeug\ndef handle(raw, store):\n    '
        + statement + '\n    open(' + sink_name + ')\n'
    )
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'open' in n.calls)
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                              source_symbols={'raw'}, sink_arg=sink_name)
    assignment = next(n for n in cfg.nodes() if 'werkzeug.utils.secure_filename' in n.calls)
    return assignment, result


def test_raw_subscript_key_cannot_borrow_the_sanitized_stored_value():
    assignment, result = evaluate('store[(tmp := raw)] = werkzeug.utils.secure_filename(raw)')
    assert assignment.defs == frozenset({'tmp'})
    assert {'raw', 'store'} <= assignment.uses
    assert result.all_matched_bindings
    assert not result.value_bound_bindings
    assert result.suppress is False


@pytest.mark.parametrize('target,expected', [
    ('store[(tmp := raw)]', set()),
    ('store[pick(tmp := raw)]', set()),
    ('store[(tmp := raw)].field', set()),
    ('left, store[(tmp := raw)]', {'left'}),
    ('[left, *rest]', {'left', 'rest'}),
    ('tmp', {'tmp'}),
])
def test_only_binding_target_positions_receive_the_call_return(target, expected):
    source = f'def handle(raw, store):\n    {target} = prepare(raw)\n'
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    node = next(n for n in cfg.nodes() if 'prepare' in n.calls)
    call = next(cs for cs in node.call_sites if cs.name == 'prepare')
    assert call.assigned_names == frozenset(expected)
    if 'tmp :=' in target:
        assert 'tmp' in node.defs


def test_chained_assignment_credits_the_direct_target_but_not_the_raw_key():
    statement = 'tmp = store[(key := raw)] = werkzeug.utils.secure_filename(raw)'
    assignment, raw_result = evaluate(statement, sink_name='key')
    assert assignment.defs == frozenset({'tmp', 'key'})
    call = next(cs for cs in assignment.call_sites if cs.name == 'werkzeug.utils.secure_filename')
    assert call.assigned_names == frozenset({'tmp'})
    assert raw_result.suppress is False
    _assignment, clean_result = evaluate(statement)
    assert clean_result.suppress is True
