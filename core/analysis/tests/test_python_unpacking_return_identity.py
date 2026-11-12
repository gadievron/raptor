"""Unknown unpacking positions cannot grant every target a sanitizer value."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import evaluate_finding


def evaluate(statement):
    source = 'import werkzeug\ndef handle(raw):\n    ' + statement + '\n    open(tmp)\n'
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'open' in n.calls)
    assignment = next(n for n in cfg.nodes() if 'werkzeug.utils.secure_filename' in n.calls)
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                              source_symbols={'raw'}, sink_arg='tmp')
    return assignment, result


def test_starred_target_cannot_credit_the_raw_position_as_sanitized():
    assignment, result = evaluate('safe, tmp, *rest = werkzeug.utils.secure_filename(raw), raw')
    assert assignment.defs == frozenset({'safe', 'tmp', 'rest'})
    assert result.all_matched_bindings
    assert not result.value_bound_bindings
    assert result.suppress is False


@pytest.mark.parametrize('statement', [
    '[safe, tmp] = werkzeug.utils.secure_filename(raw), raw',
    'safe, tmp, *rest = (*(raw, raw), werkzeug.utils.secure_filename(raw), raw)',
    'safe, tmp = werkzeug.utils.secure_filename(raw), raw',
])
def test_raw_target_never_borrows_another_element_call_return(statement):
    _assignment, result = evaluate(statement)
    assert result.all_matched_bindings
    assert not result.value_bound_bindings
    assert result.suppress is False


@pytest.mark.parametrize('statement', [
    'tmp, other = werkzeug.utils.secure_filename(raw), raw',
    '[tmp, other] = werkzeug.utils.secure_filename(raw), raw',
    'other, tmp = raw, werkzeug.utils.secure_filename(raw)',
    '[other, tmp] = raw, werkzeug.utils.secure_filename(raw)',
    'tmp = werkzeug.utils.secure_filename(raw)',
])
def test_exact_plain_return_positions_keep_value_bound_controls(statement):
    assignment, result = evaluate(statement)
    call = next(cs for cs in assignment.call_sites if cs.name == 'werkzeug.utils.secure_filename')
    assert call.assigned_names == frozenset({'tmp'})
    assert result.value_bound_bindings
    assert result.suppress is True
