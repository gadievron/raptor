"""An augmented assignment does not assign only the call's return value."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import evaluate_finding


def evaluate(statement):
    source = (
        'import werkzeug\ndef handle(raw):\n    tmp = raw\n    '
        + statement + '\n    open(tmp)\n'
    )
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if 'open' in n.calls)
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                              source_symbols={'raw'}, sink_arg='tmp')
    return cfg, result


def test_sanitized_suffix_cannot_sanitize_the_existing_path_prefix():
    _cfg, result = evaluate('tmp += werkzeug.utils.secure_filename(raw)')
    assert result.all_matched_bindings
    assert not result.value_bound_bindings
    assert result.suppress is False


@pytest.mark.parametrize('operator', ['+=', '-=', '*=', '|='])
def test_augmented_call_preserves_symbols_without_fresh_return_identity(operator):
    source = f'def handle(raw):\n    tmp = raw\n    tmp {operator} scrub(raw)\n    consume(tmp)\n'
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    node = next(n for n in cfg.nodes() if 'scrub' in n.calls)
    assert node.defs == frozenset({'tmp'})
    assert {'tmp', 'raw'} <= node.uses
    assert len(node.call_sites) == 1
    call = node.call_sites[0]
    assert call.arg_names == frozenset({'raw'})
    assert not call.assigned_names


@pytest.mark.parametrize('statement', [
    'tmp = werkzeug.utils.secure_filename(raw)',
    'tmp: str = werkzeug.utils.secure_filename(raw)',
    'tmp = other = werkzeug.utils.secure_filename(raw)',
])
def test_direct_return_assignment_keeps_existing_value_bound_control(statement):
    _cfg, result = evaluate(statement)
    assert result.value_bound_bindings
    assert result.suppress is True
