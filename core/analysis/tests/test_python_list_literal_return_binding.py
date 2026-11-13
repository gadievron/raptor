"""Exact list literal unpacking preserves only the corresponding call return."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import evaluate_finding


def evaluate(statement, parameters='raw'):
    source = 'import werkzeug\ndef handle(' + parameters + '):\n    ' + statement + '\n    open(tmp)\n'
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    node = next(node for node in cfg.nodes() if 'werkzeug.utils.secure_filename' in node.calls)
    site = next(site for site in node.call_sites if site.name == 'werkzeug.utils.secure_filename')
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                              source_symbols={'raw'}, sink_arg='tmp')
    return site, result


def test_exact_list_literal_position_retains_sanitized_return_binding():
    site, result = evaluate('tmp, other = [werkzeug.utils.secure_filename(raw), raw]')
    assert result.suppress is True
    assert site.assigned_names == frozenset({'tmp'})


@pytest.mark.parametrize('statement', [
    '[tmp, other] = [werkzeug.utils.secure_filename(raw), raw]',
    'other, tmp = [raw, werkzeug.utils.secure_filename(raw)]',
    '[other, tmp] = [raw, werkzeug.utils.secure_filename(raw)]',
])
def test_exact_list_literal_positions_keep_corresponding_output_names(statement):
    site, result = evaluate(statement)
    assert site.assigned_names == frozenset({'tmp'})
    assert result.suppress is True


@pytest.mark.parametrize('statement', [
    'safe, tmp = [werkzeug.utils.secure_filename(raw), raw]',
    'safe, tmp, *rest = [werkzeug.utils.secure_filename(raw), raw]',
    'safe, tmp = [*raw, werkzeug.utils.secure_filename(raw)]',
    'tmp, tmp = [werkzeug.utils.secure_filename(raw), raw]',
    '(tmp, other), tail = [werkzeug.utils.secure_filename(raw), raw]',
    'holder.value = tmp, other = [werkzeug.utils.secure_filename(raw), raw]',
    'items = tmp, other = [werkzeug.utils.secure_filename(raw), raw]',
])
def test_unknown_positions_raw_elements_and_rebound_targets_cannot_suppress(statement):
    _site, result = evaluate(statement, parameters='raw,holder')
    assert result.suppress is False
