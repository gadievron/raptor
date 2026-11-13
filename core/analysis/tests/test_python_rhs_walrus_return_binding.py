"""Simple assignments through one walrus preserve direct return identity."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import evaluate_finding


def evaluate(statement, extra=''):
    text = ('import werkzeug\ndef handle(raw,holder):\n' + extra
            + '    tmp=raw\n    ' + statement + '\n    open(tmp)\n')
    cfg = build_python_cfg(text, 'handle')
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    site = next(site for node in cfg.nodes() for site in node.call_sites
                if site.name == 'werkzeug.utils.secure_filename')
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                              source_symbols={'raw'}, sink_arg='tmp')
    return site, result


def test_bare_assignment_through_walrus_retains_sanitized_return_identity():
    site, result = evaluate('tmp = (alias := werkzeug.utils.secure_filename(raw))')
    assert result.suppress is True
    assert site.assigned_names == frozenset({'tmp', 'alias'})


@pytest.mark.parametrize('statement,expected', [
    ('tmp: str = (alias := werkzeug.utils.secure_filename(raw))', {'tmp', 'alias'}),
    ('tmp = (tmp := werkzeug.utils.secure_filename(raw))', {'tmp'}),
])
def test_single_bare_target_forms_preserve_exact_return_names(statement, expected):
    site, result = evaluate(statement)
    assert site.assigned_names == frozenset(expected)
    assert result.suppress is True


@pytest.mark.parametrize('statement', [
    'tmp = (alias := werkzeug.utils.secure_filename(raw)) if False else raw',
    'tmp = (alias := werkzeug.utils.secure_filename(raw)) + raw',
    'holder.value = tmp = (alias := werkzeug.utils.secure_filename(raw))',
    'holder.value = (alias := werkzeug.utils.secure_filename(raw))',
    'holder["value"] = (alias := werkzeug.utils.secure_filename(raw))',
    'tmp, other = (alias := werkzeug.utils.secure_filename(raw))',
])
def test_complex_conditional_and_chained_outer_targets_gain_no_return_credit(statement):
    site, result = evaluate(statement)
    assert site.assigned_names == frozenset()
    assert result.suppress is False


def test_rhs_walrus_preserves_global_scope_escape_refusal():
    site, result = evaluate('tmp = (alias := werkzeug.utils.secure_filename(raw))',
                            extra='    global tmp, alias\n')
    assert site.assigned_names == frozenset()
    assert result.suppress is False
