"""A standalone walrus captures its direct call's exact return value."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import evaluate_finding


def build(statement, extra=''):
    text = ('import werkzeug\ndef handle(raw):\n'
            + extra + '    tmp=raw\n    ' + statement + '\n    open(tmp)\n')
    cfg = build_python_cfg(text, 'handle')
    assert cfg is not None
    return cfg


def test_standalone_walrus_preserves_the_sanitized_return_binding():
    cfg = build('(tmp := werkzeug.utils.secure_filename(raw))')
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                            source_symbols={'raw'}, sink_arg='tmp').suppress is True
    site = next(site for node in cfg.nodes() for site in node.call_sites
                if site.name.endswith('secure_filename'))
    assert site.assigned_names == frozenset({'tmp'})


@pytest.mark.parametrize('statement', [
    'False and (tmp := werkzeug.utils.secure_filename(raw))',
    'consume(tmp := werkzeug.utils.secure_filename(raw))',
    '[(tmp := werkzeug.utils.secure_filename(raw)) for _ in ()]',
    'lambda: (tmp := werkzeug.utils.secure_filename(raw))',
    '(tmp := werkzeug.utils.secure_filename(raw)) if False else None',
])
def test_conditional_nested_and_deferred_walruses_gain_no_return_credit(statement):
    cfg = build(statement)
    for node in cfg.nodes():
        for site in node.call_sites:
            if site.name.endswith('secure_filename'):
                assert site.assigned_names == frozenset()


def test_skipped_walrus_cannot_suppress_the_raw_sink():
    cfg = build('False and (tmp := werkzeug.utils.secure_filename(raw))')
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                            source_symbols={'raw'}, sink_arg='tmp').suppress is False


def test_global_walrus_target_retains_scope_escape_refusal():
    cfg = build('(tmp := werkzeug.utils.secure_filename(raw))', extra='    global tmp\n')
    site = next(site for node in cfg.nodes() for site in node.call_sites
                if site.name.endswith('secure_filename'))
    assert site.assigned_names == frozenset()


def test_standalone_walrus_keeps_the_catalog_namespace_guard():
    cfg = build('(tmp := werkzeug.utils.secure_filename(raw))',
                extra='    werkzeug.utils.secure_filename=lambda value: value\n')
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                            source_symbols={'raw'}, sink_arg='tmp').suppress is False
