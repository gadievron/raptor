"""Dynamic attribute receivers cannot borrow a static sanitizer identity."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.sanitizer_cut import evaluate_finding


def _subject(expression):
    source = ('import werkzeug.utils\ndef handle(raw, holder):\n'
              '    clean='+expression+'\n    open(clean)\n')
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                              source_symbols={'raw'}, sink_arg='clean')
    return cfg, result


def test_subscript_receiver_cannot_borrow_canonical_sanitizer_identity():
    _, result = _subject('holder[0].werkzeug.utils.secure_filename(raw)')
    assert result.suppress is False


def test_call_receiver_cannot_borrow_canonical_sanitizer_identity():
    _, result = _subject('factory().werkzeug.utils.secure_filename(raw)')
    assert result.suppress is False


def test_genuine_import_root_keeps_sanitizer_identity():
    _, result = _subject('werkzeug.utils.secure_filename(raw)')
    assert result.suppress is True


@pytest.mark.parametrize('receiver', ['holder[0]', 'factory()', '(holder if flag else other)', '(saved:=holder)'])
def test_dynamic_roots_do_not_create_static_call_records(receiver):
    cfg, _ = _subject(receiver+'.werkzeug.utils.secure_filename(raw)')
    sites = [site for node in cfg.nodes() for site in node.call_sites]
    assert all(site.name != 'werkzeug.utils.secure_filename' for site in sites)
    assert all(node.calls == frozenset(site.name for site in node.call_sites) for node in cfg.nodes())
    if receiver == 'factory()':
        assert any(site.name == 'factory' for site in sites)
    assignment = next(node for node in cfg.nodes() if 'clean' in node.defs)
    assert 'raw' in assignment.uses
    if receiver == 'holder[0]':
        assert 'holder' in assignment.uses


def test_dynamic_match_guard_keeps_nested_calls_without_fabricating_identity():
    source = 'def handle(raw, holder):\n    match raw:\n        case _ if factory().werkzeug.utils.secure_filename(raw):\n            pass\n'
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sites = [site for node in cfg.nodes() for site in node.call_sites]
    assert any(site.name == 'factory' for site in sites)
    assert all(site.name != 'werkzeug.utils.secure_filename' for site in sites)


def test_static_dotted_and_self_calls_keep_existing_records():
    cfg = build_python_cfg('def handle(self, raw):\n    clean=self.method(raw)\n    module.utility(clean)\n', 'handle')
    assert cfg is not None
    sites = {site.name: site for node in cfg.nodes() for site in node.call_sites}
    assert sites['self.method'].assigned_names == frozenset({'clean'})
    assert sites['module.utility'].arg_names == frozenset({'clean'})
