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


def test_unpacking_a_call_result_does_not_capture_the_whole_return():
    source = "import shlex\ndef handle(raw):\n    left, tmp, right = shlex.quote(raw)\n"
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    assignment = next(n for n in cfg.nodes() if "shlex.quote" in n.calls)
    site = next(cs for cs in assignment.call_sites if cs.name == "shlex.quote")
    assert assignment.defs == frozenset({"left", "tmp", "right"})
    assert site.arg_names == frozenset({"raw"})
    assert not site.assigned_names


@pytest.mark.parametrize("statement", [
    "[left, tmp, right] = shlex.quote(raw)",
    "left, *tmp = shlex.quote(raw)",
    "(left, tmp), other = shlex.quote(raw), raw",
])
def test_destructured_return_elements_have_no_whole_return_identity(statement):
    cfg = build_python_cfg("import shlex\ndef handle(raw):\n    " + statement + "\n", "handle")
    assert cfg is not None
    assignment = next(n for n in cfg.nodes() if "shlex.quote" in n.calls)
    assert "tmp" in assignment.defs
    assert not next(cs for cs in assignment.call_sites if cs.name == "shlex.quote").assigned_names


def test_chained_whole_return_keeps_identity_without_crediting_unpacking():
    cfg = build_python_cfg("import shlex\ndef handle(raw):\n    whole = left, tmp, right = shlex.quote(raw)\n", "handle")
    assert cfg is not None
    assignment = next(n for n in cfg.nodes() if "shlex.quote" in n.calls)
    assert assignment.defs == frozenset({"whole", "left", "tmp", "right"})
    assert next(cs for cs in assignment.call_sites if cs.name == "shlex.quote").assigned_names == frozenset({"whole"})
