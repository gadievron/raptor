"""Deferred generator writes cannot retain enclosing-cell certificates."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
WRITERS = [
    '((value := " ") for item in [0])',
    '(item for item in [0] if (value := " "))',
    '([(value := " ") for inner in [0]] for item in [0])',
    '((lambda argument=(value := " "): argument) for item in [0])',
]


def query(tmp_path, expression, *, snapshot=False, fresh=False):
    pytest.importorskip('z3')
    source = 'import re\ndef consume(argument): pass\ndef handle(value):\n'
    source += ' gen = ' + expression + '\n'
    if not fresh:
        source += GUARD + '\n'
    if snapshot:
        source += ' alias = value\n'
    source += ' next(gen)\n'
    if fresh:
        source += GUARD + '\n'
    source += ' consume(' + ('alias' if snapshot else 'value') + ')\n'
    # The source and generator are never imported or executed.
    (tmp_path / 'app.py').write_text(source)
    return sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                        sink_uri='app.py', sink_line=len(source.splitlines()), sink_class='xss')


@pytest.mark.parametrize('expression', WRITERS, ids=['element', 'filter', 'nested-eager', 'lambda-default'])
def test_deferred_writer_expires_enclosing_parameter(tmp_path, expression):
    result = query(tmp_path, expression)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


@pytest.mark.parametrize('expression', WRITERS, ids=['element', 'filter', 'nested-eager', 'lambda-default'])
def test_earlier_snapshot_survives_generator_write(tmp_path, expression):
    result = query(tmp_path, expression, snapshot=True)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize('expression', [
    '(value for value in [0])',
    '((lambda: (value := " ")) for item in [0])',
])
def test_generator_local_bindings_preserve_outer_parameter(tmp_path, expression):
    result = query(tmp_path, expression)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_fresh_guard_retains_conservative_escaping_writer_refusal(tmp_path):
    result = query(tmp_path, WRITERS[0], fresh=True)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_eager_walrus_is_not_a_deferred_writer():
    tree = ast.parse('def handle(value):\n unused = [(value := " ") for item in [0]]\n')
    function = tree.body[0]
    assert 'value' not in sb._nested_scope_escaping_rebinds(function)


@pytest.mark.parametrize('definition', [
    'later = lambda gen=((value := " ") for item in [0]): gen',
    'def later(gen=((value := " ") for item in [0])): pass',
])
def test_generator_in_definition_default_captures_outer_cell(definition):
    tree = ast.parse('def handle(value):\n ' + definition + '\n')
    assert 'value' in sb._nested_scope_escaping_rebinds(tree.body[0])


def test_own_default_does_not_write_the_function_parameter_cell():
    tree = ast.parse('value = "abc"\ndef handle(value, gen=((value := " ") for item in [0])):\n pass\n')
    function = tree.body[1]
    assert 'value' not in sb._nested_scope_escaping_rebinds(function)
    assert sb._python_name_has_local_slot(function, 'value')
