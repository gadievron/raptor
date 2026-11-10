"""Opaque import execution may expire separately shared name facts."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = """import re
value = "abc"
def change_value():
 global value
 value = " "
def consume(argument):
 pass
"""
HELPER = "from app import change_value\nchange_value()\nmarker = 0\n"
IMPORTS = [pytest.param('import helper', id='module'),
           pytest.param('from helper import marker', id='from')]


def query(tmp_path, statement, *, mode='shared', same_row=False):
    """Model canonical app plus an uncached helper; inspect source only.

    Neither file is imported or executed. Module/cache identity is an
    explicit profile premise, not evidence supplied by these fixtures.
    """
    pytest.importorskip('z3')
    text = PREFIX + ('def handle(value):\n' if mode == 'parameter' else 'def handle():\n')
    if mode != 'fresh':
        text += GUARD + '\n'
    if mode == 'snapshot':
        text += ' alias = value\n'
    sink = 'consume(' + ('alias' if mode == 'snapshot' else 'value') + ')'
    text += ' ' + statement
    if same_row:
        text += '; ' + sink + '\n'
    else:
        text += '\n'
        if mode == 'fresh':
            text += GUARD + '\n'
        text += ' ' + sink + '\n'
    (tmp_path / 'app.py').write_text(text)
    (tmp_path / 'helper.py').write_text(HELPER)
    return sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                        sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')


@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot', 'fresh'])
@pytest.mark.parametrize('statement', IMPORTS)
def test_import_effect_preserves_owned_or_refreshed_value(tmp_path, statement, mode):
    result = query(tmp_path, statement, mode=mode)
    expected = sb.Tier0Status.NOT_APPLICABLE if mode == 'shared' else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning


@pytest.mark.parametrize('statement', ['import helper as value', 'from helper import marker as value'])
def test_import_binding_cannot_borrow_parameter_certificate(tmp_path, statement):
    result = query(tmp_path, statement, mode='parameter')
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


@pytest.mark.parametrize('statement', IMPORTS)
@pytest.mark.parametrize('local', [False, True], ids=['shared', 'parameter'])
def test_same_row_import_effect_respects_slot_ownership(statement, local):
    text = ('def handle(value):\n' if local else 'def handle():\n')
    text += ' pass\n ' + statement + '; consume(value)\n'
    assert sb._variable_reassigned_between(ast.parse(text), 'value', 2, 3) is (not local)


@pytest.mark.parametrize('statement', IMPORTS)
def test_compound_import_sink_remains_unadmitted(tmp_path, statement):
    result = query(tmp_path, statement, mode='parameter', same_row=True)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
