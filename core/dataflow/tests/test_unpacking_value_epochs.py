"""Iterable unpack effects preserve RHS snapshots but not shared slots."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = """import re
value = "abc"
class Source:
 def __iter__(self):
  global value
  value = " "
  return iter((0, 0))
source = Source()
"""


def query(tmp_path, middle, *, sink='value', mode='shared'):
    pytest.importorskip('z3')
    text = PREFIX + ('def handle(value):\n' if mode == 'parameter' else 'def handle():\n')
    text += GUARD + '\n'
    if mode == 'snapshot':
        text += ' alias = value\n'
        sink = 'alias'
    text += middle + '\n consume(' + sink + ')\n'
    (tmp_path / 'app.py').write_text(text)
    return sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                        sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')


@pytest.mark.parametrize('middle', [' left, right = source', ' unused = [*source]'])
@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot'])
def test_unpack_effect_retains_only_owned_value(tmp_path, middle, mode):
    result = query(tmp_path, middle, mode=mode)
    expected = sb.Tier0Status.NOT_APPLICABLE if mode == 'shared' else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning


@pytest.mark.parametrize('middle', [' alias, (left, right) = (value, source)',
                                    ' (left, right), alias = (source, value)'])
@pytest.mark.parametrize('sink', ['alias', 'value'])
def test_nested_target_unpack_preserves_captured_rhs(tmp_path, middle, sink):
    result = query(tmp_path, middle, sink=sink)
    expected = sb.Tier0Status.SOUND if sink == 'alias' else sb.Tier0Status.NOT_APPLICABLE
    assert result.status is expected, result.reasoning


@pytest.mark.parametrize('middle', [' alias, other = value, 0',
                                    ' other, (alias, spare) = (0, (value, 0))'])
def test_pairable_literal_unpack_retains_identity_transfer(tmp_path, middle):
    result = query(tmp_path, middle, sink='alias')
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_same_row_unpack_is_an_effect_before_shared_read():
    tree = ast.parse('def handle():\n pass\n left, right = source; consume(value)\n')
    assert sb._variable_reassigned_between(tree, 'value', 2, 3)
