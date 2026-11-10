"""Operator dispatch ends shared name epochs without explicit call syntax."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = """import re
value = "abc"
class Operand:
 def __add__(self, other):
  global value
  value = " "
  return 0
 def __bool__(self):
  global value
  value = " "
  return True
 def __eq__(self, other):
  global value
  value = " "
  return True
operand = Operand()
"""


@pytest.mark.parametrize('expression', ['operand + 0', 'not operand',
                                        'operand == 0', 'operand and 0'])
@pytest.mark.parametrize('local', [False, True], ids=['shared', 'local'])
def test_operator_effect_preserves_only_local_snapshot(tmp_path, expression, local):
    pytest.importorskip('z3')
    source = PREFIX + ('def handle(value):\n' if local else 'def handle():\n')
    source += GUARD + '\n unused = ' + expression + '\n consume(value)\n'
    (tmp_path / 'app.py').write_text(source)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(source.splitlines()), sink_class='xss')
    assert result.status is (sb.Tier0Status.SOUND if local else sb.Tier0Status.NOT_APPLICABLE), result.reasoning


@pytest.mark.parametrize('expression', ['operand + 0', 'not operand', 'operand == 0', 'operand and 0'])
def test_same_row_operator_and_default_are_epoch_boundaries(expression):
    tree = ast.parse('def handle():\n pass\n unused = ' + expression + '; consume(value)\n')
    assert sb._variable_reassigned_between(tree, 'value', 2, 3)
    default = ast.parse('def later(argument=' + expression + '): pass').body[0]
    assert sb._python_possible_call(default)


def test_operator_backedge_and_local_slot():
    tree = ast.parse('def handle():\n pass\n while True:\n  consume(value)\n  unused = operand + 0\n')
    assert sb._rebound_in_loop_containing_sink(tree, 'value', 2, 4)
    local = ast.parse('def handle(value):\n pass\n while True:\n  consume(value)\n  unused = operand + 0\n')
    assert not sb._rebound_in_loop_containing_sink(local, 'value', 2, 4)
