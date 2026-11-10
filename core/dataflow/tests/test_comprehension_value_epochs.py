"""Creation acquires an iterator without certifying deferred execution."""
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
  return iter(())
source = Source()
"""
EXPRESSIONS = ['[item for item in source]', '{item for item in source}',
               '{item: item for item in source}', '(item for item in source)']


@pytest.mark.parametrize('expression', EXPRESSIONS, ids=['list', 'set', 'dict', 'generator'])
@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot', 'fresh'])
def test_creation_effect_preserves_owned_or_refreshed_value(tmp_path, expression, mode):
    pytest.importorskip('z3')
    text = PREFIX + ('def handle(value):\n' if mode == 'parameter' else 'def handle():\n')
    if mode != 'fresh':
        text += GUARD + '\n'
    if mode == 'snapshot':
        text += ' alias = value\n'
    text += ' unused = ' + expression + '\n'
    if mode == 'fresh':
        text += GUARD + '\n'
    text += ' consume(' + ('alias' if mode == 'snapshot' else 'value') + ')\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    expected = sb.Tier0Status.NOT_APPLICABLE if mode == 'shared' else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning


@pytest.mark.parametrize('expression', EXPRESSIONS)
def test_creation_in_default_and_same_row_precedes_shared_read(expression):
    default = ast.parse('def later(argument=' + expression + '): pass').body[0]
    assert sb._python_possible_call(default)
    tree = ast.parse('def handle():\n pass\n unused = ' + expression + '; consume(value)\n')
    assert sb._variable_reassigned_between(tree, 'value', 2, 3)
