"""Formatted-value dispatch cannot freeze another shared name slot."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = """import re
value = "abc"
class Formatter:
 def __format__(self, spec):
  global value
  value = " "
  return ""
 def __str__(self):
  global value
  value = " "
  return ""
 def __repr__(self):
  global value
  value = " "
  return ""
formatter = Formatter()
"""
EXPRESSIONS = ['f"{formatter}"', 'f"{formatter!s}"', 'f"{formatter!r}"',
               'f"{formatter!a}"', 'f"{formatter:>10}"']


@pytest.mark.parametrize('expression', EXPRESSIONS)
@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot', 'fresh'])
@pytest.mark.parametrize('default', [False, True], ids=['value', 'default'])
def test_formatted_value_effect_preserves_owned_or_refreshed_values(tmp_path, expression, mode, default):
    pytest.importorskip('z3')
    text = PREFIX + ('def handle(value):\n' if mode == 'parameter' else 'def handle():\n')
    if mode != 'fresh':
        text += GUARD + '\n'
    if mode == 'snapshot':
        text += ' alias = value\n'
    text += (' def later(argument=' + expression + '):\n  pass\n' if default
             else ' unused = ' + expression + '\n')
    if mode == 'fresh':
        text += GUARD + '\n'
    text += ' consume(' + ('alias' if mode == 'snapshot' else 'value') + ')\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    expected = sb.Tier0Status.NOT_APPLICABLE if mode == 'shared' else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning


@pytest.mark.parametrize('expression', ['f"constant"', 'f"{{formatter}}"'])
def test_constant_only_joined_strings_preserve_shared_values(tmp_path, expression):
    pytest.importorskip('z3')
    text = PREFIX + 'def handle():\n' + GUARD
    text += '\n unused = ' + expression + '\n consume(value)\n'
    (tmp_path / 'app.py').write_text(text)
    result = sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize('expression', EXPRESSIONS)
def test_same_row_formatting_effect_precedes_shared_read(expression):
    tree = ast.parse('def handle():\n pass\n unused = ' + expression + '; consume(value)\n')
    assert sb._variable_reassigned_between(tree, 'value', 2, 3)
