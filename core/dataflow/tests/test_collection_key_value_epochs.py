"""Collection key callbacks do not freeze separately shared name slots."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'
PREFIX = """import re
value = "abc"
class Key:
 def __hash__(self):
  global value
  value = " "
  return 1
key = Key()
"""


def query(tmp_path, expression, *, mode='shared', default=False, prefix=PREFIX):
    pytest.importorskip('z3')
    text = prefix + ('def handle(value):\n' if mode == 'parameter' else 'def handle():\n')
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
    return sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                        sink_uri='app.py', sink_line=len(text.splitlines()), sink_class='xss')


@pytest.mark.parametrize('expression', ['{key: 0}', '{key}', '{(0, key): 0}'])
@pytest.mark.parametrize('mode', ['shared', 'parameter', 'snapshot', 'fresh'])
@pytest.mark.parametrize('default', [False, True], ids=['value', 'default'])
def test_unknown_key_dispatch_retains_owned_or_refreshed_values(tmp_path, expression, mode, default):
    result = query(tmp_path, expression, mode=mode, default=default)
    expected = sb.Tier0Status.NOT_APPLICABLE if mode == 'shared' else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning


@pytest.mark.parametrize('expression', ['{}', '{"fixed": 0}', '{None: 0}', '{...: 0}',
    '{b"fixed": 0}', '{1.25: 0}', '{1j: 0}', '{(0, ("fixed", None)): 0}',
    '{"fixed"}', '{(0, ("fixed", None))}', '{0: 1, False: 2, 0.0: 3, 0j: 4}'])
def test_literal_key_construction_preserves_existing_shared_fact(tmp_path, expression):
    result = query(tmp_path, expression)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize('expression', ['{first: 0, second: 1}', '{first, second}'])
def test_unknown_collision_equality_cannot_retain_shared_fact(tmp_path, expression):
    prefix = ("import re\nvalue = 'abc'\nclass Key:\n def __hash__(self):\n  return 1\n"
              " def __eq__(self, other):\n  global value\n  value = ' '\n  return False\n"
              "first = Key()\nsecond = Key()\n")
    result = query(tmp_path, expression, prefix=prefix)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_literal_keys_do_not_hide_value_format_callbacks(tmp_path):
    prefix = ("import re\nvalue = 'abc'\nclass Formatter:\n def __format__(self, spec):\n"
              "  global value\n  value = ' '\n  return ''\nformatter = Formatter()\n")
    result = query(tmp_path, '{"fixed": f"{formatter}"}', prefix=prefix)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_key_effect_precedes_same_row_shared_read():
    tree = ast.parse('def handle():\n pass\n unused = {key: 0}; consume(value)\n')
    assert sb._variable_reassigned_between(tree, 'value', 2, 3)
